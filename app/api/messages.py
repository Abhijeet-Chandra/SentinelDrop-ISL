import hashlib

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import Message
from app.monitor.sentinel import record_local_event
from app.services.audit_log import record_event
from app.services.auth import get_current_user
from app.services.message import EncryptedMessage
from app.services.message_storage import (
    MAX_PENDING_MESSAGES_PER_USER,
    mark_message_received,
    pending_message_count,
    store_message,
)
from app.services.relay_sessions import (
    active_relay_session_ids,
    relay_peer_user_id,
    reserve_message_nonce,
)


router = APIRouter(prefix="/messages", tags=["Messages"])
MAX_CIPHERTEXT_HEX_CHARS = 2_000_032


class CiphertextSendRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=255)
    sequence_number: int = Field(ge=0, le=4_294_967_295)
    message_type: str = Field(min_length=1, max_length=50)
    nonce: str = Field(min_length=24, max_length=24)
    ciphertext: str = Field(min_length=32, max_length=MAX_CIPHERTEXT_HEX_CHARS)
    sender_user_id: int | None = None
    recipient_user_id: int | None = None


class ReceiveAckRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=255)
    sequence_number: int = Field(ge=0, le=4_294_967_295)
    ciphertext: str = Field(min_length=32, max_length=MAX_CIPHERTEXT_HEX_CHARS)


def _transfer_event_type(message_type: str, direction: str) -> str:
    kind = (message_type or "text").lower()
    if kind in {"image", "png", "jpeg", "jpg", "document", "file"}:
        base = "FILE"
    elif kind in {"audio", "audio_transcript", "voice", "transcript"}:
        base = "AUDIO_TRANSCRIPT"
    else:
        base = "TEXT"
    return f"{base}_{direction}"


def _cipher_bytes(nonce_hex: str, ciphertext_hex: str) -> tuple[bytes, bytes]:
    try:
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Ciphertext and nonce must be hexadecimal.") from exc
    if len(nonce) != 12 or len(ciphertext) < 16:
        raise HTTPException(status_code=400, detail="Ciphertext is incomplete or malformed.")
    return nonce, ciphertext


def _queue_payload(message: Message) -> dict:
    return {
        "id": message.id,
        "session_id": message.session_id,
        "sequence_number": message.sequence_number,
        "message_type": message.message_type,
        "nonce": message.nonce,
        "ciphertext": message.ciphertext,
        "sender_user_id": message.sender_user_id,
        "recipient_user_id": message.recipient_user_id,
        "filename": message.filename,
        "mime_type": message.mime_type,
        "file_size": message.file_size,
        "transfer_kind": "file" if message.filename else "text",
    }


@router.post("/send")
def send_ciphertext_message(
    request: CiphertextSendRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Persist and route browser-encrypted bytes; the API never accepts plaintext."""
    recipient_user_id = relay_peer_user_id(db, request.session_id, current_user.id)
    if recipient_user_id is None:
        raise HTTPException(status_code=403, detail="Session is not available to this account.")
    if request.sender_user_id not in (None, current_user.id):
        raise HTTPException(status_code=403, detail="Sender identity does not match the signed-in account.")
    if request.recipient_user_id not in (None, recipient_user_id):
        raise HTTPException(status_code=403, detail="Recipient is not a member of this session.")
    if pending_message_count(db, recipient_user_id) >= MAX_PENDING_MESSAGES_PER_USER:
        record_local_event("flood", "Recipient ciphertext queue reached its per-user capacity.")
        raise HTTPException(status_code=429, detail="Recipient pending queue is full. Try again after they receive messages.")
    nonce, ciphertext = _cipher_bytes(request.nonce, request.ciphertext)

    if not reserve_message_nonce(db, request.session_id, current_user.id, nonce.hex()):
        record_local_event("replay", "AES-GCM nonce reuse rejected.")
        raise HTTPException(status_code=409, detail="GCM nonce was already used in this session.")

    duplicate = db.query(Message.id).filter(
        Message.session_id == request.session_id,
        Message.sender_user_id == current_user.id,
        Message.sequence_number == request.sequence_number,
    ).first()
    if duplicate is not None:
        record_local_event("replay", "Duplicate sender sequence rejected.")
        raise HTTPException(status_code=409, detail="This message sequence was already used.")

    message = EncryptedMessage(
        session_id=request.session_id,
        sequence_number=request.sequence_number,
        message_type=request.message_type,
        nonce=nonce,
        ciphertext=ciphertext,
    )
    stored = store_message(
        db,
        message,
        sender_user_id=current_user.id,
        recipient_user_id=recipient_user_id,
    )
    record_event(
        db=db,
        event_type=_transfer_event_type(request.message_type, "SENT"),
        session_id=request.session_id,
        details=(
            f"Stored end-to-end encrypted {request.message_type} message, sequence "
            f"{request.sequence_number}, ciphertext SHA-256 {stored.ciphertext_hash}."
        ),
        actor_id=current_user.username,
        status="success",
    )
    return {
        "message_id": stored.id,
        "session_id": stored.session_id,
        "sequence_number": stored.sequence_number,
        "message_type": stored.message_type,
        "ciphertext_sha256": stored.ciphertext_hash,
        "encrypted": True,
    }


@router.get("/pending")
def list_pending_ciphertext(
    session_id: str | None = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    query = db.query(Message).filter(
        Message.recipient_user_id == current_user.id,
        Message.received_at.is_(None),
        Message.ciphertext.is_not(None),
    )
    if session_id is not None:
        if relay_peer_user_id(db, session_id, current_user.id) is None:
            raise HTTPException(status_code=403, detail="Session is not available to this account.")
        query = query.filter(Message.session_id == session_id)
    else:
        allowed = active_relay_session_ids(db, current_user.id)
        if not allowed:
            return {"messages": []}
        query = query.filter(Message.session_id.in_(allowed))
    messages = query.order_by(Message.sent_at, Message.id).limit(200).all()
    return {"messages": [_queue_payload(message) for message in messages]}


@router.post("/receive")
def acknowledge_decrypted_message(
    request: ReceiveAckRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Acknowledge ciphertext only after the receiving browser authenticates it."""
    peer_user_id = relay_peer_user_id(db, request.session_id, current_user.id)
    if peer_user_id is None:
        raise HTTPException(status_code=403, detail="Session is not available to this account.")
    _, ciphertext = _cipher_bytes("00" * 12, request.ciphertext)
    ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
    stored = db.query(Message).filter(
        Message.session_id == request.session_id,
        Message.sequence_number == request.sequence_number,
        Message.sender_user_id == peer_user_id,
        Message.recipient_user_id == current_user.id,
    ).first()
    if stored is None or stored.ciphertext_hash != ciphertext_hash:
        record_local_event("tamper", "Receive acknowledgement did not match a queued ciphertext.")
        raise HTTPException(status_code=404, detail="Queued ciphertext was not found or did not match.")

    if stored.received_at is None:
        mark_message_received(
            db,
            session_id=request.session_id,
            sequence_number=request.sequence_number,
            sender_user_id=peer_user_id,
            recipient_user_id=current_user.id,
        )
        record_event(
            db=db,
            event_type=_transfer_event_type(stored.message_type, "RECEIVED"),
            session_id=request.session_id,
            details=f"Receiver acknowledged authenticated ciphertext, sequence {request.sequence_number}.",
            actor_id=current_user.username,
            status="success",
        )
    return {"received": True, "sequence_number": request.sequence_number}
