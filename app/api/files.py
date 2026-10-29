"""Ciphertext-only file relay endpoints; file encryption stays in the browser."""

import hashlib

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import Message
from app.monitor.sentinel import record_local_event
from app.services.audit_log import record_event
from app.services.auth import get_current_user
from app.services.binary_message import EncryptedBinaryMessage
from app.services.file_transfer import MAX_FILE_SIZE
from app.services.message_storage import (
    MAX_PENDING_MESSAGES_PER_USER,
    mark_message_received,
    pending_message_count,
    store_binary_message,
)
from app.services.relay_sessions import relay_peer_user_id, reserve_message_nonce


router = APIRouter(prefix="/files", tags=["File Transfer"])


class EncryptedFileRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=255)
    sequence_number: int = Field(ge=0, le=4_294_967_295)
    message_type: str = Field(min_length=1, max_length=50)
    nonce: str = Field(min_length=24, max_length=24)
    ciphertext: str = Field(min_length=32, max_length=(MAX_FILE_SIZE + 16) * 2)
    filename: str = Field(min_length=1, max_length=255)
    mime_type: str | None = Field(default=None, max_length=255)
    file_size: int = Field(ge=0, le=MAX_FILE_SIZE)
    sender_user_id: int | None = None
    recipient_user_id: int | None = None


class FileReceiveAckRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=255)
    sequence_number: int = Field(ge=0, le=4_294_967_295)
    ciphertext: str = Field(min_length=32, max_length=(MAX_FILE_SIZE + 16) * 2)


@router.post("/inbox")
def enqueue_encrypted_file(
    request: EncryptedFileRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Persist browser-encrypted file bytes and visible transfer metadata only."""
    peer_user_id = relay_peer_user_id(db, request.session_id, current_user.id)
    if peer_user_id is None:
        raise HTTPException(status_code=403, detail="Session is not available to this account.")
    if request.sender_user_id not in (None, current_user.id):
        raise HTTPException(status_code=403, detail="Sender identity does not match the signed-in account.")
    if request.recipient_user_id not in (None, peer_user_id):
        raise HTTPException(status_code=403, detail="Recipient is not a member of this session.")
    if pending_message_count(db, peer_user_id) >= MAX_PENDING_MESSAGES_PER_USER:
        record_local_event("flood", "Recipient ciphertext queue reached its per-user capacity.")
        raise HTTPException(status_code=429, detail="Recipient pending queue is full. Try again after they receive messages.")
    if any(separator in request.filename for separator in ("/", "\\")) or request.filename in {".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid filename.")
    if any(ord(character) < 32 for character in request.filename):
        raise HTTPException(status_code=400, detail="Invalid filename.")
    try:
        nonce = bytes.fromhex(request.nonce)
        ciphertext = bytes.fromhex(request.ciphertext)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Ciphertext and nonce must be hexadecimal.") from exc
    if len(nonce) != 12 or len(ciphertext) != request.file_size + 16:
        raise HTTPException(status_code=400, detail="Encrypted file is malformed or its size metadata does not match.")

    duplicate = db.query(Message.id).filter(
        Message.session_id == request.session_id,
        Message.sender_user_id == current_user.id,
        Message.sequence_number == request.sequence_number,
    ).first()
    if duplicate is not None:
        record_local_event("replay", "Duplicate sender sequence rejected for file transfer.")
        raise HTTPException(status_code=409, detail="This message sequence was already used.")
    if not reserve_message_nonce(db, request.session_id, current_user.id, nonce.hex()):
        record_local_event("replay", "AES-GCM nonce reuse rejected for file transfer.")
        raise HTTPException(status_code=409, detail="GCM nonce was already used in this session.")

    message = EncryptedBinaryMessage(
        session_id=request.session_id,
        sequence_number=request.sequence_number,
        message_type=request.message_type,
        nonce=nonce,
        ciphertext=ciphertext,
        filename=request.filename,
        mime_type=request.mime_type,
        file_size=request.file_size,
    )
    stored = store_binary_message(
        db,
        message,
        sender_user_id=current_user.id,
        recipient_user_id=peer_user_id,
    )
    record_event(
        db=db,
        event_type="FILE_SENT",
        session_id=request.session_id,
        details=(
            f"Stored end-to-end encrypted {request.message_type} file '{request.filename}', "
            f"sequence {request.sequence_number}, ciphertext SHA-256 {stored.ciphertext_hash}."
        ),
        actor_id=current_user.username,
        status="success",
    )
    return {"message_id": stored.id, "queued": True, "sequence_number": request.sequence_number}


@router.post("/receive-encrypted")
def receive_encrypted_file(
    request: FileReceiveAckRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Acknowledge a file only after the receiving browser authenticates it."""
    peer_user_id = relay_peer_user_id(db, request.session_id, current_user.id)
    if peer_user_id is None:
        raise HTTPException(status_code=403, detail="Session is not available to this account.")
    try:
        ciphertext = bytes.fromhex(request.ciphertext)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Ciphertext must be hexadecimal.") from exc
    ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
    stored = db.query(Message).filter(
        Message.session_id == request.session_id,
        Message.sequence_number == request.sequence_number,
        Message.sender_user_id == peer_user_id,
        Message.recipient_user_id == current_user.id,
    ).first()
    if stored is None or stored.filename is None or stored.ciphertext_hash != ciphertext_hash:
        record_local_event("tamper", "File receive acknowledgement did not match a queued ciphertext.")
        raise HTTPException(status_code=404, detail="Queued encrypted file was not found or did not match.")
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
            event_type="FILE_RECEIVED",
            session_id=request.session_id,
            details=f"Receiver acknowledged authenticated file ciphertext, sequence {request.sequence_number}.",
            actor_id=current_user.username,
            status="success",
        )
    return {"received": True, "sequence_number": request.sequence_number}


@router.post("/prepare")
async def prepare_file(
    session_id: str = Form(...),
    message_type: str = Form(...),
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
):
    """Retired route: encryption must happen on the sending browser."""
    raise HTTPException(
        status_code=410,
        detail="Server-side encryption is disabled. Encrypt files in the paired browser and use /files/inbox.",
    )


@router.post("/receive")
def receive_file(
    session_id: str = Form(...),
    sequence_number: int = Form(...),
    message_type: str = Form(...),
    nonce: str = Form(...),
    ciphertext: str = Form(...),
    filename: str = Form(...),
    current_user=Depends(get_current_user),
):
    """Retired route: the receiving browser authenticates and decrypts files."""
    raise HTTPException(
        status_code=410,
        detail="Server-side decryption is disabled. Decrypt files in the receiving browser.",
    )


@router.get("/received")
def list_received_files(current_user=Depends(get_current_user)):
    raise HTTPException(status_code=410, detail="Received files are decrypted and kept in the browser, not on the server.")


@router.get("/received/{filename}")
def download_received_file(filename: str, current_user=Depends(get_current_user)):
    raise HTTPException(status_code=410, detail="Received files are no longer stored on the server.")
