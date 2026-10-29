from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import User, UserIdentity
from app.services.auth import get_current_user
from app.services.handshake_manager import (
    PendingHandshake,
    handshake_manager,
)
from app.services.relay_sessions import get_or_create_relay_session
from app.monitor.sentinel import record_local_event
from app.services.audit_log import record_event
from app.services.trusted_devices import get_trusted_device
from app.services.user_identity import (
    find_identity_by_public_key,
)


router = APIRouter(prefix="/sessions", tags=["Sessions"])


class SessionEstablishRequest(BaseModel):
    device_public_key: str
    ephemeral_public_key: str
    session_id: str | None = None


class SessionInitiateRequest(BaseModel):
    device_public_key: str


class SessionFinalizeRequest(BaseModel):
    session_id: str
    peer_ephemeral_public_key: str


@router.post("/initiate")
def initiate_secure_session(
    request: SessionInitiateRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Legacy server-key handshake is disabled; the browser derives keys locally."""
    raise HTTPException(status_code=410, detail="Use browser-owned pairing and /sessions/open.")


@router.post("/establish", include_in_schema=False)
def establish_secure_session(
    request: SessionEstablishRequest,
    current_user=Depends(get_current_user),
):
    """
    Respond to a secure session initiation.

    The initiator supplies its static and ephemeral public keys.
    This device generates its own ephemeral key pair and derives
    the shared session key.
    """

    raise HTTPException(
        status_code=410,
        detail=(
            "This legacy server-identity handshake is disabled. Use the "
            "authenticated user pairing and session workflow instead."
        ),
    )


@router.post("/finalize")
def finalize_secure_session(
    request: SessionFinalizeRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Legacy server-key handshake is disabled; the browser derives keys locally."""
    raise HTTPException(status_code=410, detail="Use browser-owned pairing and /sessions/open.")


class SessionOpenRequest(BaseModel):
    device_public_key: str


@router.post("/open")
def open_secure_session(
    request: SessionOpenRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Establish a bidirectional session with a trusted peer.

    The database stores only peer account membership and public identities;
    each browser derives its encryption key locally.
    """

    trusted_device = get_trusted_device(
        db=db,
        public_key=request.device_public_key,
        owner_user_id=current_user.id,
    )
    if trusted_device is None:
        record_local_event("untrusted", "Session open rejected.")
        record_event(
            db=db,
            event_type="untrusted_session",
            details="Rejected session open from an untrusted device.",
            actor_id=current_user.username,
            status="failure",
        )
        raise HTTPException(
            status_code=403,
            detail="Device is not trusted.",
        )

    local_identity = db.query(UserIdentity).filter(UserIdentity.user_id == current_user.id).first()
    if local_identity is None or not local_identity.client_managed:
        raise HTTPException(status_code=409, detail="Register this browser's public identity before opening a session.")
    peer_identity = find_identity_by_public_key(db, request.device_public_key)
    if peer_identity is None:
        raise HTTPException(
            status_code=404,
            detail="Peer identity is not registered on this server.",
        )

    peer_user = db.query(User).filter(User.id == peer_identity.user_id).first()
    if peer_user is None:
        raise HTTPException(
            status_code=404,
            detail="Peer account no longer exists.",
        )
    if get_trusted_device(
        db=db,
        public_key=local_identity.public_key,
        owner_user_id=peer_identity.user_id,
    ) is None:
        raise HTTPException(
            status_code=403,
            detail=(
                "The other device must also confirm your fingerprint "
                "before a session can start."
            ),
        )

    relay, created = get_or_create_relay_session(
        db,
        current_user.id,
        peer_identity.user_id,
        local_identity.public_key,
        peer_identity.public_key,
    )
    session_id = relay.session_id
    if created:
        record_event(
            db=db,
            event_type="SESSION_ESTABLISHED",
            session_id=session_id,
            details="Ciphertext-only relay session established; encryption key remains in the paired browsers.",
            actor_id=current_user.username,
            status="success",
        )
    return {
        "session_id": session_id,
        "local_user_id": current_user.id,
        "peer_user_id": peer_identity.user_id,
        "peer_public_key": peer_identity.public_key,
        "message": "End-to-end session established." if created else "Secure session already established.",
    }
