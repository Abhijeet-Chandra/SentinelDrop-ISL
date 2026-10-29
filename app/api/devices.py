import os
import hmac

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import TrustedDevice, TrustedDeviceApproval, UserIdentity
from app.security.device_identity import (
    get_public_key_base64,
    get_public_key_fingerprint,
)
from app.security.pairing import create_pairing_payload
from app.services.audit_log import record_event
from app.services.auth import get_current_user
from app.services.pairing import (
    confirm_pairing,
    prepare_pairing,
)
from app.services.qr import pairing_qr_png_bytes
from app.services.session_manager import session_manager
from app.services.relay_sessions import revoke_relay_sessions_for_user
from app.services.user_identity import fingerprint_from_public_bytes


router = APIRouter(
    prefix="/devices",
    tags=["Devices"],
)


class PairingPayloadRequest(BaseModel):
    payload: str


class ConfirmPairingRequest(BaseModel):
    payload: str
    fingerprint: str


class RegisterClientIdentityRequest(BaseModel):
    public_key: str
    fingerprint: str


def _pairing_body() -> dict:
    payload = create_pairing_payload()
    return {
        "payload": payload,
        "fingerprint": get_public_key_fingerprint(),
        "public_key": get_public_key_base64(),
        "device": os.environ.get(
            "SENTINEL_DEVICE_NAME",
            "SentinelDrop",
        ),
    }


@router.get("/identity")
def get_device_identity():
    """Public device identity used for QR pairing and fingerprints."""

    body = _pairing_body()
    return {
        "device": body["device"],
        "public_key": body["public_key"],
        "fingerprint": body["fingerprint"],
    }


@router.get("/pairing")
def get_pairing_payload():
    """Public pairing payload shown on the receiver QR screen."""

    return _pairing_body()


@router.get("/pairing/qr")
def get_pairing_qr():
    """PNG QR code containing this device's pairing payload."""

    return Response(content=pairing_qr_png_bytes(), media_type="image/png")


def _user_pairing_body(db: Session, current_user) -> dict:
    identity = db.query(UserIdentity).filter(UserIdentity.user_id == current_user.id).first()
    if identity is None or not identity.client_managed:
        raise HTTPException(
            status_code=409,
            detail="This browser has not registered its private device identity yet. Refresh the page to initialize secure browser storage.",
        )
    device_name = current_user.username
    payload = create_pairing_payload(
        device_name=device_name,
        public_key=identity.public_key,
        fingerprint=identity.fingerprint,
    )
    return {
        "payload": payload,
        "fingerprint": identity.fingerprint,
        "public_key": identity.public_key,
        "device": device_name,
    }


@router.put("/me/identity")
def register_client_identity(
    request: RegisterClientIdentityRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Register only a browser-generated X25519 public key; private keys stay client-side."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    from app.services.audit_log import record_event

    try:
        public_bytes = base64.b64decode(request.public_key, validate=True)
        X25519PublicKey.from_public_bytes(public_bytes)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid X25519 public key.") from exc

    expected_fingerprint = fingerprint_from_public_bytes(public_bytes)
    if not hmac.compare_digest(expected_fingerprint, request.fingerprint.lower()):
        raise HTTPException(status_code=400, detail="Public-key fingerprint does not match.")

    duplicate = db.query(UserIdentity).filter(
        UserIdentity.public_key == request.public_key,
        UserIdentity.user_id != current_user.id,
    ).first()
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="This public key is already registered to another account.")

    identity = db.query(UserIdentity).filter(UserIdentity.user_id == current_user.id).first()
    if identity is None:
        identity = UserIdentity(
            user_id=current_user.id,
            public_key=request.public_key,
            fingerprint=expected_fingerprint,
            client_managed=True,
        )
        db.add(identity)
        event_type = "CLIENT_IDENTITY_REGISTERED"
    else:
        if identity.public_key != request.public_key:
            old_device = db.query(TrustedDevice).filter(
                TrustedDevice.public_key == identity.public_key
            ).first()
            if old_device is not None:
                db.query(TrustedDeviceApproval).filter(
                    TrustedDeviceApproval.device_id == old_device.id
                ).delete(synchronize_session=False)
                db.delete(old_device)
            identity.public_key = request.public_key
            identity.fingerprint = expected_fingerprint
            identity.client_managed = True
            session_manager.remove_sessions_for_user(current_user.id)
            revoke_relay_sessions_for_user(db, current_user.id)
            event_type = "CLIENT_IDENTITY_ROTATED"
        else:
            identity.fingerprint = expected_fingerprint
            identity.client_managed = True
            event_type = "CLIENT_IDENTITY_CONFIRMED"

    db.commit()
    db.refresh(identity)
    record_event(
        db=db,
        event_type=event_type,
        details="Browser public identity registered; the private key is held by the browser.",
        actor_id=current_user.username,
        status="success",
    )
    return {
        "device": current_user.username,
        "public_key": identity.public_key,
        "fingerprint": identity.fingerprint,
        "private_key_stored_by_server": False,
    }


@router.get("/me/pairing")
def get_my_pairing_payload(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Authenticated pairing payload for this signed-in client."""

    return _user_pairing_body(db, current_user)


@router.get("/me/pairing/qr")
def get_my_pairing_qr(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    body = _user_pairing_body(db, current_user)
    return Response(
        content=pairing_qr_png_bytes(payload=body["payload"]),
        media_type="image/png",
    )


@router.get("/trusted")
def list_trusted_devices(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    devices = (
        db.query(TrustedDevice)
        .join(TrustedDeviceApproval, TrustedDeviceApproval.device_id == TrustedDevice.id)
        .filter(TrustedDeviceApproval.user_id == current_user.id)
        .all()
    )
    return {
        "devices": [
            {
                "device_name": device.device_name,
                "fingerprint": device.fingerprint,
                "public_key": device.public_key,
            }
            for device in devices
        ]
    }


@router.post("/pairing/prepare")
def prepare_device_pairing(
    request: PairingPayloadRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    try:
        return prepare_pairing(request.payload)

    except ValueError as exc:
        record_event(
            db=db,
            event_type="DEVICE_PAIRING_FAILURE",
            details=str(exc),
            actor_id=current_user.username,
            status="failure",
        )
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@router.post("/pairing/confirm")
def confirm_device_pairing(
    request: ConfirmPairingRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    identity = db.query(UserIdentity).filter(UserIdentity.user_id == current_user.id).first()
    if identity is None or not identity.client_managed:
        raise HTTPException(status_code=409, detail="Register this browser's public identity before trusting another device.")
    try:
        preview = prepare_pairing(request.payload)
        if preview["public_key"] == identity.public_key:
            raise ValueError("Cannot pair a device with itself.")
        device = confirm_pairing(
            db=db,
            owner_user_id=current_user.id,
            payload=request.payload,
            confirmed_fingerprint=request.fingerprint,
        )

    except ValueError as exc:
        record_event(
            db=db,
            event_type="DEVICE_PAIRING_FAILURE",
            details=str(exc),
            actor_id=current_user.username,
            status="failure",
        )
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    record_event(
        db=db,
        event_type="DEVICE_PAIRING_SUCCESS",
        details=f"Trusted {device.device_name} ({device.fingerprint}).",
        actor_id=current_user.username,
        status="success",
    )

    return {
        "message": "Device trusted successfully.",
        "device": device.device_name,
        "fingerprint": device.fingerprint,
        "public_key": device.public_key,
    }
