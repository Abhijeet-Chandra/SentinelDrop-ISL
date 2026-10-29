import pytest

from app.database.connection import SessionLocal
from app.database.models import TrustedDevice, TrustedDeviceApproval, User
from app.security.pairing import create_pairing_payload
from app.security.passwords import hash_password
from app.services.pairing import confirm_pairing, prepare_pairing
import uuid


def _new_owner(db):
    user = User(username=f"pair_{uuid.uuid4().hex[:8]}", password_hash=hash_password("TestPassword123!"))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_prepare_pairing():
    payload = create_pairing_payload()

    data = prepare_pairing(payload)

    assert data["version"] == 1
    assert data["device"]
    assert data["public_key"]
    assert data["fingerprint"]


def test_confirm_pairing():
    payload = create_pairing_payload()
    prepared = prepare_pairing(payload)

    db = SessionLocal()

    try:
        owner = _new_owner(db)
        device = confirm_pairing(
            db=db,
            owner_user_id=owner.id,
            payload=payload,
            confirmed_fingerprint=prepared["fingerprint"],
        )

        assert device.trusted is True
        assert device.device_name == prepared["device"]
        assert device.public_key == prepared["public_key"]
        assert device.fingerprint == prepared["fingerprint"]
        assert db.query(TrustedDeviceApproval).filter_by(user_id=owner.id, device_id=device.id).first()

    finally:
        db.query(TrustedDeviceApproval).filter_by(user_id=owner.id).delete()
        db.query(TrustedDevice).filter(
            TrustedDevice.public_key == prepared["public_key"]
        ).delete()

        db.commit()
        db.close()


def test_confirm_pairing_rejects_wrong_fingerprint():
    payload = create_pairing_payload()
    prepared = prepare_pairing(payload)

    db = SessionLocal()

    try:
        owner = _new_owner(db)
        with pytest.raises(ValueError, match="Fingerprint confirmation"):
            confirm_pairing(
                db=db,
                owner_user_id=owner.id,
                payload=payload,
                confirmed_fingerprint="00:11:22:33",
            )

        device = (
            db.query(TrustedDevice)
            .filter(
                TrustedDevice.public_key == prepared["public_key"]
            )
            .first()
        )

        assert device is None

    finally:
        db.query(TrustedDeviceApproval).filter_by(user_id=owner.id).delete()
        db.query(TrustedDevice).filter(
            TrustedDevice.public_key == prepared["public_key"]
        ).delete()

        db.commit()
        db.close()
