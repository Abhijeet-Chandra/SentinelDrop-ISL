from sqlalchemy.orm import Session

from app.database.models import TrustedDevice, TrustedDeviceApproval


def add_trusted_device(
    db: Session,
    owner_user_id: int,
    device_name: str,
    public_key: str,
    fingerprint: str,
) -> TrustedDevice:
    """Store a device as trusted."""

    existing_device = (
        db.query(TrustedDevice)
        .filter(TrustedDevice.public_key == public_key)
        .first()
    )

    if existing_device is None:
        device = TrustedDevice(
            device_name=device_name,
            public_key=public_key,
            fingerprint=fingerprint,
            trusted=True,
        )
        db.add(device)
        db.flush()
    else:
        device = existing_device
        device.device_name = device_name
        device.fingerprint = fingerprint
        device.trusted = True

    approval = (
        db.query(TrustedDeviceApproval)
        .filter_by(user_id=owner_user_id, device_id=device.id)
        .first()
    )
    if approval is None:
        db.add(TrustedDeviceApproval(user_id=owner_user_id, device_id=device.id))
    db.commit()
    db.refresh(device)

    return device


def get_trusted_device(
    db: Session,
    public_key: str,
    owner_user_id: int | None = None,
) -> TrustedDevice | None:
    """Find a trusted device by its public key."""

    query = db.query(TrustedDevice).filter(TrustedDevice.public_key == public_key)
    if owner_user_id is None:
        query = query.filter(TrustedDevice.trusted.is_(True))
    else:
        query = query.join(
            TrustedDeviceApproval,
            TrustedDeviceApproval.device_id == TrustedDevice.id,
        ).filter(TrustedDeviceApproval.user_id == owner_user_id)
    return query.first()


def revoke_trusted_device(
    db: Session,
    public_key: str,
    owner_user_id: int,
) -> bool:
    """Revoke trust for a device."""

    device = db.query(TrustedDevice).filter(TrustedDevice.public_key == public_key).first()

    if device is None:
        return False

    approval = db.query(TrustedDeviceApproval).filter_by(
        user_id=owner_user_id, device_id=device.id
    ).first()
    if approval is None:
        return False
    db.delete(approval)
    db.commit()

    return True
