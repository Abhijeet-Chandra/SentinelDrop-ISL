import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)
from sqlalchemy.orm import Session

from app.database.models import User, UserIdentity
from app.storage_paths import data_path


USER_KEY_DIRECTORY = data_path("keys", "users")


def fingerprint_from_public_bytes(public_bytes: bytes) -> str:
    digest = hashlib.sha256(public_bytes).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _user_key_dir(user_id: int) -> Path:
    return USER_KEY_DIRECTORY / str(user_id)


def _write_key_pair(user_id: int) -> tuple[bytes, bytes]:
    directory = _user_key_dir(user_id)
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / "device_private.key"
    public_path = directory / "device_public.key"

    # The private key is the source of truth. Rebuild a missing or stale
    # public-key file from it so the public identity always matches crypto.
    if private_path.exists():
        private_bytes = private_path.read_bytes()
        private_key = X25519PrivateKey.from_private_bytes(private_bytes)
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if not public_path.exists() or public_path.read_bytes() != public_bytes:
            public_path.write_bytes(public_bytes)
        return private_bytes, public_bytes

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)
    return private_bytes, public_bytes


def ensure_user_identity(db: Session, user: User) -> UserIdentity:
    """Create a per-user X25519 identity used for QR pairing."""

    existing = (
        db.query(UserIdentity)
        .filter(UserIdentity.user_id == user.id)
        .first()
    )
    if existing is not None:
        # Once a browser-owned public key has been registered, never replace it
        # with a server-generated identity. The private identity lives in the
        # browser and is not available to backend session code.
        return existing

    _, public_bytes = _write_key_pair(user.id)
    public_key = base64.b64encode(public_bytes).decode("ascii")
    fingerprint = fingerprint_from_public_bytes(public_bytes)

    identity = UserIdentity(
        user_id=user.id,
        public_key=public_key,
        fingerprint=fingerprint,
    )
    db.add(identity)
    db.commit()
    db.refresh(identity)
    return identity


def load_user_private_key(user_id: int) -> X25519PrivateKey:
    private_path = _user_key_dir(user_id) / "device_private.key"
    if not private_path.exists():
        _write_key_pair(user_id)
    return X25519PrivateKey.from_private_bytes(private_path.read_bytes())


def load_user_public_key_bytes(user_id: int) -> bytes:
    public_path = _user_key_dir(user_id) / "device_public.key"
    if not public_path.exists():
        _, public_bytes = _write_key_pair(user_id)
        return public_bytes
    return public_path.read_bytes()


def get_user_public_key_base64(user_id: int) -> str:
    return base64.b64encode(load_user_public_key_bytes(user_id)).decode("ascii")


def find_identity_by_public_key(
    db: Session,
    public_key: str,
) -> UserIdentity | None:
    return (
        db.query(UserIdentity)
        .filter(UserIdentity.public_key == public_key)
        .first()
    )
