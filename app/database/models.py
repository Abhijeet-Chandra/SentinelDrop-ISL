from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    is_admin: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default="0",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class UserIdentity(Base):
    __tablename__ = "user_identities"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id: Mapped[int] = mapped_column(
        Integer,
        unique=True,
        nullable=False,
        index=True,
    )

    public_key: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    fingerprint: Mapped[str] = mapped_column(
        String(95),
        unique=True,
        nullable=False,
        index=True,
    )

    client_managed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        server_default="0",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class RelaySession(Base):
    """Durable authorization record for a ciphertext-only peer session."""

    __tablename__ = "relay_sessions"
    __table_args__ = (
        UniqueConstraint("user_a_id", "user_b_id", name="uq_relay_session_user_pair"),
    )

    session_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    user_a_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    user_b_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    public_key_a: Mapped[str] = mapped_column(String(255), nullable=False)
    public_key_b: Mapped[str] = mapped_column(String(255), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class AuthToken(Base):
    __tablename__ = "auth_tokens"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        index=True,
    )

    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    session_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    sequence_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    message_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    sender_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    recipient_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)

    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    ciphertext_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)

    nonce: Mapped[str | None] = mapped_column(String(64), nullable=True)

    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)

    mime_type: Mapped[str | None] = mapped_column(String(255), nullable=True)

    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)

    signature: Mapped[str | None] = mapped_column(Text, nullable=True)

    signature_payload: Mapped[str | None] = mapped_column(Text, nullable=True)

    signature_algorithm: Mapped[str | None] = mapped_column(String(100), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class UsedMessageNonce(Base):
    """Per-sender/session AES-GCM nonce registry, including legacy unique values."""

    __tablename__ = "used_message_nonces"
    __table_args__ = (
        UniqueConstraint("session_id", "sender_user_id", "nonce", name="uq_used_nonce_sender_session"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    sender_user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)


class TrustedDevice(Base):
    __tablename__ = "trusted_devices"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    device_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    public_key: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    fingerprint: Mapped[str] = mapped_column(
        String(95),
        unique=True,
        nullable=False,
        index=True,
    )

    trusted: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    paired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class TrustedDeviceApproval(Base):
    """A user's explicit approval of another device identity."""

    __tablename__ = "trusted_device_approvals"
    __table_args__ = (UniqueConstraint("user_id", "device_id", name="uq_user_trusted_device"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("trusted_devices.id"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    session_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )

    details: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
    )

    actor_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )

    status: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    previous_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    entry_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
