"""Database-backed authorization for browser-encrypted peer sessions."""

import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database.models import RelaySession, UsedMessageNonce


def get_active_relay_session(db: Session, session_id: str) -> RelaySession | None:
    return (
        db.query(RelaySession)
        .filter(RelaySession.session_id == session_id, RelaySession.active.is_(True))
        .first()
    )


def relay_peer_user_id(db: Session, session_id: str, user_id: int) -> int | None:
    relay = get_active_relay_session(db, session_id)
    if relay is None:
        return None
    if user_id == relay.user_a_id:
        return relay.user_b_id
    if user_id == relay.user_b_id:
        return relay.user_a_id
    return None


def active_relay_session_ids(db: Session, user_id: int) -> list[str]:
    rows = (
        db.query(RelaySession.session_id)
        .filter(
            RelaySession.active.is_(True),
            (RelaySession.user_a_id == user_id) | (RelaySession.user_b_id == user_id),
        )
        .all()
    )
    return [row[0] for row in rows]


def get_or_create_relay_session(
    db: Session,
    user_a_id: int,
    user_b_id: int,
    user_a_public_key: str,
    user_b_public_key: str,
) -> tuple[RelaySession, bool]:
    """Return a durable account-pair session, replacing it after key rotation."""
    if user_a_id < user_b_id:
        low_id, high_id = user_a_id, user_b_id
        low_key, high_key = user_a_public_key, user_b_public_key
    else:
        low_id, high_id = user_b_id, user_a_id
        low_key, high_key = user_b_public_key, user_a_public_key

    relay = (
        db.query(RelaySession)
        .filter(RelaySession.user_a_id == low_id, RelaySession.user_b_id == high_id)
        .first()
    )
    if relay is not None and relay.active and (
        relay.public_key_a == low_key and relay.public_key_b == high_key
    ):
        return relay, False

    session_id = secrets.token_urlsafe(32)
    if relay is None:
        relay = RelaySession(
            session_id=session_id,
            user_a_id=low_id,
            user_b_id=high_id,
            public_key_a=low_key,
            public_key_b=high_key,
            active=True,
        )
        db.add(relay)
    else:
        relay.session_id = session_id
        relay.public_key_a = low_key
        relay.public_key_b = high_key
        relay.active = True
        relay.created_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(relay)
    return relay, True


def revoke_relay_sessions_for_user(db: Session, user_id: int) -> None:
    db.query(RelaySession).filter(
        RelaySession.active.is_(True),
        (RelaySession.user_a_id == user_id) | (RelaySession.user_b_id == user_id),
    ).update({RelaySession.active: False}, synchronize_session=False)
    db.commit()


def reserve_message_nonce(db: Session, session_id: str, sender_user_id: int, nonce: str) -> bool:
    """Reserve a GCM nonce atomically; caller commits with the corresponding message."""
    from sqlalchemy.exc import IntegrityError

    db.add(UsedMessageNonce(session_id=session_id, sender_user_id=sender_user_id, nonce=nonce))
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        return False
    return True
