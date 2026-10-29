import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import AuthToken, User


security = HTTPBearer()
AUTH_TOKEN_TTL_SECONDS = max(60, int(os.environ.get("SENTINEL_TOKEN_TTL_SECONDS", "604800")))


def create_auth_token(
    db: Session,
    user: User,
) -> str:
    """Create a random authentication token and store only its hash."""

    token = secrets.token_urlsafe(32)

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    auth_token = AuthToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=AUTH_TOKEN_TTL_SECONDS),
    )

    db.add(auth_token)
    db.commit()

    return token


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        security
    ),
    db: Session = Depends(get_db),
) -> User:
    """Authenticate a request using a Bearer token."""

    token = credentials.credentials

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    auth_token = (
        db.query(AuthToken)
        .filter(
            AuthToken.token_hash == token_hash
        )
        .first()
    )

    if auth_token is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token.",
        )

    expires_at = auth_token.expires_at
    if expires_at is None:
        db.delete(auth_token)
        db.commit()
        raise HTTPException(
            status_code=401,
            detail="Authentication token expired. Please sign in again.",
        )
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        db.delete(auth_token)
        db.commit()
        raise HTTPException(
            status_code=401,
            detail="Authentication token expired. Please sign in again.",
        )

    user = (
        db.query(User)
        .filter(User.id == auth_token.user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Authenticated user not found.",
        )

    return user


def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """Require an authenticated account with the administrator role."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return current_user
