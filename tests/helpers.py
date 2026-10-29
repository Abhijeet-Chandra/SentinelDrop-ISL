import hashlib

from app.database.connection import SessionLocal
from app.database.models import AuthToken
from app.services.session_manager import session_manager


def bind_test_session(session, headers, peer_headers=None):
    """Bind an in-memory test session to authenticated test accounts."""
    def user_id(auth_headers):
        token = auth_headers["Authorization"].removeprefix("Bearer ")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        db = SessionLocal()
        try:
            record = db.query(AuthToken).filter(AuthToken.token_hash == token_hash).first()
            assert record is not None
            return record.user_id
        finally:
            db.close()

    user_a = user_id(headers)
    user_b = user_id(peer_headers) if peer_headers else user_a
    session_manager.add_session(session)
    session_manager.add_session_view(session, user_a)
    if user_b != user_a:
        session_manager.add_session_view(session, user_b)
    session_manager.bind_users(session.session_id, user_a, user_b)


def get_test_user_id(auth_headers):
    token = auth_headers["Authorization"].removeprefix("Bearer ")
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    db = SessionLocal()
    try:
        record = db.query(AuthToken).filter(AuthToken.token_hash == token_hash).first()
        assert record is not None
        return record.user_id
    finally:
        db.close()


def create_admin_headers(client):
    from uuid import uuid4

    from app.database.models import User
    from app.security.passwords import hash_password

    username = f"test_admin_{uuid4().hex[:8]}"
    password = "TestAdminPassword123!"
    db = SessionLocal()
    try:
        db.add(User(username=username, password_hash=hash_password(password), is_admin=True))
        db.commit()
    finally:
        db.close()
    response = client.post("/auth/admin/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def register_client_identity(client, headers):
    """Create test-only browser identity material and register its public half."""
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from app.services.user_identity import fingerprint_from_public_bytes

    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key = base64.b64encode(public_bytes).decode("ascii")
    fingerprint = fingerprint_from_public_bytes(public_bytes)
    response = client.put(
        "/devices/me/identity",
        headers=headers,
        json={"public_key": public_key, "fingerprint": fingerprint},
    )
    assert response.status_code == 200, response.text
    return {"private_key": private_key, "public_key": public_key, "fingerprint": fingerprint}
