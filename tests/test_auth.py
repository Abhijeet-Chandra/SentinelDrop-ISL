import uuid
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.database.connection import SessionLocal
from app.database.models import AuthToken
from app.main import app
from app.services.auth import get_current_user


client = TestClient(app)


def unique_username():
    return f"testuser_{uuid.uuid4().hex[:8]}"


def test_register_user():
    username = unique_username()

    response = client.post(
        "/auth/register",
        json={
            "username": username,
            "password": "TestPassword123!",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["message"] == (
        "User registered successfully."
    )
    assert body["username"] == username


def test_register_duplicate_user():
    username = unique_username()

    first_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "password": "TestPassword123!",
        },
    )

    assert first_response.status_code == 200

    second_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "password": "AnotherPassword123!",
        },
    )

    assert second_response.status_code == 409
    assert second_response.json()["detail"] == (
        "Username already exists."
    )


def test_login_success_returns_token():
    username = unique_username()
    password = "TestPassword123!"

    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "password": password,
        },
    )

    assert register_response.status_code == 200

    login_response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    assert login_response.status_code == 200

    body = login_response.json()

    assert body["message"] == "Login successful."
    assert body["username"] == username
    assert body["access_token"]
    assert body["token_type"] == "bearer"


def test_login_invalid_password():
    username = unique_username()

    client.post(
        "/auth/register",
        json={
            "username": username,
            "password": "CorrectPassword123!",
        },
    )

    response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": "WrongPassword123!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid username or password."
    )


def test_login_unknown_user():
    response = client.post(
        "/auth/login",
        json={
            "username": unique_username(),
            "password": "SomePassword123!",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == (
        "Invalid username or password."
    )


def test_token_is_stored_as_hash():
    username = unique_username()
    password = "TestPassword123!"

    client.post(
        "/auth/register",
        json={
            "username": username,
            "password": password,
        },
    )

    login_response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    token = login_response.json()["access_token"]

    db = SessionLocal()

    try:
        stored_token = (
            db.query(AuthToken)
            .order_by(AuthToken.id.desc())
            .first()
        )

        assert stored_token is not None
        assert stored_token.token_hash != token
        assert len(stored_token.token_hash) == 64

    finally:
        db.close()


def test_expired_bearer_token_requires_sign_in_again():
    username = unique_username()
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"username": username, "password": password}).status_code == 200
    login = client.post("/auth/login", json={"username": username, "password": password})
    token = login.json()["access_token"]
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    db = SessionLocal()
    try:
        row = db.query(AuthToken).filter(AuthToken.token_hash == token_hash).one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()
