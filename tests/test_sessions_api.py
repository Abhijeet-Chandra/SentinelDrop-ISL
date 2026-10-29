import uuid

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_legacy_session_establish_requires_authentication():
    response = client.post(
        "/sessions/establish",
        json={"device_public_key": "untrusted-device-key", "ephemeral_public_key": "AA=="},
    )
    assert response.status_code == 401


def test_authenticated_legacy_session_establish_is_gone():
    username = f"legacy_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"username": username, "password": password}).status_code == 200
    login = client.post("/auth/login", json={"username": username, "password": password})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    response = client.post(
        "/sessions/establish",
        headers=headers,
        json={"device_public_key": "untrusted-device-key", "ephemeral_public_key": "AA=="},
    )
    assert response.status_code == 410
    assert "authenticated user pairing" in response.json()["detail"]
