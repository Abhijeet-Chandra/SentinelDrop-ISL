import uuid

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def _auth_headers():
    username = f"legacy_hs_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"username": username, "password": password}).status_code == 200
    login = client.post("/auth/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_legacy_server_handshake_requires_authentication():
    response = client.post("/sessions/initiate", json={"device_public_key": "unused"})
    assert response.status_code == 401


def test_legacy_server_handshake_routes_are_disabled():
    headers = _auth_headers()
    initiate = client.post("/sessions/initiate", headers=headers, json={"device_public_key": "unused"})
    finalize = client.post(
        "/sessions/finalize",
        headers=headers,
        json={"session_id": "unused", "peer_ephemeral_public_key": "AA=="},
    )
    assert initiate.status_code == finalize.status_code == 410
