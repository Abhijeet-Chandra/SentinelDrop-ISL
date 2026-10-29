from fastapi.testclient import TestClient

from app.main import app
from tests.test_messages_api import _auth_headers


client = TestClient(app)


def test_pairing_payload_is_public():
    response = client.get("/devices/pairing")
    assert response.status_code == 200
    body = response.json()
    assert body["payload"]
    assert body["fingerprint"]
    assert body["public_key"]


def test_pairing_qr_png_is_public():
    response = client.get("/devices/pairing/qr")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.content[:8] == b"\x89PNG\r\n\x1a\n"


def test_confirm_pairing_requires_auth():
    response = client.post(
        "/devices/pairing/confirm",
        json={"payload": "{}", "fingerprint": "aa"},
    )
    assert response.status_code == 401


def test_trusted_devices_list():
    headers = _auth_headers()
    response = client.get("/devices/trusted", headers=headers)
    assert response.status_code == 200
    assert "devices" in response.json()


def test_browser_public_identity_registration_replaces_server_key_and_is_idempotent():
    import base64
    import hashlib

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    headers = _login_new_user("browser_identity")
    public_bytes = X25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = ":".join(hashlib.sha256(public_bytes).hexdigest()[i:i + 2] for i in range(0, 64, 2))
    request = {"public_key": base64.b64encode(public_bytes).decode(), "fingerprint": fingerprint}

    first = client.put("/devices/me/identity", headers=headers, json=request)
    second = client.put("/devices/me/identity", headers=headers, json=request)
    pairing = client.get("/devices/me/pairing", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert pairing.status_code == 200
    assert pairing.json()["public_key"] == request["public_key"]
    assert "private_key" not in pairing.json()


def test_browser_identity_registration_rejects_wrong_fingerprint():
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    headers = _login_new_user("bad_browser_identity")
    public_bytes = X25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    response = client.put(
        "/devices/me/identity",
        headers=headers,
        json={"public_key": base64.b64encode(public_bytes).decode(), "fingerprint": "00"},
    )
    assert response.status_code == 400


def test_trusted_devices_are_scoped_to_the_user_who_approved_them():
    owner_headers = _login_new_user("trust_owner")
    peer_headers = _login_new_user("trust_peer")
    unrelated_headers = _login_new_user("trust_unrelated")
    from tests.helpers import register_client_identity

    register_client_identity(client, owner_headers)
    register_client_identity(client, peer_headers)
    peer = client.get("/devices/me/pairing", headers=peer_headers).json()

    approved = client.post(
        "/devices/pairing/confirm",
        headers=owner_headers,
        json={"payload": peer["payload"], "fingerprint": peer["fingerprint"]},
    )
    assert approved.status_code == 200

    owner_devices = client.get("/devices/trusted", headers=owner_headers).json()["devices"]
    unrelated_devices = client.get("/devices/trusted", headers=unrelated_headers).json()["devices"]
    assert [device["public_key"] for device in owner_devices] == [peer["public_key"]]
    assert unrelated_devices == []


def _login_new_user(prefix):
    import uuid

    username = f"{prefix}_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"username": username, "password": password}).status_code == 200
    login = client.post("/auth/login", json={"username": username, "password": password})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}
