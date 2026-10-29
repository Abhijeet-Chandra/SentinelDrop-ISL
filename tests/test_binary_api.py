import base64

from fastapi.testclient import TestClient

from app.main import app
from tests.test_messages_api import _account


client = TestClient(app)


def test_server_side_binary_encryption_and_decryption_are_disabled():
    headers, _ = _account("legacy_binary")
    send = client.post(
        "/binary/send",
        headers=headers,
        json={
            "session_id": "unused",
            "data": base64.b64encode(b"must stay client-encrypted").decode("ascii"),
            "message_type": "image",
        },
    )
    assert send.status_code == 410

    receive = client.post(
        "/binary/receive",
        headers=headers,
        json={
            "session_id": "unused",
            "sequence_number": 0,
            "message_type": "image",
            "nonce": "00" * 12,
            "ciphertext": "00" * 16,
        },
    )
    assert receive.status_code == 410


def test_binary_send_requires_authentication():
    response = client.post(
        "/binary/send",
        json={
            "session_id": "unused",
            "data": base64.b64encode(b"x").decode("ascii"),
            "message_type": "image",
        },
    )
    assert response.status_code == 401
