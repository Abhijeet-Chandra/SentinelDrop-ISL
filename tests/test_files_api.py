import uuid

from fastapi.testclient import TestClient

from app.main import app
from tests.test_messages_api import _account


client = TestClient(app)


def test_encrypted_file_inbox_requires_authentication():
    response = client.post(
        "/files/inbox",
        json={
            "session_id": "missing-session",
            "sequence_number": 0,
            "message_type": "image",
            "nonce": "00" * 12,
            "ciphertext": "00" * 16,
            "filename": "demo.png",
            "file_size": 0,
        },
    )
    assert response.status_code == 401


def test_legacy_server_file_encryption_and_decryption_are_disabled(tmp_path):
    headers, _ = _account("legacy_file")
    source = tmp_path / "note.txt"
    source.write_bytes(b"plain files must never be processed by the server")

    with source.open("rb") as stream:
        prepare = client.post(
            "/files/prepare",
            headers=headers,
            data={"session_id": "unused", "message_type": "document"},
            files={"file": ("note.txt", stream, "text/plain")},
        )
    assert prepare.status_code == 410

    receive = client.post(
        "/files/receive",
        headers=headers,
        data={
            "session_id": "unused",
            "sequence_number": 0,
            "message_type": "document",
            "nonce": "00" * 12,
            "ciphertext": "00" * 16,
            "filename": "note.txt",
        },
    )
    assert receive.status_code == 410
    assert client.get("/files/received", headers=headers).status_code == 410
    assert client.get(f"/files/received/{uuid.uuid4().hex}.txt", headers=headers).status_code == 410
