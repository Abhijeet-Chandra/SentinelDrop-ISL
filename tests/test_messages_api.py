import base64
import hashlib
import json
import os
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi.testclient import TestClient

from app.database.connection import SessionLocal
from app.database.models import Message
from app.main import app
from tests.helpers import register_client_identity


client = TestClient(app)


def _auth_headers():
    return _account("msg")[0]


def _account(prefix):
    username = f"{prefix}_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"username": username, "password": password}).status_code == 200
    login = client.post("/auth/login", json={"username": username, "password": password})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    identity = register_client_identity(client, headers)
    return headers, identity


def _paired_accounts():
    headers_a, identity_a = _account("msg_a")
    headers_b, identity_b = _account("msg_b")
    pairing_a = client.get("/devices/me/pairing", headers=headers_a).json()
    pairing_b = client.get("/devices/me/pairing", headers=headers_b).json()
    for owner, peer in ((headers_a, pairing_b), (headers_b, pairing_a)):
        confirmed = client.post(
            "/devices/pairing/confirm",
            headers=owner,
            json={"payload": peer["payload"], "fingerprint": peer["fingerprint"]},
        )
        assert confirmed.status_code == 200
    opened = client.post("/sessions/open", headers=headers_a, json={"device_public_key": pairing_b["public_key"]})
    assert opened.status_code == 200
    return headers_a, headers_b, identity_a, identity_b, opened.json()


def _encrypted_payload(identity, peer_public_key, session, plaintext=b"hello"):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    shared = identity["private_key"].exchange(
        X25519PublicKey.from_public_bytes(base64.b64decode(peer_public_key))
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(session["session_id"].encode()).digest(),
        info=(
            f"SentinelDrop end-to-end AES-256-GCM v2|{session['session_id']}|"
            f"{session['local_user_id']}|{session['peer_user_id']}"
        ).encode(),
    ).derive(shared)
    metadata = {
        "session_id": session["session_id"],
        "sequence_number": int.from_bytes(os.urandom(4), "big"),
        "message_type": "text",
        "sender_user_id": session["local_user_id"],
        "recipient_user_id": session["peer_user_id"],
    }
    aad = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    nonce = os.urandom(12)
    return {
        **metadata,
        "nonce": nonce.hex(),
        "ciphertext": AESGCM(key).encrypt(nonce, plaintext, aad).hex(),
    }


def test_send_message_requires_authentication():
    response = client.post("/messages/send", json={"session_id": "no-session", "message": "plaintext"})
    assert response.status_code == 401


def test_send_message_rejects_plaintext_contract():
    headers_a, _, _, _, session = _paired_accounts()
    response = client.post(
        "/messages/send",
        headers=headers_a,
        json={"session_id": session["session_id"], "message": "plaintext must never reach API"},
    )
    assert response.status_code == 422


def test_send_message_persists_and_returns_ciphertext_metadata_only():
    headers_a, _, identity_a, _, session = _paired_accounts()
    payload = _encrypted_payload(identity_a, session["peer_public_key"], session)
    response = client.post("/messages/send", headers=headers_a, json=payload)
    assert response.status_code == 200
    result = response.json()
    assert result["encrypted"] is True
    assert result["ciphertext_sha256"] == hashlib.sha256(bytes.fromhex(payload["ciphertext"])).hexdigest()
    assert "ciphertext" not in result and "message" not in result

    db = SessionLocal()
    try:
        stored = db.query(Message).filter(Message.session_id == session["session_id"]).one()
        assert stored.ciphertext == payload["ciphertext"]
        assert "hello" not in stored.ciphertext
        assert stored.sender_user_id == session["local_user_id"]
        assert stored.recipient_user_id == session["peer_user_id"]
    finally:
        db.close()


def test_duplicate_sender_sequence_is_rejected():
    headers_a, _, identity_a, _, session = _paired_accounts()
    payload = _encrypted_payload(identity_a, session["peer_public_key"], session)
    first = client.post("/messages/send", headers=headers_a, json=payload)
    assert first.status_code == 200
    replay = client.post("/messages/send", headers=headers_a, json=payload)
    assert replay.status_code == 409


def test_reused_gcm_nonce_is_rejected_even_with_a_new_sequence():
    headers_a, _, identity_a, _, session = _paired_accounts()
    payload = _encrypted_payload(identity_a, session["peer_public_key"], session)
    assert client.post("/messages/send", headers=headers_a, json=payload).status_code == 200
    reused_nonce = {**payload, "sequence_number": (payload["sequence_number"] + 1) % 4_294_967_296}
    response = client.post("/messages/send", headers=headers_a, json=reused_nonce)
    assert response.status_code == 409
    assert "nonce" in response.json()["detail"].lower()


def test_nonmember_cannot_read_or_acknowledge_ciphertext():
    headers_a, headers_b, identity_a, _, session = _paired_accounts()
    outsider, _ = _account("outsider")
    payload = _encrypted_payload(identity_a, session["peer_public_key"], session)
    assert client.post("/messages/send", headers=headers_a, json=payload).status_code == 200
    assert client.get("/messages/pending", headers=outsider).json()["messages"] == []
    ack = client.post(
        "/messages/receive",
        headers=outsider,
        json={"session_id": session["session_id"], "sequence_number": payload["sequence_number"], "ciphertext": payload["ciphertext"]},
    )
    assert ack.status_code == 403
    pending = client.get("/messages/pending", headers=headers_b).json()["messages"]
    assert any(item["ciphertext"] == payload["ciphertext"] for item in pending)


def test_recipient_pending_queue_is_bounded():
    headers_a, _, identity_a, _, session = _paired_accounts()
    db = SessionLocal()
    try:
        db.add_all(
            Message(
                session_id=f"existing-{index}",
                sequence_number=index,
                message_type="text",
                sender_user_id=session["local_user_id"],
                recipient_user_id=session["peer_user_id"],
                ciphertext_hash=f"{index:064x}",
                ciphertext="00" * 16,
                nonce=f"{index:024x}"[-24:],
            )
            for index in range(200)
        )
        db.commit()
    finally:
        db.close()

    payload = _encrypted_payload(identity_a, session["peer_public_key"], session)
    response = client.post("/messages/send", headers=headers_a, json=payload)
    assert response.status_code == 429
    assert "pending queue" in response.json()["detail"].lower()
