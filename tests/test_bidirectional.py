import uuid
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from fastapi.testclient import TestClient

from app.database.connection import SessionLocal
from app.database.models import User
from app.main import app
from app.services.session_manager import session_manager
from app.services.user_identity import ensure_user_identity
from tests.helpers import create_admin_headers, register_client_identity


client = TestClient(app)
CLIENT_IDENTITIES = {}


def _register_and_login(prefix: str) -> tuple[dict, str]:
    username = f"{prefix}_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    register = client.post(
        "/auth/register",
        json={"username": username, "password": password},
    )
    assert register.status_code == 200
    login = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    CLIENT_IDENTITIES[headers["Authorization"]] = register_client_identity(client, headers)
    return headers, username


def _derive_client_key(headers, peer_public_key, session_id, sender_user_id, recipient_user_id):
    identity = CLIENT_IDENTITIES[headers["Authorization"]]
    peer = X25519PublicKey.from_public_bytes(base64.b64decode(peer_public_key))
    shared = identity["private_key"].exchange(peer)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(session_id.encode()).digest(),
        info=f"SentinelDrop end-to-end AES-256-GCM v2|{session_id}|{sender_user_id}|{recipient_user_id}".encode(),
    ).derive(shared)


def _encrypted_payload(headers, session, plaintext, message_type="text", extra=None):
    key = _derive_client_key(
        headers,
        session["peer_public_key"],
        session["session_id"],
        session["local_user_id"],
        session["peer_user_id"],
    )
    sequence = int.from_bytes(os.urandom(4), "big")
    metadata = {
        "session_id": session["session_id"],
        "sequence_number": sequence,
        "message_type": message_type,
        "sender_user_id": session["local_user_id"],
        "recipient_user_id": session["peer_user_id"],
        **(extra or {}),
    }
    aad = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        **metadata,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }, key, aad


def _pair_users(headers_a, headers_b):
    pairing_a = client.get("/devices/me/pairing", headers=headers_a).json()
    pairing_b = client.get("/devices/me/pairing", headers=headers_b).json()
    confirm_a = client.post(
        "/devices/pairing/confirm",
        headers=headers_a,
        json={
            "payload": pairing_b["payload"],
            "fingerprint": pairing_b["fingerprint"],
        },
    )
    confirm_b = client.post(
        "/devices/pairing/confirm",
        headers=headers_b,
        json={
            "payload": pairing_a["payload"],
            "fingerprint": pairing_a["fingerprint"],
        },
    )
    assert confirm_a.status_code == 200
    assert confirm_b.status_code == 200
    return pairing_a, pairing_b


def test_bidirectional_text_between_two_users():
    headers_a, _ = _register_and_login("alice")
    headers_b, _ = _register_and_login("bob")
    pairing_a, pairing_b = _pair_users(headers_a, headers_b)

    open_a = client.post(
        "/sessions/open",
        headers=headers_a,
        json={"device_public_key": pairing_b["public_key"]},
    )
    assert open_a.status_code == 200
    session_a = open_a.json()
    open_b = client.post(
        "/sessions/open",
        headers=headers_b,
        json={"device_public_key": pairing_a["public_key"]},
    )
    assert open_b.json()["session_id"] == session_a["session_id"]
    session_b = open_b.json()

    payload, key, aad = _encrypted_payload(headers_a, session_a, b"hello from A")
    send_a = client.post(
        "/messages/send",
        headers=headers_a,
        json=payload,
    )
    assert send_a.status_code == 200

    pending_b = client.get("/messages/pending", headers=headers_b).json()
    incoming_b = [item for item in pending_b["messages"] if item["ciphertext"] == payload["ciphertext"]]
    assert incoming_b
    record = incoming_b[0]
    peer_b = X25519PublicKey.from_public_bytes(base64.b64decode(pairing_a["public_key"]))
    shared_b = CLIENT_IDENTITIES[headers_b["Authorization"]]["private_key"].exchange(peer_b)
    key_b = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(session_b["session_id"].encode()).digest(), info=f"SentinelDrop end-to-end AES-256-GCM v2|{session_b['session_id']}|{record['sender_user_id']}|{record['recipient_user_id']}".encode()).derive(shared_b)
    metadata = {key: record[key] for key in ("session_id", "sequence_number", "message_type", "sender_user_id", "recipient_user_id")}
    aad_b = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    assert AESGCM(key_b).decrypt(bytes.fromhex(record["nonce"]), bytes.fromhex(record["ciphertext"]), aad_b) == b"hello from A"
    assert "message" not in send_a.json()
    receive_b = client.post(
        "/messages/receive",
        headers=headers_b,
        json={"session_id": record["session_id"], "sequence_number": record["sequence_number"], "ciphertext": record["ciphertext"]},
    )
    assert receive_b.status_code == 200
    payload_b, _, _ = _encrypted_payload(headers_b, session_b, b"hello from B")
    send_b = client.post(
        "/messages/send",
        headers=headers_b,
        json=payload_b,
    )
    assert send_b.status_code == 200
    pending_a = client.get("/messages/pending", headers=headers_a).json()
    match = [item for item in pending_a["messages"] if item["ciphertext"] == payload_b["ciphertext"]]
    assert match
    record_b = match[0]
    assert "message" not in send_b.json()
    receive_a = client.post("/messages/receive", headers=headers_a, json={"session_id": record_b["session_id"], "sequence_number": record_b["sequence_number"], "ciphertext": record_b["ciphertext"]})
    assert receive_a.status_code == 200
    session_manager.remove_session(session_a["session_id"])


def test_ciphertext_session_and_inbox_survive_api_process_restart():
    headers_a, _ = _register_and_login("restarta")
    headers_b, _ = _register_and_login("restartb")
    pairing_a, pairing_b = _pair_users(headers_a, headers_b)
    opened = client.post(
        "/sessions/open",
        headers=headers_a,
        json={"device_public_key": pairing_b["public_key"]},
    )
    assert opened.status_code == 200
    session_a = opened.json()
    payload, _, _ = _encrypted_payload(headers_a, session_a, b"survives restart")
    assert client.post("/messages/send", headers=headers_a, json=payload).status_code == 200

    # A worker restart clears all process-local session state.
    session_manager.remove_session(session_a["session_id"])

    reopened = client.post(
        "/sessions/open",
        headers=headers_b,
        json={"device_public_key": pairing_a["public_key"]},
    )
    assert reopened.status_code == 200
    assert reopened.json()["session_id"] == session_a["session_id"]
    pending = client.get("/messages/pending", headers=headers_b).json()["messages"]
    assert any(item["ciphertext"] == payload["ciphertext"] for item in pending)


def test_bidirectional_image_and_transcript():
    headers_a, _ = _register_and_login("imga")
    headers_b, _ = _register_and_login("imgb")
    pairing_a, pairing_b = _pair_users(headers_a, headers_b)
    session_a = client.post(
        "/sessions/open",
        headers=headers_a,
        json={"device_public_key": pairing_b["public_key"]},
    )
    session_a = session_a.json()
    session_b = client.post(
        "/sessions/open",
        headers=headers_b,
        json={"device_public_key": pairing_a["public_key"]},
    ).json()
    image_payload, _, _ = _encrypted_payload(
        headers_a,
        session_a,
        b"fake-png-bytes",
        "image",
        {"filename": "shot.png", "mime_type": "image/png", "file_size": len(b"fake-png-bytes")},
    )
    send_image = client.post(
        "/files/inbox",
        headers=headers_a,
        json=image_payload,
    )
    assert send_image.status_code == 200
    pending = client.get("/messages/pending", headers=headers_b).json()
    files = [item for item in pending["messages"] if item.get("transfer_kind") == "file"]
    assert files
    file_record = files[0]
    file_metadata = {key: file_record[key] for key in ("session_id", "sequence_number", "message_type", "sender_user_id", "recipient_user_id", "filename", "mime_type", "file_size")}
    file_aad = json.dumps(file_metadata, sort_keys=True, separators=(",", ":")).encode()
    file_key = _derive_client_key(headers_b, pairing_a["public_key"], session_b["session_id"], file_record["sender_user_id"], file_record["recipient_user_id"])
    assert AESGCM(file_key).decrypt(bytes.fromhex(file_record["nonce"]), bytes.fromhex(file_record["ciphertext"]), file_aad) == b"fake-png-bytes"
    received = client.post(
        "/files/receive-encrypted",
        headers=headers_b,
        json={"session_id": file_record["session_id"], "sequence_number": file_record["sequence_number"], "ciphertext": file_record["ciphertext"]},
    )
    assert received.status_code == 200

    voice_payload, _, _ = _encrypted_payload(headers_b, session_b, b"transcribed note", "audio_transcript")
    send_voice = client.post(
        "/messages/send",
        headers=headers_b,
        json=voice_payload,
    )
    assert send_voice.status_code == 200
    pending_a = client.get("/messages/pending", headers=headers_a).json()
    voice = [
        item
        for item in pending_a["messages"]
        if item.get("message_type") == "audio_transcript"
    ]
    assert voice
    voice_record = voice[0]
    voice_key = _derive_client_key(headers_a, pairing_b["public_key"], session_a["session_id"], voice_record["sender_user_id"], voice_record["recipient_user_id"])
    voice_metadata = {key: voice_record[key] for key in ("session_id", "sequence_number", "message_type", "sender_user_id", "recipient_user_id")}
    voice_aad = json.dumps(voice_metadata, sort_keys=True, separators=(",", ":")).encode()
    assert AESGCM(voice_key).decrypt(bytes.fromhex(voice_record["nonce"]), bytes.fromhex(voice_record["ciphertext"]), voice_aad) == b"transcribed note"
    receive_voice = client.post("/messages/receive", headers=headers_a, json={"session_id": voice_record["session_id"], "sequence_number": voice_record["sequence_number"], "ciphertext": voice_record["ciphertext"]})
    assert receive_voice.status_code == 200
    session_manager.remove_session(session_a["session_id"])


def test_login_and_pairing_audit_events():
    headers_a, name_a = _register_and_login("audita")
    headers_b, _ = _register_and_login("auditb")
    _pair_users(headers_a, headers_b)
    assert client.get("/audit/events", headers=headers_a).status_code == 403
    admin_headers = create_admin_headers(client)
    events = client.get("/audit/events", headers=admin_headers).json()["events"]
    types = {event["event_type"] for event in events}
    assert "LOGIN_SUCCESS" in types
    assert "DEVICE_PAIRING_SUCCESS" in types
    assert any(event.get("created_at") for event in events)
    assert any(event.get("previous_hash") or event["id"] for event in events)
    bad = client.post(
        "/auth/login",
        json={"username": name_a, "password": "wrong-password"},
    )
    assert bad.status_code == 401
    events = client.get("/audit/events", headers=admin_headers).json()["events"]
    assert any(event["event_type"] == "LOGIN_FAILURE" for event in events)


def test_encryption_demo_log_disabled_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("ENABLE_ENCRYPTION_DEMO_LOG", raising=False)
    log_path = tmp_path / "encryption_demo.log"
    monkeypatch.setattr(
        "app.services.encryption_demo_log.DEMO_LOG_PATH",
        log_path,
    )
    headers_a, _ = _register_and_login("demooff")
    headers_b, _ = _register_and_login("demopeer")
    _, pairing_b = _pair_users(headers_a, headers_b)
    opened = client.post(
        "/sessions/open",
        headers=headers_a,
        json={"device_public_key": pairing_b["public_key"]},
    )
    rejected = client.post(
        "/messages/send",
        headers=headers_a,
        json={
            "session_id": opened.json()["session_id"],
            "message": "should not be logged",
        },
    )
    assert rejected.status_code == 422
    assert not log_path.exists()


def test_encryption_demo_log_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("ENABLE_ENCRYPTION_DEMO_LOG", "true")
    monkeypatch.setenv("ENCRYPTION_DEMO_INCLUDE_PLAINTEXT", "true")
    log_path = tmp_path / "encryption_demo.log"
    monkeypatch.setattr(
        "app.services.encryption_demo_log.DEMO_LOG_PATH",
        log_path,
    )
    headers_a, _ = _register_and_login("demoon")
    headers_b, _ = _register_and_login("demoonpeer")
    _, pairing_b = _pair_users(headers_a, headers_b)
    opened = client.post(
        "/sessions/open",
        headers=headers_a,
        json={"device_public_key": pairing_b["public_key"]},
    )
    send = client.post(
        "/messages/send",
        headers=headers_a,
        json={
            "session_id": opened.json()["session_id"],
            "message": "demo plaintext",
            "message_type": "text",
        },
    )
    assert send.status_code == 422
    assert not log_path.exists()
    session_manager.remove_session(opened.json()["session_id"])


def test_user_identities_are_distinct():
    headers_a, name_a = _register_and_login("ida")
    headers_b, name_b = _register_and_login("idb")
    pairing_a = client.get("/devices/me/pairing", headers=headers_a).json()
    pairing_b = client.get("/devices/me/pairing", headers=headers_b).json()
    assert pairing_a["public_key"] != pairing_b["public_key"]
    assert pairing_a["fingerprint"] != pairing_b["fingerprint"]
    db = SessionLocal()
    try:
        user_a = db.query(User).filter(User.username == name_a).first()
        user_b = db.query(User).filter(User.username == name_b).first()
        identity_a = ensure_user_identity(db, user_a)
        identity_b = ensure_user_identity(db, user_b)
        assert identity_a.public_key != identity_b.public_key
    finally:
        db.close()
