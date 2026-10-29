"""Bounded, in-memory security demonstrations for the Admin Dashboard."""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.middleware.rate_limit import RateLimitMiddleware
from app.services.audit_log import _calculate_hash
from app.services.message_storage import MAX_PENDING_MESSAGES_PER_USER


def _scenario(name: str, setup: str, expected: str, observed: str, passed: bool, limitations: str) -> dict:
    return {
        "name": name,
        "setup": setup,
        "expected": expected,
        "observed": observed,
        "passed": bool(passed),
        "limitations": limitations,
    }


def run_security_demos() -> dict:
    """Run seven small simulations; no accounts, network, or database rows are changed."""
    scenarios = []
    plaintext = b"fixed training sample"
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"local-demo")
    visible_on_api = ciphertext.hex()
    scenarios.append(_scenario(
        "Plaintext versus ciphertext visibility",
        "Encrypt a fixed sample locally with AES-256-GCM and inspect the value modeled as the API payload.",
        "The relay payload contains ciphertext and does not contain the sample plaintext.",
        f"Plaintext present in relay value: {plaintext.hex() in visible_on_api}; ciphertext bytes: {len(ciphertext)}.",
        plaintext.hex() not in visible_on_api and ciphertext != plaintext,
        "This is an in-memory model of the browser/API boundary, not a packet capture of a live browser session.",
    ))

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1
    try:
        AESGCM(key).decrypt(nonce, bytes(tampered), b"local-demo")
        tamper_rejected = False
    except InvalidTag:
        tamper_rejected = True
    scenarios.append(_scenario(
        "Ciphertext tamper detection",
        "Flip one bit in an AES-GCM ciphertext body while keeping its nonce and tag.",
        "Authenticated decryption rejects the modified ciphertext.",
        f"InvalidTag rejection observed: {tamper_rejected}.",
        tamper_rejected,
        "Demonstrates AEAD integrity for this sample; it is not a penetration test of the deployed app.",
    ))

    seen = {"demo-session:sender-1:sequence-7"}
    replay_identifier = "demo-session:sender-1:sequence-7"
    replay_rejected = replay_identifier in seen
    scenarios.append(_scenario(
        "Replay detection",
        "Submit the same bounded session/sender/sequence identifier twice to an isolated replay set.",
        "The second identifier is recognized as already used.",
        f"Duplicate identifier rejected: {replay_rejected}.",
        replay_rejected,
        "This models a duplicate check; persistent API replay behavior is separately covered by integration tests.",
    ))

    trusted_private = X25519PrivateKey.generate()
    attacker_private = X25519PrivateKey.generate()
    trusted_public = trusted_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    attacker_public = attacker_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    trusted_fingerprint = hashlib.sha256(trusted_public).digest()
    impersonation_accepted = hashlib.sha256(attacker_public).digest() == trusted_fingerprint
    scenarios.append(_scenario(
        "Untrusted device impersonation",
        "Compare a generated attacker's X25519 public-key fingerprint with a separately trusted identity.",
        "A different public key is not accepted as the trusted device.",
        f"Attacker fingerprint matched trusted identity: {impersonation_accepted}.",
        not impersonation_accepted,
        "Uses generated keys in memory; it does not exercise a real account or pairing QR.",
    ))

    limiter = RateLimitMiddleware(lambda scope, receive, send: None, login_max_requests=12, window_seconds=60)
    allowed_attempts = sum(limiter._allow("isolated-admin-demo", 12) for _ in range(12))
    thirteenth_allowed = limiter._allow("isolated-admin-demo", 12)
    scenarios.append(_scenario(
        "Failed-login rate-limit policy",
        "Apply the same sliding-window limiter used by the API to 13 local login-attempt events.",
        "The first 12 are under the configured threshold and the next is blocked.",
        f"Allowed before block: {allowed_attempts}; 13th attempt allowed: {thirteenth_allowed}.",
        allowed_attempts == 12 and not thirteenth_allowed,
        "No password is checked and no real account is locked; this exercises only the local limiter policy.",
    ))

    count_at_limit = MAX_PENDING_MESSAGES_PER_USER
    queue_rejects_next = count_at_limit >= MAX_PENDING_MESSAGES_PER_USER
    scenarios.append(_scenario(
        "Bounded pending-message queue",
        f"Evaluate the configured per-recipient cap using a simulated queue of {count_at_limit} records.",
        "A new transfer is refused when the recipient queue is full.",
        f"Configured cap: {MAX_PENDING_MESSAGES_PER_USER}; next transfer refused: {queue_rejects_next}.",
        queue_rejects_next,
        "The demo does not create queue rows or send a flood; API enforcement is covered by tests.",
    ))

    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    original_hash = _calculate_hash("DEMO", "demo-session", "original audit detail", timestamp, None)
    modified_expected_hash = _calculate_hash("DEMO", "demo-session", "modified audit detail", timestamp, None)
    audit_tamper_detected = original_hash != modified_expected_hash
    scenarios.append(_scenario(
        "Audit-row modification detection",
        "Hash a fixed audit row, then alter its details without updating its recorded hash.",
        "Recomputing the row hash detects that the details changed.",
        f"Recorded and recomputed hashes differ: {audit_tamper_detected}.",
        audit_tamper_detected,
        "This detects a changed row when its recorded hash remains; a full-chain rewrite or tail deletion needs external anchoring.",
    ))

    return {
        "scope": "isolated in-memory demonstration",
        "scenarios": scenarios,
        "note": "All seven scenarios use bounded sample data. No live network traffic, user messages, accounts, or audit rows are changed.",
    }
