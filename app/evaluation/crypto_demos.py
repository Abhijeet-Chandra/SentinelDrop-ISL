"""Bounded, admin-facing demonstrations for hashing and signatures."""

from __future__ import annotations

import base64
import hashlib
import os
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


MAX_HASH_INPUT_BYTES = 1_000_000
TOY_DIGEST_BITS = 12
TOY_SEARCH_LIMIT = 25_000


def _toy_digest(data: bytes) -> int:
    """Return an intentionally truncated SHA-256 digest for teaching only."""
    return int.from_bytes(hashlib.sha256(data).digest()[:2], "big") & ((1 << TOY_DIGEST_BITS) - 1)


def _toy_hash_demos() -> dict:
    original = b"sentinel educational sample"
    target = _toy_digest(original)

    started = time.perf_counter()
    preimage_attempts = None
    for candidate_number in range(TOY_SEARCH_LIMIT):
        if _toy_digest(f"preimage-{candidate_number}".encode()) == target:
            preimage_attempts = candidate_number + 1
            break
    preimage_ms = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    second_preimage_attempts = None
    for candidate_number in range(TOY_SEARCH_LIMIT):
        candidate = f"second-preimage-{candidate_number}".encode()
        if candidate != original and _toy_digest(candidate) == target:
            second_preimage_attempts = candidate_number + 1
            break
    second_preimage_ms = (time.perf_counter() - started) * 1000

    seen: dict[bytes, int] = {}
    collision_attempts = None
    started = time.perf_counter()
    for candidate_number in range(TOY_SEARCH_LIMIT):
        digest = _toy_digest(f"collision-{candidate_number}".encode())
        if digest in seen:
            collision_attempts = candidate_number + 1
            break
        seen[digest] = candidate_number
    collision_ms = (time.perf_counter() - started) * 1000

    return {
        "digest_bits": TOY_DIGEST_BITS,
        "attempt_limit": TOY_SEARCH_LIMIT,
        "preimage_attempts": preimage_attempts,
        "preimage_time_ms": round(preimage_ms, 4),
        "second_preimage_attempts": second_preimage_attempts,
        "second_preimage_time_ms": round(second_preimage_ms, 4),
        "collision_attempts": collision_attempts,
        "collision_time_ms": round(collision_ms, 4),
        "scope": "educational only",
        "note": (
            "These searches use only a 12-bit truncated SHA-256 toy digest and a fixed work limit. "
            "They illustrate the concepts; they do not test or weaken full SHA-256."
        ),
    }


def analyze_hash(text: str) -> dict:
    if not text:
        raise ValueError("Enter sample text to hash.")
    data = text.encode("utf-8")
    if len(data) > MAX_HASH_INPUT_BYTES:
        raise ValueError("Hash input must be 1 MB or smaller.")

    started = time.perf_counter()
    digest = hashlib.sha256(data).hexdigest()
    generation_ms = (time.perf_counter() - started) * 1000

    sizes = (32, 1024, 16 * 1024, 256 * 1024)
    size_benchmarks = []
    for size in sizes:
        payload = os.urandom(size)
        samples = []
        for _ in range(5):
            started = time.perf_counter()
            hashlib.sha256(payload).digest()
            samples.append((time.perf_counter() - started) * 1000)
        size_benchmarks.append(
            {"bytes": size, "mean_generation_time_ms": round(sum(samples) / len(samples), 4)}
        )

    changed = bytearray(data)
    changed[0] ^= 1
    changed_digest = hashlib.sha256(changed).digest()
    original_digest = bytes.fromhex(digest)
    changed_bits = sum((left ^ right).bit_count() for left, right in zip(original_digest, changed_digest))

    return {
        "algorithm": "SHA-256",
        "input_bytes": len(data),
        "digest_hex": digest,
        "generation_time_ms": round(generation_ms, 4),
        "modified_input_digest_hex": changed_digest.hex(),
        "digest_changed_bits": changed_bits,
        "digest_output_bits": 256,
        "size_benchmarks": size_benchmarks,
        "toy_demonstration": _toy_hash_demos(),
        "security_note": (
            "A demo cannot prove resistance. Generic idealized SHA-256 work estimates are about 2^256 "
            "for a preimage and 2^128 for a collision; the 12-bit searches above are not SHA-256 attacks."
        ),
    }


def run_signature_demo(text: str) -> dict:
    if not text:
        raise ValueError("Enter sample text to sign.")
    data = text.encode("utf-8")
    if len(data) > MAX_HASH_INPUT_BYTES:
        raise ValueError("Signature input must be 1 MB or smaller.")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    started = time.perf_counter()
    signature = private_key.sign(data)
    sign_ms = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    try:
        public_key.verify(signature, data)
        valid = True
    except InvalidSignature:
        valid = False
    verify_ms = (time.perf_counter() - started) * 1000

    altered = data + b"!"
    try:
        public_key.verify(signature, altered)
        altered_valid = True
    except InvalidSignature:
        altered_valid = False

    return {
        "algorithm": "Ed25519",
        "signature_base64": base64.b64encode(signature).decode("ascii"),
        "public_key_base64": base64.b64encode(
            public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode("ascii"),
        "signature_generation_time_ms": round(sign_ms, 4),
        "verification_time_ms": round(verify_ms, 4),
        "valid_signature_verified": valid,
        "modified_message_verified": altered_valid,
        "private_key_exposed": False,
        "note": "An ephemeral key is generated for this demonstration; the private key is neither returned nor stored.",
    }
