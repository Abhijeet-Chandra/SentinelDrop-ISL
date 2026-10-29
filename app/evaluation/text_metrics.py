"""Admin-only text and primitive-level cryptographic demonstrations."""

from __future__ import annotations

import hashlib
import os
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.security.encryption import decrypt_data, encrypt_data


def _aes_block(key: bytes, block: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _changed_bits(left: bytes, right: bytes) -> int:
    return sum((a ^ b).bit_count() for a, b in zip(left, right))


def _changed_hex_characters(left: bytes, right: bytes) -> int:
    left_hex, right_hex = left.hex(), right.hex()
    return sum(a != b for a, b in zip(left_hex, right_hex))


def analyze_text(text: str) -> dict:
    """Measure sample-text AEAD timings, AES avalanche, and SHA-256 properties."""
    if not text:
        raise ValueError("Enter sample text to analyze.")
    if len(text.encode("utf-8")) > 1_000_000:
        raise ValueError("Sample text must be 1 MB or smaller.")

    plaintext = text.encode("utf-8")
    key = os.urandom(32)

    start = time.perf_counter()
    ciphertext, nonce = encrypt_data(plaintext, key, b"sentineldrop-admin-text-analysis")
    encryption_ms = (time.perf_counter() - start) * 1000
    start = time.perf_counter()
    recovered = decrypt_data(ciphertext, nonce, key, b"sentineldrop-admin-text-analysis")
    decryption_ms = (time.perf_counter() - start) * 1000

    # Demonstrate AES's block-level avalanche using an ephemeral evaluation key,
    # not an application session key or the AES-GCM nonce/ciphertext.
    rounds = 16
    avalanche_samples = []
    diffusion_counts = []
    confusion_counts = []
    for _ in range(rounds):
        sample_key = os.urandom(32)
        sample_block = bytearray(os.urandom(16))
        sample_baseline = _aes_block(sample_key, bytes(sample_block))
        changed_sample = bytearray(sample_block)
        changed_sample[0] ^= 1
        changed_output = _aes_block(sample_key, bytes(changed_sample))
        avalanche_samples.append(
            {
                "changed_bits": _changed_bits(sample_baseline, changed_output),
                "bit_change_percent": _changed_bits(sample_baseline, changed_output) / 128 * 100,
                "changed_hex_characters": _changed_hex_characters(sample_baseline, changed_output),
                "hex_character_change_percent": _changed_hex_characters(sample_baseline, changed_output) / 32 * 100,
            }
        )
        changed_key = bytearray(sample_key)
        changed_key[0] ^= 1
        confusion_counts.append(_changed_bits(sample_baseline, _aes_block(bytes(changed_key), bytes(sample_block))))
        for bit_index in range(128):
            probe = bytearray(sample_block)
            probe[bit_index // 8] ^= 1 << (bit_index % 8)
            diffusion_counts.append(_changed_bits(sample_baseline, _aes_block(sample_key, bytes(probe))))

    avalanche_bits = round(sum(row["changed_bits"] for row in avalanche_samples) / rounds)
    avalanche_percent = sum(row["bit_change_percent"] for row in avalanche_samples) / rounds
    avalanche_character_percent = sum(row["hex_character_change_percent"] for row in avalanche_samples) / rounds
    avalanche_character_count = round(sum(row["changed_hex_characters"] for row in avalanche_samples) / rounds, 2)
    block_bits = 128
    confusion_bits = round(sum(confusion_counts) / rounds)
    diffusion_average = sum(diffusion_counts) / len(diffusion_counts)

    digest = hashlib.sha256(plaintext).digest()
    changed_hash_input = bytearray(plaintext)
    changed_hash_input[0] ^= 1
    changed_digest = hashlib.sha256(changed_hash_input).digest()
    hash_changed_bits = _changed_bits(digest, changed_digest)

    return {
        "input_bytes": len(plaintext),
        "ciphertext_bytes": len(ciphertext),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "encryption_time_ms": round(encryption_ms, 4),
        "decryption_time_ms": round(decryption_ms, 4),
        "total_crypto_time_ms": round(encryption_ms + decryption_ms, 4),
        "recovery_matches": recovered == plaintext,
        "aes_block_bits": block_bits,
        "diffusion_average_changed_bits": round(diffusion_average, 2),
        "diffusion_min_changed_bits": min(diffusion_counts),
        "diffusion_max_changed_bits": max(diffusion_counts),
        "diffusion_percent": round(diffusion_average / block_bits * 100, 2),
        "avalanche_changed_bits": avalanche_bits,
        "avalanche_percent": round(avalanche_percent, 2),
        "avalanche_rounds": rounds,
        "avalanche_mean_percent": round(avalanche_percent, 2),
        "avalanche_mean_changed_hex_characters": avalanche_character_count,
        "avalanche_mean_hex_character_change_percent": round(avalanche_character_percent, 2),
        "hex_character_reference_percent": 100,
        "aes_block_hex_characters": 32,
        "avalanche_samples": [
            {
                "sample": index + 1,
                "changed_bits": row["changed_bits"],
                "bit_change_percent": round(row["bit_change_percent"], 2),
                "changed_hex_characters": row["changed_hex_characters"],
                "hex_character_change_percent": round(row["hex_character_change_percent"], 2),
            }
            for index, row in enumerate(avalanche_samples)
        ],
        "confusion_changed_bits": confusion_bits,
        "confusion_percent": round(confusion_bits / block_bits * 100, 2),
        "hash_algorithm": "SHA-256",
        "sample_text_sha256": digest.hex(),
        "hash_avalanche_changed_bits": hash_changed_bits,
        "hash_output_bits": len(digest) * 8,
        "hash_avalanche_percent": round(hash_changed_bits / (len(digest) * 8) * 100, 2),
        "hash_security_note": "For ideal SHA-256, generic preimage search is about 2^256 work and generic collision search about 2^128 work. These are theoretical estimates, not measured by this demo.",
        "analysis_note": "Diffusion averages output changes across every possible one-bit plaintext flip in 16 AES-256 block samples. Avalanche reports 16 one-bit plaintext-flip samples; character-level means changed hexadecimal characters. Confusion averages one key-bit flip per sample. All use fresh temporary evaluation material, not the app's session key. AES-GCM encrypt/decrypt timings measure this sample on this server process only.",
    }
