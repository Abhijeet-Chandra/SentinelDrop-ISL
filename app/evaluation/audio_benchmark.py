"""Bounded voice-transcription and transcript-crypto timing for administrators."""

from __future__ import annotations

import os
import statistics
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.services.voice import MODEL_NAME, MODEL_PATH, _model_is_ready, transcribe_wav


MAX_AUDIO_BYTES = 20 * 1024 * 1024
MAX_BENCHMARK_ROUNDS = 3


def run_voice_benchmark(audio_path: Path, rounds: int = 3) -> dict:
    if not 1 <= rounds <= MAX_BENCHMARK_ROUNDS:
        raise ValueError(f"Choose between 1 and {MAX_BENCHMARK_ROUNDS} voice benchmark rounds.")
    if not audio_path.is_file():
        raise ValueError("Choose a valid WAV file.")
    audio_bytes = audio_path.stat().st_size
    if audio_bytes == 0 or audio_bytes > MAX_AUDIO_BYTES:
        raise ValueError("Audio must be non-empty and no larger than 20 MB.")
    if not _model_is_ready(MODEL_PATH):
        raise RuntimeError(f"Provision the offline Vosk model ({MODEL_NAME}) before running this benchmark.")

    key = AESGCM.generate_key(bit_length=256)
    transcription_samples = []
    encryption_samples = []
    decryption_samples = []
    transcript_sizes = []
    roundtrip_verified = True
    for _ in range(rounds):
        started = time.perf_counter()
        transcript = transcribe_wav(audio_path)
        transcription_samples.append((time.perf_counter() - started) * 1000)
        plaintext = transcript.encode("utf-8")
        transcript_sizes.append(len(plaintext))

        nonce = os.urandom(12)
        started = time.perf_counter()
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, b"sentineldrop-admin-voice-benchmark")
        encryption_samples.append((time.perf_counter() - started) * 1000)
        started = time.perf_counter()
        recovered = AESGCM(key).decrypt(nonce, ciphertext, b"sentineldrop-admin-voice-benchmark")
        decryption_samples.append((time.perf_counter() - started) * 1000)
        roundtrip_verified = roundtrip_verified and recovered == plaintext

    summarize = lambda values: {
        "mean_ms": round(statistics.mean(values), 4),
        "median_ms": round(statistics.median(values), 4),
        "min_ms": round(min(values), 4),
        "max_ms": round(max(values), 4),
    }
    return {
        "measured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": MODEL_NAME,
        "rounds": rounds,
        "audio_bytes": audio_bytes,
        "transcript_bytes_mean": round(statistics.mean(transcript_sizes), 2),
        "transcription": summarize(transcription_samples),
        "transcript_encryption": summarize(encryption_samples),
        "transcript_decryption": summarize(decryption_samples),
        "crypto_roundtrip_verified": roundtrip_verified,
        "transcript_returned_or_stored": False,
        "measurement_scope": "backend offline Vosk processing plus isolated AES-GCM transcript microbenchmark; excludes network, device recording, and UI time",
        "note": "Transcript content is discarded after each run. Results depend on the model build, CPU, and runtime environment; compare runs only with that context recorded.",
    }
