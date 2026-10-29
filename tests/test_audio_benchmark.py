from app.evaluation import audio_benchmark


def test_voice_benchmark_reports_timing_without_returning_transcript(tmp_path, monkeypatch):
    recording = tmp_path / "sample.wav"
    recording.write_bytes(b"sample wav bytes")
    monkeypatch.setattr(audio_benchmark, "_model_is_ready", lambda _path: True)
    monkeypatch.setattr(audio_benchmark, "transcribe_wav", lambda _path: "sensitive spoken phrase")

    result = audio_benchmark.run_voice_benchmark(recording, rounds=2)
    assert result["rounds"] == 2
    assert result["model"] == audio_benchmark.MODEL_NAME
    assert result["transcript_returned_or_stored"] is False
    assert "sensitive spoken phrase" not in repr(result)
    assert result["crypto_roundtrip_verified"] is True
    assert result["transcription"]["mean_ms"] >= 0
    assert result["transcript_encryption"]["mean_ms"] >= 0
    assert result["transcript_decryption"]["mean_ms"] >= 0
