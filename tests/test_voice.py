from pathlib import Path
import tarfile
import wave

import pytest

import app.services.voice as voice_service
from app.services.voice import (
    MODEL_PATH,
    _model_is_ready,
    validate_wav_file,
    transcribe_wav,
)


def create_test_wav(path: Path):
    with wave.open(str(path), "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(16000)
        audio.writeframes(b"\x00\x00" * 16000)


def test_validate_wav_file(tmp_path):
    wav_path = tmp_path / "test.wav"
    create_test_wav(wav_path)

    audio = validate_wav_file(wav_path)

    try:
        assert audio.getnchannels() == 1
        assert audio.getsampwidth() == 2
        assert audio.getframerate() == 16000
    finally:
        audio.close()


def test_validate_wav_rejects_missing_file(tmp_path):
    with pytest.raises(
        ValueError,
        match="does not exist",
    ):
        validate_wav_file(tmp_path / "missing.wav")


def test_validate_wav_rejects_stereo(tmp_path):
    wav_path = tmp_path / "stereo.wav"

    with wave.open(str(wav_path), "wb") as audio:
        audio.setnchannels(2)
        audio.setsampwidth(2)
        audio.setframerate(16000)
        audio.writeframes(b"\x00\x00" * 32000)

    with pytest.raises(
        ValueError,
        match="mono",
    ):
        validate_wav_file(wav_path)


@pytest.mark.skipif(
    not _model_is_ready(MODEL_PATH),
    reason="Offline Vosk model is not installed; tests must not download it.",
)
def test_transcribe_silent_wav(tmp_path):
    wav_path = tmp_path / "silent.wav"
    create_test_wav(wav_path)

    result = transcribe_wav(wav_path)

    assert isinstance(result, str)


def test_browser_model_archive_contains_model_root_and_required_files(tmp_path, monkeypatch):
    model_path = tmp_path / "model"
    (model_path / "am").mkdir(parents=True)
    (model_path / "conf").mkdir(parents=True)
    (model_path / "am" / "final.mdl").write_bytes(b"model")
    (model_path / "conf" / "model.conf").write_text("model config")
    archive_path = tmp_path / "browser-model.tar.gz"
    monkeypatch.setattr(voice_service, "MODEL_PATH", model_path)
    monkeypatch.setattr(voice_service, "MODEL_NAME", "test-model")
    monkeypatch.setattr(voice_service, "BROWSER_MODEL_ARCHIVE_PATH", archive_path)

    result = voice_service.prepare_browser_model_archive()

    assert result == archive_path
    with tarfile.open(result, "r:gz") as archive:
        names = set(archive.getnames())
    assert "test-model/am/final.mdl" in names
    assert "test-model/conf/model.conf" in names
