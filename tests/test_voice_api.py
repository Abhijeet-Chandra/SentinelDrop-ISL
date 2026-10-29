import uuid

from fastapi.testclient import TestClient

from app.database.connection import SessionLocal
from app.database.models import AuditLog
from app.main import app


client = TestClient(app)


def create_voice_user():
    username = f"voice_{uuid.uuid4().hex[:8]}"
    password = "TestPassword123!"
    client.post("/auth/register", json={"username": username, "password": password})
    login = client.post("/auth/login", json={"username": username, "password": password})
    return username, {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_voice_model_archive_requires_authentication(monkeypatch, tmp_path):
    archive = tmp_path / "model.tar.gz"
    archive.write_bytes(b"test model archive")
    monkeypatch.setattr("app.api.voice.prepare_browser_model_archive", lambda: archive)

    response = client.get("/voice/model")

    assert response.status_code == 401


def test_voice_model_archive_is_downloadable_by_authenticated_user(monkeypatch, tmp_path):
    archive = tmp_path / "model.tar.gz"
    archive.write_bytes(b"test model archive")
    monkeypatch.setattr("app.api.voice.prepare_browser_model_archive", lambda: archive)
    _, headers = create_voice_user()

    response = client.get("/voice/model", headers=headers)

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/gzip"
    assert response.content == b"test model archive"


def test_voice_audio_upload_endpoint_is_retired():
    _, headers = create_voice_user()
    response = client.post(
        "/voice/transcribe",
        headers=headers,
        files={"file": ("recording.wav", b"private audio", "audio/wav")},
    )

    assert response.status_code == 410
    assert "on your device" in response.json()["detail"].lower()


def test_voice_transcription_metric_records_no_audio_or_transcript():
    username, headers = create_voice_user()
    response = client.post(
        "/voice/transcription-metric",
        headers=headers,
        json={"audio_bytes": 32000, "transcription_time_ms": 1234.5},
    )

    assert response.status_code == 200
    assert response.json()["recorded"] is True
    with SessionLocal() as db:
        event = (
            db.query(AuditLog)
            .filter(AuditLog.event_type == "VOICE_CLIENT_TRANSCRIPTION_COMPLETED", AuditLog.actor_id == username)
            .order_by(AuditLog.id.desc())
            .first()
        )
    assert event is not None
    assert "sender device" in event.details.lower()
    assert "audio_bytes=32000" in event.details
    assert "transcription_time_ms=1234.500" in event.details
    assert "sensitive spoken phrase" not in event.details


def test_voice_transcription_metrics_are_bounded():
    _, headers = create_voice_user()
    response = client.post(
        "/voice/transcription-metric",
        headers=headers,
        json={"audio_bytes": 100_000_000, "transcription_time_ms": 1234.5},
    )

    assert response.status_code == 422


def test_voice_benchmark_is_admin_only():
    assert client.post("/admin/evaluation/voice-benchmark", files={"audio": ("sample.wav", b"x", "audio/wav")}).status_code == 401
    _, headers = create_voice_user()
    response = client.post(
        "/admin/evaluation/voice-benchmark",
        headers=headers,
        files={"audio": ("sample.wav", b"x", "audio/wav")},
    )
    assert response.status_code == 403
