from pathlib import Path
import tarfile

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.services.audit_log import record_event
from app.services.auth import get_current_user
from app.services.voice import MODEL_NAME, prepare_browser_model_archive


router = APIRouter(
    prefix="/voice",
    tags=["Voice"],
)
MAX_METRIC_AUDIO_BYTES = 20 * 1024 * 1024


class VoiceTranscriptionMetric(BaseModel):
    audio_bytes: int = Field(ge=0, le=MAX_METRIC_AUDIO_BYTES)
    transcription_time_ms: float = Field(ge=0, le=600_000)


@router.get("/model")
def download_browser_voice_model(current_user=Depends(get_current_user)):
    """Download the speech model; audio recognition itself stays in the browser."""
    try:
        archive_path = prepare_browser_model_archive()
    except (OSError, RuntimeError, tarfile.TarError) as exc:
        raise HTTPException(
            status_code=503,
            detail="The offline speech model is not available yet. Check backend storage and internet access, then retry.",
        ) from exc

    return FileResponse(
        Path(archive_path),
        media_type="application/gzip",
        filename=f"{MODEL_NAME}.tar.gz",
        headers={"Cache-Control": "private, max-age=31536000, immutable"},
    )


@router.post("/transcription-metric")
def record_client_transcription_metric(
    metric: VoiceTranscriptionMetric,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Store timing metadata only; neither audio nor transcript is accepted."""
    record_event(
        db,
        event_type="VOICE_CLIENT_TRANSCRIPTION_COMPLETED",
        details=(
            "Offline transcription completed on sender device; "
            f"audio_bytes={metric.audio_bytes}; "
            f"transcription_time_ms={metric.transcription_time_ms:.3f}. "
            "Audio and transcript content were not uploaded or stored."
        ),
        actor_id=current_user.username,
        status="success",
    )
    return {"recorded": True}


@router.post("/transcribe")
def retired_server_transcription_endpoint():
    """Prevent legacy clients from uploading audio to the backend."""
    raise HTTPException(
        status_code=410,
        detail="Server-side audio transcription has been retired. Reload the app to transcribe on your device.",
    )
