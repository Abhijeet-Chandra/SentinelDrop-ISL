import csv
import io
import json
import tempfile
import os
import ipaddress
from pathlib import Path
from datetime import timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session, aliased

from app.database.connection import engine, get_db
from app.database.models import Message, User
from app.evaluation.image_metrics import ciphertext_preview_data_url, evaluate_image_bytes
from app.evaluation.image_benchmark import run_image_benchmark
from app.evaluation.audio_benchmark import MAX_AUDIO_BYTES, run_voice_benchmark as measure_voice_benchmark
from app.evaluation.performance import run_performance_benchmark
from app.evaluation.text_metrics import analyze_text
from app.evaluation.crypto_demos import analyze_hash, run_signature_demo
from app.evaluation.security_demos import run_security_demos
from app.monitor.sentinel import get_monitor_status
from app.monitor.pcap_analysis import analyze_pcap_file
from app.monitor.live_capture import live_capture_manager
from app.monitor.http_traffic import http_request_monitor
from app.services.audit_signature import get_audit_signing_public_key, verify_audit_signature
from app.services.auth import get_admin_user
from app.services.time_utils import to_utc_isoformat
from app.services.voice import MODEL_NAME, MODEL_PATH, _model_is_ready


router = APIRouter(prefix="/admin", tags=["Administrator"])
MAX_ANALYSIS_IMAGE_BYTES = 8 * 1024 * 1024
MAX_PCAP_UPLOAD_BYTES = 20 * 1024 * 1024


class TextAnalysisRequest(BaseModel):
    text: str


class CryptoDemoRequest(BaseModel):
    text: str


def _message_query(db: Session):
    sender = aliased(User)
    recipient = aliased(User)
    return (
        db.query(Message, sender.username, recipient.username)
        .outerjoin(sender, Message.sender_user_id == sender.id)
        .outerjoin(recipient, Message.recipient_user_id == recipient.id)
    )


def _message_record(row, include_ciphertext: bool = False) -> dict:
    message, sender, recipient = row
    ciphertext = message.ciphertext or ""
    signature_payload = (
        json.loads(message.signature_payload)
        if message.signature_payload
        else None
    )
    transfer_latency_ms = None
    if message.sent_at is not None and message.received_at is not None:
        sent = message.sent_at
        received = message.received_at
        if sent.tzinfo is None:
            sent = sent.replace(tzinfo=timezone.utc)
        if received.tzinfo is None:
            received = received.replace(tzinfo=timezone.utc)
        transfer_latency_ms = round((received - sent).total_seconds() * 1000, 3)
    item = {
        "id": message.id,
        "session_id": message.session_id,
        "sequence_number": message.sequence_number,
        "message_type": message.message_type,
        "sender": sender,
        "recipient": recipient,
        "sender_user_id": message.sender_user_id,
        "recipient_user_id": message.recipient_user_id,
        "filename": message.filename,
        "sent_at": to_utc_isoformat(message.sent_at),
        "received_at": to_utc_isoformat(message.received_at),
        "transfer_latency_ms": transfer_latency_ms,
        "ciphertext_sha256": message.ciphertext_hash,
        "ciphertext_bytes": len(ciphertext) // 2,
        "nonce": message.nonce,
        "authentication_tag": ciphertext[-32:] if len(ciphertext) >= 32 else None,
        "signature": message.signature,
        "signature_algorithm": message.signature_algorithm,
        "signature_payload": signature_payload,
        "signature_valid": verify_audit_signature(signature_payload, message.signature)
        if signature_payload
        else False,
    }
    if include_ciphertext:
        item["ciphertext"] = ciphertext
        is_image = (
            message.message_type.lower() in {"image", "png", "jpeg", "jpg"}
            or (message.filename or "").lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp"))
        )
        if is_image and ciphertext:
            item["ciphertext_image_preview"] = ciphertext_preview_data_url(
                bytes.fromhex(ciphertext)
            )
            item["ciphertext_image_preview_note"] = (
                "Preview of this transfer's actual ciphertext bytes (including its GCM tag), rendered as pixels. It is not a decryptable image file."
            )
    return item


@router.get("/message-logs")
def list_message_logs(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _admin=Depends(get_admin_user),
):
    rows = _message_query(db).order_by(Message.id.desc()).limit(limit).all()
    return {
        "count": len(rows),
        "signature_public_key": get_audit_signing_public_key(),
        "signature_note": (
            "Ed25519 server audit attestation over sender, recipient, time, nonce, "
            "and ciphertext hash; it is not a client-generated signature."
        ),
        "messages": [_message_record(row) for row in rows],
    }


@router.get("/message-logs/{message_id}")
def get_message_log(
    message_id: int,
    db: Session = Depends(get_db),
    _admin=Depends(get_admin_user),
):
    row = _message_query(db).filter(Message.id == message_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Message log not found.")
    return _message_record(row, include_ciphertext=True)


@router.post("/evaluation/image-metrics")
async def run_image_metrics(
    image: UploadFile = File(...),
    _admin=Depends(get_admin_user),
):
    """Analyze an admin-selected image in memory; the upload is not persisted."""
    image_bytes = await image.read(MAX_ANALYSIS_IMAGE_BYTES + 1)
    if len(image_bytes) > MAX_ANALYSIS_IMAGE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Choose an image no larger than 8 MB.",
        )
    try:
        return evaluate_image_bytes(image_bytes, image.filename or "uploaded image")
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        await image.close()


@router.post("/evaluation/image-benchmark")
async def run_admin_image_benchmark(
    image: UploadFile = File(...),
    rounds: int = Query(default=3, ge=1, le=5),
    _admin=Depends(get_admin_user),
):
    """Repeat bounded image metrics without retaining the uploaded image."""
    image_bytes = await image.read(MAX_ANALYSIS_IMAGE_BYTES + 1)
    try:
        if len(image_bytes) > MAX_ANALYSIS_IMAGE_BYTES:
            raise HTTPException(status_code=413, detail="Choose an image no larger than 8 MB.")
        return run_image_benchmark(image_bytes, image.filename or "uploaded image", rounds)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        await image.close()


@router.post("/evaluation/benchmark")
def run_admin_performance_benchmark(
    _admin=Depends(get_admin_user),
):
    """Run the bounded AES-GCM and copy-baseline benchmark for admins."""
    return run_performance_benchmark()


@router.get("/evaluation/benchmark.csv")
def export_admin_performance_benchmark_csv(
    _admin=Depends(get_admin_user),
):
    """Run a fresh bounded benchmark and export its measured rows as CSV."""
    benchmark = run_performance_benchmark()
    output = io.StringIO(newline="")
    columns = (
        "measured_at_utc",
        "measurement_scope",
        "payload_bytes",
        "rounds",
        "baseline_copy_ms_mean",
        "encryption_ms_mean",
        "encryption_ms_median",
        "encryption_ms_stdev",
        "decryption_ms_mean",
        "decryption_ms_median",
        "decryption_ms_stdev",
        "roundtrip_ms_mean",
        "roundtrip_ms_median",
        "roundtrip_ms_stdev",
        "encryption_mib_per_second",
        "decryption_mib_per_second",
        "roundtrip_mib_per_second",
        "crypto_overhead_bytes",
        "crypto_overhead_percent",
    )
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for result in benchmark["results"]:
        writer.writerow(
            {
                "measured_at_utc": benchmark["measured_at_utc"],
                "measurement_scope": benchmark["measurement_scope"],
                "payload_bytes": result["bytes"],
                "rounds": result["rounds"],
                "baseline_copy_ms_mean": result["baseline_copy_ms"],
                "encryption_ms_mean": result["encryption_ms"],
                "encryption_ms_median": result["encryption_ms_median"],
                "encryption_ms_stdev": result["encryption_ms_stdev"],
                "decryption_ms_mean": result["decryption_ms"],
                "decryption_ms_median": result["decryption_ms_median"],
                "decryption_ms_stdev": result["decryption_ms_stdev"],
                "roundtrip_ms_mean": result["total_crypto_ms"],
                "roundtrip_ms_median": result["total_crypto_ms_median"],
                "roundtrip_ms_stdev": result["total_crypto_ms_stdev"],
                "encryption_mib_per_second": result["encryption_mib_per_second"],
                "decryption_mib_per_second": result["decryption_mib_per_second"],
                "roundtrip_mib_per_second": result[
                    "crypto_roundtrip_mib_per_second"
                ],
                "crypto_overhead_bytes": result["crypto_overhead_bytes"],
                "crypto_overhead_percent": result["crypto_overhead_percent"],
            }
        )
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="sentineldrop-aes-benchmark.csv"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/evaluation/text-analysis")
def run_text_analysis(
    request: TextAnalysisRequest,
    _admin=Depends(get_admin_user),
):
    """Analyze admin-supplied sample text without storing the input."""
    try:
        return analyze_text(request.text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/evaluation/hash-analysis")
def run_hash_analysis(
    request: CryptoDemoRequest,
    _admin=Depends(get_admin_user),
):
    """Run bounded SHA-256 timing and reduced-digest teaching demos."""
    try:
        return analyze_hash(request.text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/evaluation/signature-demo")
def run_admin_signature_demo(
    request: CryptoDemoRequest,
    _admin=Depends(get_admin_user),
):
    """Create an ephemeral Ed25519 signature without exposing its private key."""
    try:
        return run_signature_demo(request.text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/evaluation/security-demos")
def run_admin_security_demos(_admin=Depends(get_admin_user)):
    """Run bounded, isolated security demonstrations without changing app data."""
    return run_security_demos()


@router.post("/evaluation/voice-benchmark")
async def run_admin_voice_benchmark(
    audio: UploadFile = File(...),
    rounds: int = Query(default=3, ge=1, le=3),
    _admin=Depends(get_admin_user),
):
    """Measure local Vosk transcription and transient transcript AES-GCM processing."""
    temporary_path = None
    try:
        if Path(audio.filename or "").suffix.lower() != ".wav":
            raise HTTPException(status_code=400, detail="Upload a WAV recording.")
        audio_bytes = await audio.read(MAX_AUDIO_BYTES + 1)
        if len(audio_bytes) > MAX_AUDIO_BYTES:
            raise HTTPException(status_code=413, detail="Audio uploads must be 20 MB or smaller.")
        with tempfile.NamedTemporaryFile(prefix="sentineldrop-voice-benchmark-", suffix=".wav", delete=False) as target:
            temporary_path = Path(target.name)
            target.write(audio_bytes)
        return measure_voice_benchmark(temporary_path, rounds)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        await audio.close()
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


@router.post("/evaluation/pcap-analysis")
def run_pcap_analysis(
    capture: UploadFile = File(...),
    _admin=Depends(get_admin_user),
):
    """Summarize a bounded uploaded PCAP/PCAPNG capture without retaining it."""
    temporary_path = None
    try:
        suffix = Path(capture.filename or "capture.pcap").suffix.lower()
        if suffix not in {".pcap", ".pcapng", ".cap"}:
            raise HTTPException(status_code=400, detail="Upload a .pcap or .pcapng capture.")
        with tempfile.NamedTemporaryFile(prefix="sentineldrop-pcap-", suffix=suffix, delete=False) as target:
            temporary_path = Path(target.name)
            total = 0
            while True:
                chunk = capture.file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_PCAP_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Capture must be 20 MB or smaller.")
                target.write(chunk)
        try:
            return analyze_pcap_file(temporary_path)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        capture.file.close()
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


@router.get("/monitor/status")
def get_admin_monitor_status(
    _admin=Depends(get_admin_user),
):
    """Return application security events and optional PyShark availability."""
    return get_monitor_status()


@router.get("/monitor/live/interfaces")
def get_live_capture_interfaces(_admin=Depends(get_admin_user)):
    """List interfaces visible to local TShark without starting a capture."""
    try:
        return {"interfaces": live_capture_manager.interfaces()}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


class LiveCaptureRequest(BaseModel):
    interface: str
    duration_seconds: int = 10
    packet_limit: int = 1000


@router.post("/monitor/live/start")
def start_live_capture(request: LiveCaptureRequest, _admin=Depends(get_admin_user)):
    try:
        return live_capture_manager.start(
            request.interface,
            request.duration_seconds,
            request.packet_limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        status_code = 409 if "already running" in str(exc) else 503
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.get("/monitor/live/status")
def get_live_capture_status(_admin=Depends(get_admin_user)):
    return live_capture_manager.status()


@router.post("/monitor/live/stop")
def stop_live_capture(_admin=Depends(get_admin_user)):
    return live_capture_manager.stop()


class HttpMonitorRequest(BaseModel):
    duration_seconds: int = 30
    request_limit: int = 1000


@router.post("/monitor/http/start")
def start_http_monitor(request: HttpMonitorRequest, _admin=Depends(get_admin_user)):
    try:
        return http_request_monitor.start(request.duration_seconds, request.request_limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/monitor/http/status")
def get_http_monitor_status(_admin=Depends(get_admin_user)):
    return http_request_monitor.status()


@router.post("/monitor/http/stop")
def stop_http_monitor(_admin=Depends(get_admin_user)):
    return http_request_monitor.stop()


@router.get("/readiness")
def get_admin_readiness(request: Request, _admin=Depends(get_admin_user)):
    """Return deployment configuration signals without returning secret values."""
    admin_configured = bool(
        os.environ.get("SENTINEL_ADMIN_USERNAME", "").strip()
        and os.environ.get("SENTINEL_ADMIN_PASSWORD", "")
    )
    allowed_origins = [
        item.strip()
        for item in os.environ.get("SENTINEL_ALLOWED_ORIGINS", "").split(",")
        if item.strip()
    ]
    normalized_origins = set()
    for candidate in allowed_origins:
        parsed = urlsplit(candidate.strip().strip("\"'"))
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            normalized_origins.add(f"{parsed.scheme}://{parsed.netloc}")
    browser_origin = request.headers.get("origin")
    origin_allowed = None
    if browser_origin:
        parsed_origin = urlsplit(browser_origin)
        host = (parsed_origin.hostname or "").lower()
        origin_allowed = (
            parsed_origin.scheme in {"http", "https"}
            and f"{parsed_origin.scheme}://{parsed_origin.netloc}" in normalized_origins
        )
        if host in {"localhost", "127.0.0.1", "::1"}:
            try:
                origin_allowed = origin_allowed or parsed_origin.port in {5173, 5174}
            except ValueError:
                origin_allowed = False
        else:
            try:
                address = ipaddress.ip_address(host)
                origin_allowed = origin_allowed or (
                    address.version == 4
                    and (
                        address in ipaddress.ip_network("10.0.0.0/8")
                        or address in ipaddress.ip_network("192.168.0.0/16")
                        or address in ipaddress.ip_network("172.16.0.0/12")
                        or address in ipaddress.ip_network("169.254.0.0/16")
                    )
                )
            except ValueError:
                pass
    data_dir_raw = os.environ.get("SENTINEL_DATA_DIR", "").strip()
    data_dir = Path(data_dir_raw).expanduser() if data_dir_raw else None
    if data_dir is not None and not data_dir.is_absolute():
        data_dir = Path.cwd() / data_dir
    sqlite_database = engine.url.get_backend_name() == "sqlite"
    database_path = None
    if sqlite_database and engine.url.database:
        database_path = Path(engine.url.database).expanduser()
        if not database_path.is_absolute():
            database_path = Path.cwd() / database_path
    inside_data_dir = False
    if database_path is not None and data_dir is not None:
        try:
            database_path.resolve().relative_to(data_dir.resolve())
            inside_data_dir = True
        except ValueError:
            inside_data_dir = False
    data_dir_exists = bool(data_dir and data_dir.is_dir())
    writable = bool(data_dir_exists and os.access(data_dir, os.W_OK))
    model_present = _model_is_ready(MODEL_PATH)
    checks = {
        "admin_credentials_configured": {
            "ready": admin_configured,
            "detail": "Both administrator bootstrap variables are set." if admin_configured else "Set both admin bootstrap variables in the backend environment.",
        },
        "cors_origins_configured": {
            "ready": bool(allowed_origins),
            "configured_origin_count": len(allowed_origins),
            "detail": "At least one deployed frontend origin is configured." if allowed_origins else "No deployed frontend origin is configured.",
        },
        "request_origin_allowed": {
            "ready": origin_allowed,
            "advisory": origin_allowed is None,
            "detail": "The calling browser origin is allowed by the configured/default CORS rules." if origin_allowed else ("The calling browser origin is not allowed; add the exact Vercel origin to SENTINEL_ALLOWED_ORIGINS." if origin_allowed is False else "No browser Origin header was present, so per-origin CORS could not be checked."),
        },
        "https_request": {
            "ready": request.url.scheme == "https",
            "detail": "This readiness request used HTTPS." if request.url.scheme == "https" else "This request used HTTP; use the HTTPS deployment URL for browser camera and microphone access.",
        },
        "database_storage": {
            "ready": (not sqlite_database) or (inside_data_dir and data_dir_exists and writable),
            "sqlite": sqlite_database,
            "data_directory_configured": data_dir is not None,
            "data_directory_exists": data_dir_exists,
            "data_directory_writable": writable,
            "database_within_data_directory": inside_data_dir,
            "detail": "Managed database selected." if not sqlite_database else ("SQLite database is under the configured writable data directory." if inside_data_dir and data_dir_exists and writable else "SQLite persistence is not confirmed; configure a mounted writable data directory and keep the database inside it."),
        },
        "vosk_model_present": {
            "ready": model_present,
            "detail": f"Vosk model {MODEL_NAME} is present." if model_present else f"Vosk model {MODEL_NAME} is not provisioned; offline transcription will need setup.",
        },
        "secret_rotation_review": {
            "ready": None,
            "advisory": True,
            "detail": "Rotation cadence for backend credentials cannot be verified automatically; review and rotate secrets through the hosting provider.",
        },
    }
    return {
        "ready": all(check["ready"] for check in checks.values() if not check.get("advisory")),
        "checks": checks,
        "note": "Readiness reports configuration signals only. It cannot confirm provider billing, disk retention after redeploy, proxy TLS configuration, or actual cross-device operation.",
    }
import json
