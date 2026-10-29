from __future__ import annotations

import base64
import io
import os
import time
from pathlib import Path

import cv2
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, ImageOps, UnidentifiedImageError


MAX_SOURCE_PIXELS = 20_000_000
MAX_ANALYSIS_SIDE = 1024


def entropy(channel: np.ndarray) -> float:
    hist = np.bincount(channel.astype(np.uint8).ravel(), minlength=256).astype(float)
    probabilities = hist[hist > 0] / channel.size
    return float(-np.sum(probabilities * np.log2(probabilities)))


def adjacent_correlation(channel: np.ndarray, direction: str = "horizontal") -> float:
    pixels = channel
    if direction == "horizontal":
        x, y = pixels[:, :-1].ravel(), pixels[:, 1:].ravel()
    elif direction == "vertical":
        x, y = pixels[:-1, :].ravel(), pixels[1:, :].ravel()
    else:
        x, y = pixels[:-1, :-1].ravel(), pixels[1:, 1:].ravel()
    if x.size < 2:
        return 0.0
    # A deterministic grid sample bounds temporary allocations even on large inputs.
    stride = max(1, int(np.ceil(np.sqrt(x.size / 200_000))))
    x = x[::stride].astype(np.float32, copy=False)
    y = y[::stride].astype(np.float32, copy=False)
    if np.std(x) == 0 or np.std(y) == 0:
        return 0.0
    result = float(np.corrcoef(x, y)[0, 1])
    return result if np.isfinite(result) else 0.0


def mse(plain: np.ndarray, other: np.ndarray) -> float:
    if plain.shape != other.shape:
        raise ValueError("Images must have identical dimensions for MSE.")
    difference = plain.astype(np.int16) - other.astype(np.int16)
    return float(np.mean(difference.astype(np.float32) ** 2, dtype=np.float64))


def psnr(error: float, peak: float = 255.0) -> float:
    return float("inf") if error == 0 else float(10 * np.log10((peak**2) / error))


def npcr(first: np.ndarray, second: np.ndarray) -> float:
    if first.shape != second.shape:
        raise ValueError("Ciphertext views must have identical dimensions for NPCR.")
    return float(np.mean(first != second) * 100.0)


def uaci(first: np.ndarray, second: np.ndarray) -> float:
    if first.shape != second.shape:
        raise ValueError("Ciphertext views must have identical dimensions for UACI.")
    difference = np.abs(first.astype(np.int16) - second.astype(np.int16))
    return float(np.mean(difference, dtype=np.float64) / 255.0 * 100.0)


def _ciphertext_view(ciphertext_body: bytes, shape: tuple[int, int]) -> np.ndarray:
    """Map GCM ciphertext-body bytes one-to-one to grayscale pixels."""
    height, width = shape
    data = np.frombuffer(ciphertext_body, dtype=np.uint8)
    if data.size != height * width:
        raise ValueError("Ciphertext body must have one byte per analyzed pixel.")
    return np.ascontiguousarray(data.reshape(height, width))


def _png_data_url(image: np.ndarray) -> str:
    stream = io.BytesIO()
    preview = image.astype(np.uint8)
    largest_side = max(preview.shape)
    if largest_side > 700:
        scale = 700 / largest_side
        preview = cv2.resize(
            preview,
            (max(1, round(preview.shape[1] * scale)), max(1, round(preview.shape[0] * scale))),
            interpolation=cv2.INTER_AREA,
        )
    Image.fromarray(preview).save(stream, format="PNG")
    return "data:image/png;base64," + base64.b64encode(stream.getvalue()).decode("ascii")


def ciphertext_preview_data_url(ciphertext: bytes) -> str | None:
    """Render the actual stored ciphertext bytes as a compact grayscale preview."""
    if not ciphertext:
        return None
    width = min(700, max(1, int(np.ceil(np.sqrt(len(ciphertext))))))
    rows = int(np.ceil(len(ciphertext) / width))
    values = np.frombuffer(ciphertext, dtype=np.uint8)
    pixels = np.pad(values, (0, rows * width - values.size)).reshape(rows, width)
    return _png_data_url(pixels)


def evaluate(image_path: Path) -> dict:
    try:
        with Image.open(image_path) as source:
            image, source_shape = _decode_and_bound(source)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError(f"Unable to read image: {image_path}") from exc
    return evaluate_array(image, str(image_path), source_shape)


def _decode_and_bound(source: Image.Image) -> tuple[np.ndarray, list[int]]:
    width, height = source.size
    if width < 1 or height < 1 or width * height > MAX_SOURCE_PIXELS:
        raise ValueError("Images must be no larger than 20 megapixels for analysis.")
    oriented = ImageOps.exif_transpose(source)
    source_width, source_height = oriented.size
    if "A" in oriented.getbands() or "transparency" in oriented.info:
        rgba = oriented.convert("RGBA")
        rgba.thumbnail(
            (MAX_ANALYSIS_SIDE, MAX_ANALYSIS_SIDE),
            Image.Resampling.BOX,
        )
        background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        grayscale = Image.alpha_composite(background, rgba).convert("L")
    else:
        grayscale = oriented.convert("L")
        grayscale.thumbnail(
            (MAX_ANALYSIS_SIDE, MAX_ANALYSIS_SIDE),
            Image.Resampling.BOX,
        )
    return np.asarray(grayscale, dtype=np.uint8), [source_height, source_width]


def evaluate_image_bytes(image_bytes: bytes, image_name: str) -> dict:
    """Evaluate an uploaded image in memory; source and ciphertext are not persisted."""
    if not image_bytes:
        raise ValueError("Choose a non-empty image file.")
    try:
        with Image.open(io.BytesIO(image_bytes)) as source:
            image, source_shape = _decode_and_bound(source)
    except ValueError:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as exc:
        raise ValueError("The selected file is not a supported image.") from exc
    return evaluate_array(image, image_name, source_shape)


def evaluate_array(
    image: np.ndarray,
    image_name: str = "image",
    source_shape: list[int] | None = None,
) -> dict:
    """Calculate image statistics over an AES-GCM ciphertext byte visualization."""
    if image.ndim != 2 or image.size == 0:
        raise ValueError("Image analysis requires a non-empty grayscale image.")

    plain = np.ascontiguousarray(image.astype(np.uint8))
    key = AESGCM.generate_key(bit_length=256)
    aad = b"sentineldrop-image-metrics"

    start = time.perf_counter()
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, plain.tobytes(), aad)
    encryption_ms = (time.perf_counter() - start) * 1000
    # GCM adds a 16-byte tag after the ciphertext body. AES-GCM preserves the
    # plaintext byte length, so the body maps exactly to the grayscale pixels.
    encrypted_body = encrypted[:-16]
    encrypted_view = _ciphertext_view(encrypted_body, plain.shape)

    start = time.perf_counter()
    recovered_bytes = AESGCM(key).decrypt(nonce, encrypted, aad)
    decryption_ms = (time.perf_counter() - start) * 1000
    recovered = np.frombuffer(recovered_bytes, dtype=np.uint8).reshape(plain.shape)

    changed = plain.copy()
    changed.flat[0] ^= np.uint8(1)
    # Each encryption uses a fresh nonce. Metrics therefore describe the complete
    # randomized AEAD output, not AES's block-level avalanche in isolation.
    # This is an isolated educational differential experiment using a fresh,
    # throwaway key. Reusing its nonce is necessary to avoid random nonce
    # variation dominating the comparison; these values are never used by the
    # transfer or production session code.
    changed_encrypted = AESGCM(key).encrypt(nonce, changed.tobytes(), aad)
    changed_view = _ciphertext_view(changed_encrypted[:-16], plain.shape)

    recovered_mse = mse(plain, recovered)
    recovered_psnr = psnr(recovered_mse)

    return {
        "image": image_name,
        "shape": list(plain.shape),
        "source_shape": source_shape or list(plain.shape),
        "downsampled_for_analysis": source_shape is not None and source_shape != list(plain.shape),
        "source_image_data_url": _png_data_url(plain),
        "ciphertext_image_data_url": _png_data_url(encrypted_view),
        "ciphertext_visualization_note": "AES-GCM ciphertext-body bytes (the 16-byte authentication tag is excluded from this shape-preserving pixel view) displayed as grayscale pixels. The full ciphertext and tag remain intact in the transfer record. This visualization is not a decryptable image file.",
        "ciphertext_bytes": len(encrypted),
        "encryption_time_ms": round(encryption_ms, 4),
        "decryption_time_ms": round(decryption_ms, 4),
        "total_crypto_time_ms": round(encryption_ms + decryption_ms, 4),
        "entropy_plain": round(entropy(plain), 6),
        "entropy_cipher": round(entropy(np.frombuffer(encrypted_body, dtype=np.uint8)), 6),
        "npcr_percent": round(npcr(encrypted_view, changed_view), 6),
        "uaci_percent": round(uaci(encrypted_view, changed_view), 6),
        "correlation_plain_h": round(adjacent_correlation(plain, "horizontal"), 6),
        "correlation_plain_v": round(adjacent_correlation(plain, "vertical"), 6),
        "correlation_plain_d": round(adjacent_correlation(plain, "diagonal"), 6),
        "correlation_cipher_h": round(adjacent_correlation(encrypted_view, "horizontal"), 6),
        "correlation_cipher_v": round(adjacent_correlation(encrypted_view, "vertical"), 6),
        "correlation_cipher_d": round(adjacent_correlation(encrypted_view, "diagonal"), 6),
        "mse_cipher": None,
        "mse": None,
        "mse_decrypted": round(recovered_mse, 6),
        "psnr_cipher_db": None,
        "psnr_db": None,
        "psnr_decrypted_db": round(recovered_psnr, 6) if np.isfinite(recovered_psnr) else "inf",
        "correlation_plain": round(adjacent_correlation(plain, "horizontal"), 6),
        "correlation_cipher": round(adjacent_correlation(encrypted_view, "horizontal"), 6),
        "metric_note": "NPCR and UACI compare ciphertext bodies produced from a one-bit plaintext change with the same ephemeral key and nonce in this isolated experiment. AES-GCM uses counter mode, so under this controlled setup the changed plaintext bit changes only the corresponding ciphertext bit; classic image-cipher reference values near 100% NPCR and 33% UACI do not apply. The throwaway key is discarded and the nonce is never reused in production. Ciphertext-vs-plaintext MSE/PSNR are omitted because encrypted bytes are not a meaningful image-quality representation.",
    }
