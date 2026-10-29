"""Small, bounded repeated image-evaluation runs for the Admin Dashboard."""

from __future__ import annotations

import statistics
import time
import io

import cv2
import numpy as np
from PIL import Image

from app.evaluation.image_metrics import _decode_and_bound, evaluate_array, evaluate_image_bytes


IMAGE_SWEEP_LONG_SIDES = (64, 128, 256, 512, 1024)


def _run_size_sweep(image_bytes: bytes, image_name: str, rounds: int) -> list[dict]:
    try:
        with Image.open(io.BytesIO(image_bytes)) as source:
            base, _ = _decode_and_bound(source)
    except (OSError, Image.DecompressionBombError) as exc:
        raise ValueError("The selected file is not a supported image.") from exc

    source_height, source_width = base.shape
    source_long_side = max(source_height, source_width)
    output = []
    timing_names = ("encryption_time_ms", "decryption_time_ms", "total_crypto_time_ms")
    metric_names = (
        "entropy_plain", "entropy_cipher", "npcr_percent", "uaci_percent",
        "correlation_cipher_h", "correlation_cipher_v", "correlation_cipher_d",
    )
    for long_side in IMAGE_SWEEP_LONG_SIDES:
        scale = long_side / source_long_side
        height = max(1, round(source_height * scale))
        width = max(1, round(source_width * scale))
        interpolation = cv2.INTER_AREA if scale < 1 else cv2.INTER_LINEAR
        resized = cv2.resize(base, (width, height), interpolation=interpolation)
        runs = [evaluate_array(np.asarray(resized, dtype=np.uint8), image_name) for _ in range(rounds)]
        row = {
            "target_long_side": long_side,
            "shape": [height, width],
            "pixels": height * width,
            "rounds": rounds,
        }
        for name in timing_names:
            values = [run[name] for run in runs]
            row[f"{name.removesuffix('_time_ms')}_ms_mean"] = round(statistics.mean(values), 4)
            row[f"{name.removesuffix('_time_ms')}_ms_median"] = round(statistics.median(values), 4)
        for name in metric_names:
            row[name] = round(statistics.mean(run[name] for run in runs), 6)
        row["mse_decrypted"] = max(run["mse_decrypted"] for run in runs)
        row["psnr_decrypted_db"] = runs[0]["psnr_decrypted_db"]
        row["encryption_mib_per_second"] = round(
            (row["pixels"] / (row["encryption_ms_mean"] / 1000)) / (1024 * 1024), 4
        ) if row["encryption_ms_mean"] else 0
        row["decryption_mib_per_second"] = round(
            (row["pixels"] / (row["decryption_ms_mean"] / 1000)) / (1024 * 1024), 4
        ) if row["decryption_ms_mean"] else 0
        output.append(row)
    return output


def run_image_benchmark(image_bytes: bytes, image_name: str, rounds: int = 3) -> dict:
    if not 1 <= rounds <= 5:
        raise ValueError("Choose between 1 and 5 benchmark rounds.")
    if not image_bytes:
        raise ValueError("Choose a non-empty image file.")

    runs = []
    for run_number in range(1, rounds + 1):
        started = time.perf_counter()
        result = evaluate_image_bytes(image_bytes, image_name)
        wall_ms = (time.perf_counter() - started) * 1000
        runs.append(
            {
                "run": run_number,
                "image": result["image"],
                "source_shape": result["source_shape"],
                "shape": result["shape"],
                "downsampled_for_analysis": result["downsampled_for_analysis"],
                "encryption_ms": result["encryption_time_ms"],
                "decryption_ms": result["decryption_time_ms"],
                "total_crypto_ms": result["total_crypto_time_ms"],
                "end_to_end_analysis_ms": round(wall_ms, 4),
                "ciphertext_bytes": result["ciphertext_bytes"],
                "entropy_plain": result["entropy_plain"],
                "entropy_cipher": result["entropy_cipher"],
                "npcr_percent": result["npcr_percent"],
                "uaci_percent": result["uaci_percent"],
                "correlation_cipher_h": result["correlation_cipher_h"],
                "correlation_cipher_v": result["correlation_cipher_v"],
                "correlation_cipher_d": result["correlation_cipher_d"],
                "mse_decrypted": result["mse_decrypted"],
                "psnr_decrypted_db": result["psnr_decrypted_db"],
            }
        )

    timing_fields = (
        "encryption_ms",
        "decryption_ms",
        "total_crypto_ms",
        "end_to_end_analysis_ms",
    )
    summary = {
        f"mean_{field}": round(statistics.mean(row[field] for row in runs), 4)
        for field in timing_fields
    }
    summary.update(
        {
            f"median_{field}": round(statistics.median(row[field] for row in runs), 4)
            for field in timing_fields
        }
    )
    first = runs[0]
    summary.update(
        {
            "image": first["image"],
            "source_shape": first["source_shape"],
            "shape": first["shape"],
            "downsampled_for_analysis": first["downsampled_for_analysis"],
        }
    )
    size_sweep = _run_size_sweep(image_bytes, image_name, rounds)
    return {
        "rounds": rounds,
        "measurements": len(runs),
        "runs": runs,
        "summary": summary,
        "size_sweep": size_sweep,
        "note": (
            "Each run uses fresh throwaway AES-GCM key/nonce material. NPCR/UACI "
            "are controlled one-bit differential measurements; because AES-GCM "
            "uses counter mode, they are not expected to match classic image-cipher "
            "reference values. The size sweep scales this selected image to five "
            "bounded analysis sizes and repeats each size for the requested rounds. "
            "End-to-end analysis time includes image decode and metric computation; "
            "crypto times cover only AES-GCM operations."
        ),
    }
