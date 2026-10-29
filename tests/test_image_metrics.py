import numpy as np
import cv2

from app.evaluation.image_metrics import _ciphertext_view, evaluate


def test_ciphertext_view_preserves_each_ciphertext_body_byte():
    ciphertext_body = bytes(range(16))
    view = _ciphertext_view(ciphertext_body, (4, 4))
    assert view.shape == (4, 4)
    assert view.tobytes() == ciphertext_body


def test_image_metrics_on_synthetic_image(tmp_path):
    image_path = tmp_path / "plain.png"
    pixels = np.tile(np.arange(256, dtype=np.uint8), (128, 2))[:128, :256]
    cv2.imwrite(str(image_path), pixels)

    result = evaluate(image_path)

    assert result["entropy_cipher"] > 7.5
    assert abs(result["npcr_percent"] - (100 / pixels.size)) < 1e-6
    assert abs(result["uaci_percent"] - (100 / (255 * pixels.size))) < 1e-6
    assert abs(result["correlation_cipher"]) < abs(result["correlation_plain"]) or abs(
        result["correlation_cipher"]
    ) < 0.2
    assert result["mse_cipher"] is None
    assert result["psnr_cipher_db"] is None
    assert result["mse_decrypted"] == 0
    assert result["psnr_decrypted_db"] == "inf"
    assert "same ephemeral key and nonce" in result["metric_note"]
from PIL import Image

from app.evaluation.image_metrics import _decode_and_bound


def test_transparent_palette_pixels_are_composited_on_white_before_metrics():
    image = Image.new("P", (2, 1))
    image.putpalette([0, 0, 0, 0, 0, 0] + [0, 0, 0] * 254)
    image.putdata([0, 1])
    image.info["transparency"] = 0

    pixels, _ = _decode_and_bound(image)

    assert pixels.tolist() == [[255, 0]]
