import io

from PIL import Image


def _png_bytes():
    output = io.BytesIO()
    Image.new("RGB", (8, 8), (120, 60, 30)).save(output, format="PNG")
    return output.getvalue()


def test_image_benchmark_returns_repeatable_metric_series(client):
    from tests.helpers import create_admin_headers

    response = client.post(
        "/admin/evaluation/image-benchmark?rounds=2",
        headers=create_admin_headers(client),
        files={"image": ("sample.png", _png_bytes(), "image/png")},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["rounds"] == 2
    assert result["measurements"] == 2
    assert len(result["runs"]) == 2
    assert {row["run"] for row in result["runs"]} == {1, 2}
    assert all(row["encryption_ms"] >= 0 for row in result["runs"])
    assert result["summary"]["mean_encryption_ms"] >= 0
    assert "controlled one-bit differential" in result["note"]
    sweep = result["size_sweep"]
    assert len(sweep) == 5
    assert [row["pixels"] for row in sweep] == sorted(row["pixels"] for row in sweep)
    assert all(row["encryption_ms_mean"] >= 0 and row["decryption_ms_mean"] >= 0 for row in sweep)
    assert all("entropy_cipher" in row and "npcr_percent" in row and "uaci_percent" in row for row in sweep)


def test_image_benchmark_rejects_non_admin_and_unbounded_rounds(client):
    unauthenticated = client.post(
        "/admin/evaluation/image-benchmark?rounds=2",
        files={"image": ("sample.png", _png_bytes(), "image/png")},
    )
    assert unauthenticated.status_code == 401

    from tests.helpers import create_admin_headers

    response = client.post(
        "/admin/evaluation/image-benchmark?rounds=100",
        headers=create_admin_headers(client),
        files={"image": ("sample.png", _png_bytes(), "image/png")},
    )
    assert response.status_code == 422
