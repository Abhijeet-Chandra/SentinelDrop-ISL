import csv
import io


def test_benchmark_csv_is_admin_only_and_has_measurement_provenance(client):
    assert client.get("/admin/evaluation/benchmark.csv").status_code == 401

    from tests.helpers import create_admin_headers

    headers = create_admin_headers(client)
    response = client.get("/admin/evaluation/benchmark.csv", headers=headers)

    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "attachment" in response.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) == 4
    assert {
        "measured_at_utc",
        "payload_bytes",
        "rounds",
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
        "baseline_copy_ms_mean",
    }.issubset(rows[0])
    assert all(row["measured_at_utc"].endswith("Z") for row in rows)


def test_benchmark_csv_has_one_distinct_row_per_payload_size(client):
    from tests.helpers import create_admin_headers

    headers = create_admin_headers(client)
    response = client.get("/admin/evaluation/benchmark.csv", headers=headers)
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert all(row["measurement_scope"].startswith("backend AES-GCM") for row in rows)
    assert len({row["payload_bytes"] for row in rows}) == len(rows)
