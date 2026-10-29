import uuid

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_crypto_demo_endpoints_require_admin():
    response = client.post("/admin/evaluation/hash-analysis", json={"text": "sample"})
    assert response.status_code == 401
    pcap = client.post("/admin/evaluation/pcap-analysis", files={"capture": ("sample.pcap", b"not-a-pcap")})
    assert pcap.status_code == 401
    demos = client.post("/admin/evaluation/security-demos")
    assert demos.status_code == 401


def test_normal_user_cannot_run_crypto_demos():
    username = f"crypto_{uuid.uuid4().hex[:10]}"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"username": username, "password": password}).status_code == 200
    login = client.post("/auth/login", json={"username": username, "password": password})
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    for path in ("hash-analysis", "signature-demo", "security-demos"):
        response = client.post(
            f"/admin/evaluation/{path}",
            headers=headers,
            json={"text": "sample"} if path != "security-demos" else None,
        )
        assert response.status_code == 403


def test_security_demos_report_seven_bounded_isolated_scenarios():
    from tests.helpers import create_admin_headers

    response = client.post("/admin/evaluation/security-demos", headers=create_admin_headers(client))
    assert response.status_code == 200
    body = response.json()
    assert body["scope"] == "isolated in-memory demonstration"
    assert len(body["scenarios"]) == 7
    assert all(scenario["passed"] for scenario in body["scenarios"])
    assert all(scenario["setup"] and scenario["expected"] and scenario["observed"] and scenario["limitations"] for scenario in body["scenarios"])
