"""Hosted request monitoring reports bounded aggregates without packet claims."""

from tests.helpers import create_admin_headers


def test_http_monitor_counts_requests_without_retaining_paths_or_payloads():
    from app.monitor.http_traffic import HttpRequestMonitor

    clock = [100.0]
    monitor = HttpRequestMonitor(clock=lambda: clock[0])
    monitor.start(duration_seconds=5, request_limit=3)
    monitor.record(
        path="/messages/send/private-id?token=secret",
        status_code=201,
        request_bytes=42,
        response_bytes=9,
    )
    clock[0] += 1
    monitor.record(path="/health", status_code=200, request_bytes=0, response_bytes=12)
    monitor.record(path="/admin/monitor/http/status", status_code=200, request_bytes=0, response_bytes=99)
    monitor.record(path="/device/identity", status_code=401, request_bytes=0, response_bytes=5)

    result = monitor.status()
    assert result["source"] == "application_http"
    assert result["request_count"] == 2
    assert result["request_bytes"] == 42
    assert result["response_bytes"] == 14
    assert result["status_counts"] == {"2xx": 1, "4xx": 1}
    assert result["peak_requests_per_second"] == 1
    assert result["requests_per_second"] == [1, 1]
    assert "private-id" not in str(result)
    assert "secret" not in str(result)


def test_http_monitor_expires_and_enforces_bounds():
    from app.monitor.http_traffic import HttpRequestMonitor

    clock = [10.0]
    monitor = HttpRequestMonitor(clock=lambda: clock[0])
    for duration, limit in [(0, 1), (31, 1), (1, 0), (1, 1001)]:
        try:
            monitor.start(duration_seconds=duration, request_limit=limit)
        except ValueError:
            pass
        else:
            raise AssertionError("Unbounded HTTP monitoring was accepted")

    monitor.start(duration_seconds=2, request_limit=1)
    monitor.record(path="/auth/login", status_code=200, request_bytes=1, response_bytes=2)
    assert monitor.status()["status"] == "complete"
    clock[0] += 3
    monitor.record(path="/auth/login", status_code=200, request_bytes=1, response_bytes=2)
    assert monitor.status()["request_count"] == 1
    assert monitor.status()["requests_per_second"] == [1, 0]

    monitor.start(duration_seconds=2, request_limit=3)
    clock[0] += 3
    assert monitor.status()["status"] == "complete"


def test_http_monitor_routes_are_admin_only_and_count_real_api_requests(client, auth_headers):
    assert client.get("/admin/monitor/http/status").status_code == 401
    assert client.get("/admin/monitor/http/status", headers=auth_headers).status_code == 403
    assert client.post("/admin/monitor/http/start", headers=auth_headers, json={}).status_code == 403

    headers = create_admin_headers(client)
    invalid = client.post(
        "/admin/monitor/http/start",
        headers=headers,
        json={"duration_seconds": 31, "request_limit": 1000},
    )
    assert invalid.status_code == 400
    started = client.post(
        "/admin/monitor/http/start",
        headers=headers,
        json={"duration_seconds": 30, "request_limit": 1000},
    )
    assert started.status_code == 200
    try:
        client.get("/health")
        client.get("/device/identity")
        status = client.get("/admin/monitor/http/status", headers=headers)
        assert status.status_code == 200
        assert status.json()["request_count"] == 1
        assert status.json()["status_counts"] == {"2xx": 1}
        assert status.json()["response_bytes"] > 0
    finally:
        stopped = client.post("/admin/monitor/http/stop", headers=headers)
        assert stopped.status_code == 200
        assert stopped.json()["status"] == "stopped"
