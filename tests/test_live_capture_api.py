import threading
import time

from app.monitor.live_capture import LiveCaptureManager


def test_live_capture_summary_is_aggregated_without_endpoint_addresses():
    manager = LiveCaptureManager()
    manager._record_packet(
        {"length": 100, "sniff_timestamp": "10.0", "layers": [type("L", (), {"layer_name": "ip"})()]}
    )
    manager._record_packet(
        {"length": 200, "sniff_timestamp": "10.4", "layers": [type("L", (), {"layer_name": "tcp"})()]}
    )
    manager._state.update(status="complete", interface="Wi-Fi", duration_seconds=0.5)

    result = manager.status()
    assert result["packet_count"] == 2
    assert result["bytes_total"] == 300
    assert result["protocol_counts"] == {"IP": 1, "TCP": 1}
    assert result["unique_connections"] is None
    assert "10.0.0.1" not in str(result)
    assert result["status"] == "complete"


def test_live_capture_rejects_unbounded_limits():
    manager = LiveCaptureManager()
    try:
        manager.start("Wi-Fi", duration_seconds=31, packet_limit=100)
    except ValueError as exc:
        assert "30 seconds" in str(exc)
    else:
        raise AssertionError("Capture duration must be capped")


def test_live_capture_worker_stops_cleanly_and_caps_summary():
    class FakeCapture:
        def __init__(self, **_kwargs):
            self.closed = threading.Event()

        def apply_on_packets(self, callback, timeout=None, packet_count=None):
            callback({"length": 64, "timestamp": 10, "protocol": "TCP"})
            self.closed.wait(timeout=timeout)

        def close(self):
            self.closed.set()

    manager = LiveCaptureManager(
        capture_factory=FakeCapture,
        interface_provider=lambda: ["loopback"],
    )
    initial = manager.start("loopback", duration_seconds=10, packet_limit=5)
    assert initial["status"] == "running"
    time.sleep(0.01)
    result = manager.stop()
    assert result["status"] == "stopped"
    assert result["packet_count"] == 1
    assert result["bytes_total"] == 64
    assert result["protocol_counts"] == {"TCP": 1}
    assert result["unique_connections"] is None


def test_live_capture_endpoints_require_admin(client, auth_headers):
    assert client.get("/admin/monitor/live/interfaces").status_code == 401
    assert client.get("/admin/monitor/live/status", headers=auth_headers).status_code == 403
    assert client.get("/admin/readiness", headers=auth_headers).status_code == 403
    assert client.post("/admin/monitor/live/stop", headers=auth_headers).status_code == 403


def test_admin_live_capture_routes_call_bounded_manager(client, monkeypatch):
    from app.api import admin
    from tests.helpers import create_admin_headers

    class FakeManager:
        def interfaces(self):
            return ["loopback"]

        def start(self, interface, duration_seconds, packet_limit):
            return {"status": "running", "interface": interface, "duration_seconds": duration_seconds, "packet_limit": packet_limit}

        def status(self):
            return {"status": "running"}

        def stop(self):
            return {"status": "stopped"}

    monkeypatch.setattr(admin, "live_capture_manager", FakeManager())
    headers = create_admin_headers(client)
    assert client.get("/admin/monitor/live/interfaces", headers=headers).json() == {"interfaces": ["loopback"]}
    started = client.post(
        "/admin/monitor/live/start",
        headers=headers,
        json={"interface": "loopback", "duration_seconds": 10, "packet_limit": 1000},
    )
    assert started.status_code == 200
    assert started.json()["packet_limit"] == 1000
    assert client.get("/admin/monitor/live/status", headers=headers).json()["status"] == "running"
    assert client.post("/admin/monitor/live/stop", headers=headers).json()["status"] == "stopped"


def test_readiness_endpoint_is_admin_only_and_redacts_values(client, auth_headers, monkeypatch):
    from tests.helpers import create_admin_headers

    monkeypatch.setenv("SENTINEL_ADMIN_USERNAME", "do-not-return-this-name")
    monkeypatch.setenv("SENTINEL_ADMIN_PASSWORD", "do-not-return-this-password")
    monkeypatch.setenv("SENTINEL_ALLOWED_ORIGINS", "https://web.example")
    headers = create_admin_headers(client)
    response = client.get(
        "/admin/readiness",
        headers={**headers, "Origin": "https://web.example"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["checks"]["admin_credentials_configured"]["ready"] is True
    assert body["checks"]["request_origin_allowed"]["ready"] is True
    assert "do-not-return-this-password" not in response.text
    assert "do-not-return-this-name" not in response.text
    blocked = client.get(
        "/admin/readiness",
        headers={**headers, "Origin": "https://unlisted.example"},
    )
    assert blocked.json()["checks"]["request_origin_allowed"]["ready"] is False
    assert "unlisted.example" not in blocked.text
