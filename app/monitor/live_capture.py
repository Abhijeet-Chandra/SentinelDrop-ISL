"""Single-run, bounded live traffic summaries for the local Admin lab."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from threading import Lock, Thread, current_thread
from time import monotonic
from typing import Any


MAX_CAPTURE_SECONDS = 30
MAX_CAPTURE_PACKETS = 5_000


class LiveCaptureManager:
    def __init__(self, capture_factory=None, interface_provider=None):
        self._capture_factory = capture_factory
        self._interface_provider = interface_provider
        self._lock = Lock()
        self._state: dict[str, Any] = {
            "status": "idle",
            "interface": None,
            "packet_count": 0,
            "bytes_total": 0,
            "protocol_counts": {},
            "peak_packets_per_second": 0,
            "started_at": None,
            "duration_seconds": 0,
            "error": None,
            "note": "Live capture requires TShark and operating-system capture permissions.",
        }
        self._second_counts = defaultdict(int)
        self._capture = None
        self._thread = None

    def interfaces(self) -> list[str]:
        try:
            provider = self._interface_provider
            if provider is None:
                import pyshark

                provider = pyshark.tshark.tshark.get_all_tshark_interfaces_names
            return sorted(set(str(name) for name in provider() if name))
        except Exception as exc:
            raise RuntimeError(
                "TShark could not list capture interfaces. Install TShark and the required capture driver/permissions."
            ) from exc

    def start(self, interface: str, duration_seconds: int = 10, packet_limit: int = 1000) -> dict:
        if not 1 <= int(duration_seconds) <= MAX_CAPTURE_SECONDS:
            raise ValueError(f"Capture duration must be between 1 and {MAX_CAPTURE_SECONDS} seconds.")
        if not 1 <= int(packet_limit) <= MAX_CAPTURE_PACKETS:
            raise ValueError(f"Packet limit must be between 1 and {MAX_CAPTURE_PACKETS}.")
        if not interface or len(interface) > 200 or interface not in self.interfaces():
            raise ValueError("Choose a capture interface reported by TShark.")

        with self._lock:
            if self._state["status"] == "running":
                raise RuntimeError("A live capture is already running.")
            capture_factory = self._capture_factory
            if capture_factory is None:
                import pyshark

                capture_factory = pyshark.LiveCapture
            try:
                capture = capture_factory(interface=interface, keep_packets=False)
            except Exception as exc:
                raise RuntimeError("TShark could not open the selected interface.") from exc
            self._capture = capture
            self._second_counts.clear()
            self._state = {
                "status": "running",
                "interface": interface,
                "packet_count": 0,
                "bytes_total": 0,
                "protocol_counts": {},
                "peak_packets_per_second": 0,
                "started_at": None,
                "duration_seconds": 0,
                "error": None,
                "note": "Aggregated metadata only; endpoint addresses and packet contents are not retained.",
            }
            self._thread = Thread(
                target=self._run_capture,
                args=(capture, int(duration_seconds), int(packet_limit)),
                daemon=True,
                name="sentineldrop-live-capture",
            )
            self._thread.start()
            return dict(self._state)

    def _record_packet(self, packet) -> None:
        def value(name, default=None):
            if isinstance(packet, dict):
                return packet.get(name, default)
            return getattr(packet, name, default)

        layers = value("layers", []) or []
        protocol = str(value("protocol", "") or "").upper()
        if not protocol and layers:
            layer = layers[-1]
            protocol = str(
                layer.get("layer_name", "UNKNOWN")
                if isinstance(layer, dict)
                else getattr(layer, "layer_name", "UNKNOWN")
            ).upper()
        protocol = protocol or "UNKNOWN"
        try:
            timestamp = float(value("sniff_timestamp", value("timestamp", 0)))
        except (TypeError, ValueError):
            timestamp = 0.0
        try:
            packet_length = max(0, int(value("length", 0) or 0))
        except (TypeError, ValueError):
            packet_length = 0

        with self._lock:
            self._state["packet_count"] += 1
            self._state["bytes_total"] += packet_length
            counts = Counter(self._state["protocol_counts"])
            counts[protocol] += 1
            self._state["protocol_counts"] = dict(sorted(counts.items()))
            self._second_counts[int(timestamp)] += 1
            self._state["peak_packets_per_second"] = max(self._second_counts.values(), default=0)

    def _run_capture(self, capture, duration_seconds: int, packet_limit: int) -> None:
        started = monotonic()
        with self._lock:
            self._state["started_at"] = datetime.now(timezone.utc).isoformat()
        try:
            capture.apply_on_packets(
                self._record_packet,
                timeout=duration_seconds,
                packet_count=packet_limit,
            )
            with self._lock:
                if self._state["status"] == "running":
                    self._state["status"] = "complete"
        except Exception:
            with self._lock:
                if self._state["status"] == "running":
                    self._state["status"] = "error"
                    self._state["error"] = "Capture stopped unexpectedly. Check TShark, interface permissions, and interface availability."
        finally:
            with self._lock:
                self._state["duration_seconds"] = round(monotonic() - started, 3)
                self._state["peak_packets_per_second"] = max(self._second_counts.values(), default=0)
                self._capture = None
                if self._state["status"] == "stopping":
                    self._state["status"] = "stopped"

    def stop(self) -> dict:
        with self._lock:
            capture = self._capture
            if self._state["status"] == "running":
                self._state["status"] = "stopping"
        if capture is not None:
            try:
                capture.close()
            except Exception:
                pass
        thread = self._thread
        if thread is not None and thread is not current_thread():
            thread.join(timeout=2)
        with self._lock:
            if self._state["status"] == "stopping" and (thread is None or not thread.is_alive()):
                self._state["status"] = "stopped"
        return self.status()

    def status(self) -> dict:
        with self._lock:
            result = dict(self._state)
            result["protocol_counts"] = dict(self._state["protocol_counts"])
            result["unique_connections"] = None
            result["suspicious_flood_signal"] = (
                result["peak_packets_per_second"] >= 100
            )
            return result

live_capture_manager = LiveCaptureManager()
