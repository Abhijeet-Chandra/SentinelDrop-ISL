"""Bounded, content-free HTTP request aggregates for hosted Admin monitoring."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from threading import Lock
from time import monotonic


MAX_MONITOR_SECONDS = 30
MAX_MONITOR_REQUESTS = 1_000
MAX_DECLARED_BYTES = 100_000_000
IGNORED_PATHS = {"/health"}
IGNORED_PREFIX = "/admin/monitor/http/"


def declared_content_bytes(value: str | None) -> int:
    """Content-Length is optional and client supplied, so bound its reported value."""
    try:
        return min(MAX_DECLARED_BYTES, max(0, int(value or 0)))
    except (TypeError, ValueError):
        return 0


class HttpRequestMonitor:
    def __init__(self, clock=monotonic):
        self._clock = clock
        self._lock = Lock()
        self._started = 0.0
        self._deadline = 0.0
        self._seconds = Counter()
        self._state = self._empty_state()

    @staticmethod
    def _empty_state() -> dict:
        return {
            "source": "application_http",
            "status": "idle",
            "request_count": 0,
            "request_bytes": 0,
            "response_bytes": 0,
            "peak_requests_per_second": 0,
            "requests_per_second": [],
            "status_counts": {},
            "started_at": None,
            "duration_seconds": 0,
            "request_limit": 0,
            "note": (
                "Completed API requests only, not captured network packets. "
                "Byte totals use Content-Length headers and can omit streamed data or network overhead. "
                "No payloads, addresses, credentials, or request paths are retained. "
                "This in-memory window resets when the backend restarts."
            ),
        }

    def _refresh(self, now: float) -> None:
        if self._state["status"] == "running" and now >= self._deadline:
            self._state["status"] = "complete"

    def start(self, duration_seconds: int = 30, request_limit: int = 1000) -> dict:
        if not 1 <= duration_seconds <= MAX_MONITOR_SECONDS:
            raise ValueError(f"Monitoring duration must be between 1 and {MAX_MONITOR_SECONDS} seconds.")
        if not 1 <= request_limit <= MAX_MONITOR_REQUESTS:
            raise ValueError(f"Request limit must be between 1 and {MAX_MONITOR_REQUESTS}.")
        with self._lock:
            now = self._clock()
            self._refresh(now)
            if self._state["status"] == "running":
                raise RuntimeError("A request monitor is already running.")
            self._started = now
            self._deadline = now + duration_seconds
            self._seconds.clear()
            self._state = self._empty_state()
            self._state.update(
                status="running",
                started_at=datetime.now(timezone.utc).isoformat(),
                duration_seconds=duration_seconds,
                request_limit=request_limit,
            )
            return self._snapshot()

    def record(self, *, path: str, status_code: int, request_bytes: int, response_bytes: int) -> None:
        if path in IGNORED_PATHS or path.startswith(IGNORED_PREFIX):
            return
        with self._lock:
            now = self._clock()
            self._refresh(now)
            if self._state["status"] != "running":
                return
            self._state["request_count"] += 1
            self._state["request_bytes"] += min(MAX_DECLARED_BYTES, max(0, int(request_bytes)))
            self._state["response_bytes"] += min(MAX_DECLARED_BYTES, max(0, int(response_bytes)))
            group = f"{int(status_code) // 100}xx"
            statuses = Counter(self._state["status_counts"])
            statuses[group] += 1
            self._state["status_counts"] = dict(sorted(statuses.items()))
            second = int(now - self._started)
            self._seconds[second] += 1
            self._state["peak_requests_per_second"] = max(
                self._state["peak_requests_per_second"], self._seconds[second]
            )
            if self._state["request_count"] >= self._state["request_limit"]:
                self._state["status"] = "complete"

    def _snapshot(self) -> dict:
        snapshot = {**self._state, "status_counts": dict(self._state["status_counts"])}
        if self._state["status"] != "idle":
            elapsed = min(
                self._state["duration_seconds"],
                max(1, int(self._clock() - self._started) + 1),
            )
            snapshot["requests_per_second"] = [self._seconds[index] for index in range(elapsed)]
        return snapshot

    def status(self) -> dict:
        with self._lock:
            self._refresh(self._clock())
            return self._snapshot()

    def stop(self) -> dict:
        with self._lock:
            self._refresh(self._clock())
            if self._state["status"] == "running":
                self._state["status"] = "stopped"
            return self._snapshot()


http_request_monitor = HttpRequestMonitor()
