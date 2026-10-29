"""Bounded offline summary of administrator-uploaded packet captures."""

from __future__ import annotations

from collections import Counter, defaultdict
from math import floor


MAX_PCAP_PACKETS = 50_000
FLOOD_ALERT_PACKETS_PER_SECOND = 100


def summarize_packets(packets) -> dict:
    rows = []
    for packet in packets:
        if len(rows) >= MAX_PCAP_PACKETS:
            break
        rows.append(packet)
    if not rows:
        raise ValueError("The capture contains no readable packets.")
    timestamps = [float(row["timestamp"]) for row in rows]
    duration = max(0.0, max(timestamps) - min(timestamps))
    protocols = Counter(str(row.get("protocol") or "UNKNOWN").upper() for row in rows)
    connections = {
        (str(row.get("source") or "?"), str(row.get("destination") or "?"))
        for row in rows
        if row.get("source") or row.get("destination")
    }
    windows = defaultdict(int)
    for timestamp in timestamps:
        windows[floor(timestamp)] += 1
    peak_rate = max(windows.values(), default=0)
    total_bytes = sum(max(0, int(row.get("length") or 0)) for row in rows)

    return {
        "packet_count": len(rows),
        "bytes_total": total_bytes,
        "duration_seconds": round(duration, 3),
        "packets_per_second": round(len(rows) / duration, 3) if duration > 0 else 0,
        "peak_packets_per_second": peak_rate,
        "protocol_counts": dict(sorted(protocols.items())),
        "unique_connections": len(connections),
        "connection_counts": [
            {"source": source, "destination": destination}
            for source, destination in sorted(connections)[:100]
        ],
        "suspicious_flood_signal": peak_rate >= FLOOD_ALERT_PACKETS_PER_SECOND,
        "packet_limit": MAX_PCAP_PACKETS,
        "note": (
            "Offline summary of the uploaded capture. The flood signal is a simple packet-per-second threshold, "
            "not a verdict that an attack occurred. Only the first 50,000 packets are analyzed."
        ),
    }


def analyze_pcap_file(path) -> dict:
    try:
        import pyshark
    except Exception as exc:
        raise RuntimeError("PyShark is not installed; PCAP analysis is unavailable.") from exc

    capture = None
    try:
        capture = pyshark.FileCapture(str(path), keep_packets=False)
        rows = []
        for packet in capture:
            layers = {str(layer.layer_name).upper() for layer in packet.layers}
            network_layer = getattr(packet, "ip", None) or getattr(packet, "ipv6", None)
            rows.append({
                "timestamp": float(packet.sniff_timestamp),
                "length": int(packet.length),
                "protocol": next((name for name in ("HTTP", "TLS", "DNS", "TCP", "UDP", "ICMP") if name in layers), "OTHER"),
                "source": getattr(network_layer, "src", None) if network_layer else None,
                "destination": getattr(network_layer, "dst", None) if network_layer else None,
            })
            if len(rows) >= MAX_PCAP_PACKETS:
                break
        return summarize_packets(rows)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Could not parse this capture. Check that it is a supported PCAP/PCAPNG file and TShark is installed.") from exc
    finally:
        if capture is not None:
            capture.close()
