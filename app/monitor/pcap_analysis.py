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
    """Read offline captures in-process; no TShark executable is required."""
    import dpkt
    import socket
    from itertools import islice

    rows = []
    undecoded = 0
    try:
        with open(path, "rb") as source:
            reader = dpkt.pcap.UniversalReader(source)
            linktype = reader.datalink()
            for timestamp, raw in islice(reader, MAX_PCAP_PACKETS):
                row = {"timestamp": float(timestamp), "length": len(raw), "protocol": "OTHER"}
                try:
                    if linktype == 1:
                        network = dpkt.ethernet.Ethernet(raw).data
                    elif linktype == 113:
                        network = dpkt.sll.SLL(raw).data
                    elif linktype in (0, 108):
                        network = dpkt.loopback.Loopback(raw).data
                    elif linktype in (12, 101, 228, 229):
                        network = dpkt.ip6.IP6(raw) if raw[0] >> 4 == 6 else dpkt.ip.IP(raw)
                    else:
                        network = None
                    if isinstance(network, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        family = socket.AF_INET6 if len(network.src) == 16 else socket.AF_INET
                        row["source"] = socket.inet_ntop(family, network.src)
                        row["destination"] = socket.inet_ntop(family, network.dst)
                        transport = network.data
                        if isinstance(transport, dpkt.tcp.TCP):
                            row["protocol"] = "TCP"
                        elif isinstance(transport, dpkt.udp.UDP):
                            row["protocol"] = "UDP"
                        elif isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                            row["protocol"] = "ICMP"
                    elif isinstance(network, dpkt.arp.ARP):
                        row["protocol"] = "ARP"
                    if row["protocol"] == "OTHER":
                        undecoded += 1
                except (dpkt.UnpackError, ValueError, IndexError, socket.error):
                    undecoded += 1
                rows.append(row)
        result = summarize_packets(rows)
        result["parser"] = "dpkt"
        result["unclassified_packets"] = undecoded
        result["note"] += " Protocols are classified at the network/transport layer; TLS and HTTP inside TCP are not separately dissected. Bytes reflect captured bytes. Unrecognized packets remain OTHER."
        return result
    except (dpkt.UnpackError, ValueError, IndexError, EOFError) as exc:
        raise ValueError("Unable to read this capture. Save it as PCAP or PCAPNG in Wireshark and retry; the file may be empty, truncated, or unsupported.") from exc
