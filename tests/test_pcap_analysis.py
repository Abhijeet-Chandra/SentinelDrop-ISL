from app.monitor.pcap_analysis import summarize_packets


def test_packet_summary_counts_protocol_rates_and_connections():
    rows = summarize_packets([
        {"timestamp": 1000.0, "length": 100, "protocol": "TCP", "source": "10.0.0.1", "destination": "10.0.0.2"},
        {"timestamp": 1000.5, "length": 200, "protocol": "TCP", "source": "10.0.0.1", "destination": "10.0.0.2"},
        {"timestamp": 1001.5, "length": 50, "protocol": "UDP", "source": "10.0.0.3", "destination": "10.0.0.4"},
    ])

    assert rows["packet_count"] == 3
    assert rows["bytes_total"] == 350
    assert rows["duration_seconds"] == 1.5
    assert rows["protocol_counts"] == {"TCP": 2, "UDP": 1}
    assert rows["unique_connections"] == 2
    assert rows["packets_per_second"] == 2
    assert rows["suspicious_flood_signal"] is False
