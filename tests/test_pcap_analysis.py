from app.monitor.pcap_analysis import summarize_packets


def test_offline_pcap_and_pcapng_without_tshark(tmp_path):
    import dpkt
    from app.monitor.pcap_analysis import analyze_pcap_file
    packet = dpkt.ethernet.Ethernet(
        src=b'\x01' * 6, dst=b'\x02' * 6, type=0x800,
        data=dpkt.ip.IP(src=b'\x7f\x00\x00\x01', dst=b'\x7f\x00\x00\x02',
                        p=17, data=dpkt.udp.UDP(sport=1234, dport=5678)),
    )
    for name, writer_type in [('test.pcap', dpkt.pcap.Writer), ('test.pcapng', dpkt.pcapng.Writer)]:
        path = tmp_path / name
        with path.open('wb') as target:
            writer = writer_type(target)
            writer.writepkt(bytes(packet), ts=100.0)
            writer.writepkt(bytes(packet), ts=101.0)
        result = analyze_pcap_file(path)
        assert result['packet_count'] == 2
        assert result['protocol_counts'] == {'UDP': 2}
        assert result['duration_seconds'] == 1.0
        assert result['parser'] == 'dpkt'


def test_invalid_capture_is_rejected(tmp_path):
    import pytest
    from app.monitor.pcap_analysis import analyze_pcap_file
    path = tmp_path / 'bad.pcapng'
    path.write_bytes(b'not a capture')
    with pytest.raises(ValueError):
        analyze_pcap_file(path)


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
