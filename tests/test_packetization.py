"""Tests for the packetization module."""

import struct
import tempfile
from pathlib import Path

import pytest

from pqc_bench.packetization import (
    PacketizationResult,
    TcpFlow,
    TcpSegment,
    TlsRecord,
    compute_flow_metrics,
    extract_flows,
    format_json,
    format_text,
    group_connections,
    parse_ethernet,
    parse_ipv4,
    parse_pcap,
    parse_tcp,
    parse_tcp_options,
    parse_tls_records,
    result_to_dict,
)


# Test Fixtures: Synthetic PCAP and packet data


def create_minimal_pcap(packets: list[tuple[float, bytes]]) -> bytes:
    """Create a minimal PCAP file in memory.

    Args:
        packets: List of (timestamp_seconds, packet_bytes) tuples

    Returns:
        Complete PCAP file as bytes
    """
    # Global header (24 bytes)
    # Magic (4), version_major (2), version_minor (2), thiszone (4), sigfigs (4),
    # snaplen (4), linktype (4)
    # linktype=1 is DLT_EN10MB (Ethernet)
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    packet_data = b""
    for timestamp, data in packets:
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1e6)
        incl_len = len(data)
        orig_len = len(data)

        packet_header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        packet_data += packet_header + data

    return global_header + packet_data


def create_ethernet_frame(
    ethertype: int,
    payload: bytes,
    src_mac: bytes = b"\x00\x11\x22\x33\x44\x55",
    dst_mac: bytes = b"\x66\x77\x88\x99\xaa\xbb",
) -> bytes:
    """Create an Ethernet frame."""
    return dst_mac + src_mac + struct.pack(">H", ethertype) + payload


def create_ipv4_packet(
    src_ip: str,
    dst_ip: str,
    protocol: int,
    payload: bytes,
) -> bytes:
    """Create a minimal IPv4 packet (20-byte header, no options)."""

    def ip_to_bytes(ip: str) -> bytes:
        return bytes(int(x) for x in ip.split("."))

    version_ihl = (4 << 4) | 5  # IPv4, 20-byte header
    tos = 0
    total_length = 20 + len(payload)
    identification = 0
    flags_fragment = 0
    ttl = 64
    header_checksum = 0  # Simplified, not validated

    header = struct.pack(
        ">BBHHHBBH",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        header_checksum,
    )
    header += ip_to_bytes(src_ip) + ip_to_bytes(dst_ip)

    return header + payload


def create_tcp_segment(
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    mss: int | None = None,
) -> bytes:
    """Create a TCP segment with optional MSS option."""
    options = b""
    if mss is not None:
        # MSS option: kind=2, len=4, mss value (big-endian)
        options = struct.pack(">BBH", 2, 4, mss)
        # Pad to 4-byte boundary
        while len(options) % 4 != 0:
            options += b"\x00"

    data_offset = (5 + len(options) // 4) << 4
    window = 65535
    checksum = 0
    urgent = 0

    header = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        data_offset,
        flags,
        window,
        checksum,
        urgent,
    )

    return header + options + payload


def create_tls_record(
    content_type: int,
    version: int,
    payload: bytes,
) -> bytes:
    """Create a TLS record."""
    length = len(payload)
    return struct.pack(">BHH", content_type, version, length) + payload


def create_full_tcp_ip_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes,
    mss: int | None = None,
) -> bytes:
    """Create a complete Ethernet/IPv4/TCP packet."""
    tcp_segment = create_tcp_segment(src_port, dst_port, seq, ack, flags, payload, mss)
    ipv4_packet = create_ipv4_packet(src_ip, dst_ip, 6, tcp_segment)  # 6 = TCP
    return create_ethernet_frame(0x0800, ipv4_packet)  # 0x0800 = IPv4


# Tests: Packet Parsing


class TestParseEthernet:
    """Tests for parse_ethernet function."""

    def test_too_short(self):
        """Data shorter than 14 bytes returns None."""
        assert parse_ethernet(b"\x00" * 13) is None

    def test_ipv4_ethertype(self):
        """Parse Ethernet frame with IPv4 ethertype."""
        frame = b"\x00" * 12 + struct.pack(">H", 0x0800) + b"payload"
        result = parse_ethernet(frame)
        assert result is not None
        ethertype, payload = result
        assert ethertype == 0x0800
        assert payload == b"payload"

    def test_ipv6_ethertype(self):
        """Parse Ethernet frame with IPv6 ethertype."""
        frame = b"\x00" * 12 + struct.pack(">H", 0x86DD) + b"v6data"
        result = parse_ethernet(frame)
        assert result is not None
        assert result[0] == 0x86DD

    def test_vlan_tag(self):
        """Parse Ethernet frame with VLAN tag."""
        # VLAN ethertype (0x8100) + 2 bytes VLAN tag + real ethertype
        frame = (
            b"\x00" * 12
            + struct.pack(">H", 0x8100)
            + b"\x00\x01"
            + struct.pack(">H", 0x0800)
            + b"data"
        )
        result = parse_ethernet(frame)
        assert result is not None
        ethertype, payload = result
        assert ethertype == 0x0800
        assert payload == b"data"


class TestParseIPv4:
    """Tests for parse_ipv4 function."""

    def test_too_short(self):
        """Data shorter than 20 bytes returns None."""
        assert parse_ipv4(b"\x00" * 19) is None

    def test_wrong_version(self):
        """Non-IPv4 version returns None."""
        # Version 6, IHL 5 = 0x65
        data = struct.pack("B", 0x65) + b"\x00" * 19
        assert parse_ipv4(data) is None

    def test_valid_ipv4(self):
        """Parse valid IPv4 header."""
        packet = create_ipv4_packet("192.168.1.1", "192.168.1.2", 6, b"tcpdata")
        result = parse_ipv4(packet)
        assert result is not None
        src_ip, dst_ip, protocol, payload = result
        assert src_ip == "192.168.1.1"
        assert dst_ip == "192.168.1.2"
        assert protocol == 6
        assert payload == b"tcpdata"


class TestParseTcpOptions:
    """Tests for parse_tcp_options function."""

    def test_empty_options(self):
        """Empty options data returns empty dict."""
        assert parse_tcp_options(b"") == {}

    def test_end_of_options(self):
        """EOL option (kind=0) terminates parsing."""
        data = b"\x00\x01\x01"  # EOL, NOP, NOP
        assert parse_tcp_options(data) == {}

    def test_nop_options(self):
        """NOP options (kind=1) are skipped."""
        data = b"\x01\x01\x00"  # NOP, NOP, EOL
        assert parse_tcp_options(data) == {}

    def test_mss_option(self):
        """MSS option is parsed correctly."""
        # MSS option: kind=2, len=4, value=1460
        data = struct.pack(">BBH", 2, 4, 1460)
        result = parse_tcp_options(data)
        assert result == {"mss": 1460}

    def test_mss_with_padding(self):
        """MSS option with NOPs and EOL."""
        data = b"\x01" + struct.pack(">BBH", 2, 4, 1380) + b"\x00"
        result = parse_tcp_options(data)
        assert result == {"mss": 1380}


class TestParseTcp:
    """Tests for parse_tcp function."""

    def test_too_short(self):
        """Data shorter than 20 bytes returns None."""
        assert parse_tcp(b"\x00" * 19) is None

    def test_valid_tcp_no_options(self):
        """Parse valid TCP segment without options."""
        segment = create_tcp_segment(12345, 443, 1000, 2000, 0x12, b"payload")
        result = parse_tcp(segment)
        assert result is not None
        src_port, dst_port, seq, ack, flags, payload, options = result
        assert src_port == 12345
        assert dst_port == 443
        assert seq == 1000
        assert ack == 2000
        assert flags == 0x12  # SYN+ACK
        assert payload == b"payload"
        assert options == {}

    def test_tcp_with_mss_option(self):
        """Parse TCP SYN with MSS option."""
        segment = create_tcp_segment(12345, 443, 0, 0, 0x02, b"", mss=1460)
        result = parse_tcp(segment)
        assert result is not None
        _, _, _, _, _, _, options = result
        assert options["mss"] == 1460


# Tests: PCAP File Parsing


class TestParsePcap:
    """Tests for parse_pcap function."""

    def test_empty_file_raises(self):
        """Empty file raises ValueError."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"")
            path = f.name

        try:
            with pytest.raises(ValueError, match="Truncated PCAP file"):
                parse_pcap(path)
        finally:
            Path(path).unlink()

    def test_invalid_magic_raises(self):
        """Invalid magic number raises ValueError."""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"\x00\x00\x00\x00" + b"\x00" * 20)
            path = f.name

        try:
            with pytest.raises(ValueError, match="Unknown PCAP magic"):
                parse_pcap(path)
        finally:
            Path(path).unlink()

    def test_valid_pcap_single_packet(self):
        """Parse PCAP with a single packet."""
        packet = create_full_tcp_ip_packet(
            "10.0.0.1", "10.0.0.2", 12345, 443, 100, 0, 0x02, b"", mss=1460
        )
        pcap_data = create_minimal_pcap([(1.0, packet)])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(pcap_data)
            path = f.name

        try:
            packets = parse_pcap(path)
            assert len(packets) == 1
            assert packets[0][0] == 1.0
            assert packets[0][1] == packet
        finally:
            Path(path).unlink()

    def test_valid_pcap_multiple_packets(self):
        """Parse PCAP with multiple packets."""
        packet1 = create_full_tcp_ip_packet(
            "10.0.0.1", "10.0.0.2", 12345, 443, 100, 0, 0x02, b"", mss=1460
        )
        packet2 = create_full_tcp_ip_packet(
            "10.0.0.2", "10.0.0.1", 443, 12345, 200, 101, 0x12, b"", mss=1380
        )
        pcap_data = create_minimal_pcap([(1.0, packet1), (1.1, packet2)])

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(pcap_data)
            path = f.name

        try:
            packets = parse_pcap(path)
            assert len(packets) == 2
            assert packets[0][0] == 1.0
            assert packets[1][0] == pytest.approx(1.1, abs=0.001)
        finally:
            Path(path).unlink()


# Tests: Flow Extraction and Grouping


class TestExtractFlows:
    """Tests for extract_flows function."""

    def test_single_syn_packet(self):
        """Extract flow from a single SYN packet."""
        packet = create_full_tcp_ip_packet(
            "10.0.0.1", "10.0.0.2", 12345, 443, 100, 0, 0x02, b"", mss=1460
        )
        packets = [(0.0, packet)]

        flows = extract_flows(packets)

        assert len(flows) == 1
        flow_key = ("10.0.0.1", "10.0.0.2", 12345, 443)
        assert flow_key in flows
        assert flows[flow_key].mss == 1460
        assert len(flows[flow_key].segments) == 1

    def test_bidirectional_flow(self):
        """Extract bidirectional flows from handshake."""
        # Client SYN
        syn = create_full_tcp_ip_packet(
            "10.0.0.1", "10.0.0.2", 12345, 443, 100, 0, 0x02, b"", mss=1460
        )
        # Server SYN-ACK
        synack = create_full_tcp_ip_packet(
            "10.0.0.2", "10.0.0.1", 443, 12345, 200, 101, 0x12, b"", mss=1380
        )
        packets = [(0.0, syn), (0.1, synack)]

        flows = extract_flows(packets)

        assert len(flows) == 2
        client_key = ("10.0.0.1", "10.0.0.2", 12345, 443)
        server_key = ("10.0.0.2", "10.0.0.1", 443, 12345)
        assert client_key in flows
        assert server_key in flows
        assert flows[client_key].mss == 1460
        assert flows[server_key].mss == 1380


class TestGroupConnections:
    """Tests for group_connections function."""

    def test_single_direction(self):
        """Group with only one direction creates connection."""
        flow = TcpFlow(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=443,
            mss=1460,
        )
        # Add a SYN segment
        flow.segments.append(
            TcpSegment(seq=100, ack=0, flags=0x02, payload_len=0, payload=b"", timestamp=0.0)
        )

        flows = {flow.flow_key: flow}
        connections = group_connections(flows)

        assert len(connections) == 1
        client_flow, server_flow = connections[0]
        assert client_flow is flow
        assert server_flow is None

    def test_bidirectional_connection(self):
        """Group bidirectional flows into one connection."""
        client_flow = TcpFlow(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=443,
            mss=1460,
        )
        client_flow.segments.append(
            TcpSegment(seq=100, ack=0, flags=0x02, payload_len=0, payload=b"", timestamp=0.0)
        )

        server_flow = TcpFlow(
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=443,
            dst_port=12345,
            mss=1380,
        )
        server_flow.segments.append(
            TcpSegment(seq=200, ack=101, flags=0x12, payload_len=0, payload=b"", timestamp=0.1)
        )

        flows = {client_flow.flow_key: client_flow, server_flow.flow_key: server_flow}
        connections = group_connections(flows)

        assert len(connections) == 1


# Tests: TLS Record Parsing


class TestParseTlsRecords:
    """Tests for TLS record parsing."""

    def test_single_handshake_record(self):
        """Parse a single TLS handshake record."""
        tls_record = create_tls_record(22, 0x0303, b"\x01" * 100)  # Handshake, TLS 1.2

        flow = TcpFlow(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=12345, dst_port=443)
        flow.segments.append(
            TcpSegment(
                seq=0,
                ack=0,
                flags=0x10,
                payload_len=len(tls_record),
                payload=tls_record,
                timestamp=0.0,
            )
        )

        records = parse_tls_records(tls_record, flow)

        assert len(records) == 1
        assert records[0].content_type == 22
        assert records[0].content_type_name == "handshake"
        assert records[0].length == 100

    def test_multiple_tls_records(self):
        """Parse multiple TLS records in sequence."""
        record1 = create_tls_record(22, 0x0303, b"\x01" * 50)  # Handshake
        record2 = create_tls_record(20, 0x0303, b"\x01")  # ChangeCipherSpec
        record3 = create_tls_record(23, 0x0303, b"\x01" * 200)  # ApplicationData

        stream = record1 + record2 + record3

        flow = TcpFlow(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=12345, dst_port=443)
        flow.segments.append(
            TcpSegment(
                seq=0, ack=0, flags=0x10, payload_len=len(stream), payload=stream, timestamp=0.0
            )
        )

        records = parse_tls_records(stream, flow)

        assert len(records) == 3
        assert records[0].content_type_name == "handshake"
        assert records[1].content_type_name == "change_cipher_spec"
        assert records[2].content_type_name == "application_data"

    def test_invalid_content_type_stops_parsing(self):
        """Invalid content type stops parsing."""
        # Valid record followed by invalid data
        valid_record = create_tls_record(22, 0x0303, b"\x01" * 10)
        invalid_data = b"\xff" * 20  # 0xFF is not a valid content type

        stream = valid_record + invalid_data

        flow = TcpFlow(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=12345, dst_port=443)
        flow.segments.append(
            TcpSegment(
                seq=0, ack=0, flags=0x10, payload_len=len(stream), payload=stream, timestamp=0.0
            )
        )

        records = parse_tls_records(stream, flow)

        assert len(records) == 1


# Tests: Metrics Computation


class TestComputeFlowMetrics:
    """Tests for compute_flow_metrics function."""

    def test_none_flow(self):
        """None flow returns None."""
        assert compute_flow_metrics(None, "test") is None

    def test_empty_flow(self):
        """Empty flow has zero segments."""
        flow = TcpFlow(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=12345, dst_port=443)
        metrics = compute_flow_metrics(flow, "client_to_server")

        assert metrics is not None
        assert metrics.segment_count == 0
        assert metrics.segments_with_payload == 0

    def test_flow_with_segments(self):
        """Flow with data segments computes correct metrics."""
        flow = TcpFlow(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=12345,
            dst_port=443,
            mss=1460,
        )
        # Add segments with varying payload sizes
        flow.segments.append(
            TcpSegment(seq=0, ack=0, flags=0x02, payload_len=0, payload=b"", timestamp=0.0)
        )  # SYN, no payload
        flow.segments.append(
            TcpSegment(seq=1, ack=0, flags=0x10, payload_len=500, payload=b"a" * 500, timestamp=0.1)
        )
        flow.segments.append(
            TcpSegment(
                seq=501, ack=0, flags=0x10, payload_len=1460, payload=b"b" * 1460, timestamp=0.2
            )
        )

        metrics = compute_flow_metrics(flow, "client_to_server")

        assert metrics is not None
        assert metrics.mss == 1460
        assert metrics.segment_count == 3
        assert metrics.segments_with_payload == 2
        assert metrics.total_payload_bytes == 1960
        assert metrics.min_payload_size == 500
        assert metrics.max_payload_size == 1460
        assert metrics.full_mss_segments >= 1


# Tests: Output Formatting


class TestFormatOutput:
    """Tests for format_json and format_text functions."""

    def test_format_json(self):
        """format_json produces valid JSON."""
        import json

        result = PacketizationResult(
            pcap_file="/test/capture.pcap",
            analysis_timestamp="2025-01-01T00:00:00",
            capture_duration_sec=1.5,
            kem_algorithm="X25519MLKEM768",
            sig_algorithm="mldsa65",
            mtu=1500,
        )

        output = format_json(result)
        parsed = json.loads(output)

        assert parsed["test_parameters"]["kem_algorithm"] == "X25519MLKEM768"
        assert parsed["test_parameters"]["mtu"] == 1500

    def test_format_text(self):
        """format_text produces readable output."""
        result = PacketizationResult(
            pcap_file="/test/capture.pcap",
            analysis_timestamp="2025-01-01T00:00:00",
            capture_duration_sec=1.5,
            kem_algorithm="X25519MLKEM768",
            sig_algorithm="mldsa65",
            mtu=1500,
            client_mss=1460,
            server_mss=1460,
        )

        output = format_text(result)

        assert "X25519MLKEM768" in output
        assert "mldsa65" in output
        assert "1500" in output
        assert "1460" in output

    def test_result_to_dict(self):
        """result_to_dict produces complete dictionary."""
        result = PacketizationResult(
            pcap_file="/test/capture.pcap",
            analysis_timestamp="2025-01-01T00:00:00",
            capture_duration_sec=1.5,
        )

        d = result_to_dict(result)

        assert "metadata" in d
        assert "test_parameters" in d
        assert "environment" in d
        assert "aggregated" in d
        assert "validation" in d
        assert "connections" in d


# Tests: Data Classes


class TestTcpSegment:
    """Tests for TcpSegment dataclass."""

    def test_flag_properties(self):
        """Test flag property methods."""
        syn = TcpSegment(seq=0, ack=0, flags=0x02, payload_len=0, payload=b"", timestamp=0.0)
        assert syn.is_syn
        assert not syn.is_ack
        assert not syn.is_fin
        assert not syn.is_rst

        synack = TcpSegment(seq=0, ack=0, flags=0x12, payload_len=0, payload=b"", timestamp=0.0)
        assert synack.is_syn
        assert synack.is_ack

        fin = TcpSegment(seq=0, ack=0, flags=0x11, payload_len=0, payload=b"", timestamp=0.0)
        assert fin.is_fin
        assert fin.is_ack

        rst = TcpSegment(seq=0, ack=0, flags=0x04, payload_len=0, payload=b"", timestamp=0.0)
        assert rst.is_rst


class TestTlsRecord:
    """Tests for TlsRecord dataclass."""

    def test_content_type_names(self):
        """Test content_type_name property."""
        record = TlsRecord(content_type=22, version=0x0303, length=100, offset=0)
        assert record.content_type_name == "handshake"

        record = TlsRecord(content_type=23, version=0x0303, length=100, offset=0)
        assert record.content_type_name == "application_data"

        record = TlsRecord(content_type=99, version=0x0303, length=100, offset=0)
        assert "unknown" in record.content_type_name


class TestTcpFlow:
    """Tests for TcpFlow dataclass."""

    def test_flow_key(self):
        """Test flow_key property."""
        flow = TcpFlow(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=12345, dst_port=443)
        assert flow.flow_key == ("10.0.0.1", "10.0.0.2", 12345, 443)

    def test_reverse_key(self):
        """Test reverse_key property."""
        flow = TcpFlow(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=12345, dst_port=443)
        assert flow.reverse_key == ("10.0.0.2", "10.0.0.1", 443, 12345)
