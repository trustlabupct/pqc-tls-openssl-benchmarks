"""Packetization analysis for TLS handshake packet captures.

This module implements Option B from PLAN.md: a Python analyzer that parses
pcap files captured by packetization_capture.sh and produces JSON summaries
with transport-level and TLS record-level metrics.

The analyzer:
- Parses classic PCAP format (tcpdump output)
- Extracts TCP MSS from SYN/SYN-ACK options
- Computes segment payload statistics
- Reassembles TCP streams and parses TLS record headers
- Maps TLS records to TCP segments

No external dependencies beyond Python stdlib are required.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Data Models


@dataclass
class TcpFlow:
    """Represents a single TCP flow (one direction of a connection)."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    mss: int | None = None  # MSS from SYN option
    segments: list[TcpSegment] = field(default_factory=list)

    @property
    def flow_key(self) -> tuple[str, str, int, int]:
        """Unique key for this flow direction."""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port)

    @property
    def reverse_key(self) -> tuple[str, str, int, int]:
        """Key for the reverse direction."""
        return (self.dst_ip, self.src_ip, self.dst_port, self.src_port)


@dataclass
class TcpSegment:
    """A single TCP segment with payload."""

    seq: int
    ack: int
    flags: int
    payload_len: int
    payload: bytes
    timestamp: float  # Relative timestamp in seconds

    @property
    def is_syn(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def is_ack(self) -> bool:
        return bool(self.flags & 0x10)

    @property
    def is_fin(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def is_rst(self) -> bool:
        return bool(self.flags & 0x04)


@dataclass
class TlsRecord:
    """A TLS record parsed from reassembled TCP stream."""

    content_type: int
    version: int
    length: int
    offset: int  # Byte offset in stream
    # Mapping to TCP segments
    segment_indices: list[int] = field(default_factory=list)

    @property
    def content_type_name(self) -> str:
        """Human-readable content type name."""
        names = {
            20: "change_cipher_spec",
            21: "alert",
            22: "handshake",
            23: "application_data",
        }
        return names.get(self.content_type, f"unknown({self.content_type})")


@dataclass
class FlowMetrics:
    """Metrics computed for a single TCP flow direction."""

    direction: str  # "client_to_server" or "server_to_client"
    mss: int | None
    segment_count: int
    segments_with_payload: int
    total_payload_bytes: int
    payload_sizes: list[int]
    full_mss_segments: int  # Segments with payload == MSS
    max_payload_size: int
    min_payload_size: int
    tls_records: list[dict]
    records_spanning_segments: int  # Records that span 2+ segments


@dataclass
class ConnectionMetrics:
    """Metrics for a complete TCP connection (both directions)."""

    client_to_server: FlowMetrics
    server_to_client: FlowMetrics
    handshake_segments_total: int
    retransmissions: int
    out_of_order: int


@dataclass
class PacketizationResult:
    """Complete result of packetization analysis."""

    # Capture metadata
    pcap_file: str
    analysis_timestamp: str
    capture_duration_sec: float

    # Test parameters (from metadata.json if available)
    kem_algorithm: str | None = None
    sig_algorithm: str | None = None
    mtu: int | None = None
    iterations: int | None = None
    cert_der_size_bytes: int | None = None

    # Environment
    openssl_version: str | None = None

    # Per-connection metrics
    connections: list[ConnectionMetrics] = field(default_factory=list)

    # Aggregated statistics
    client_mss: int | None = None
    server_mss: int | None = None
    avg_client_segments: float | None = None
    avg_server_segments: float | None = None

    # Validation flags
    max_payload_exceeds_mss: bool = False
    mss_matches_mtu: bool = True


# PCAP Parsing (Classic format, no external dependencies)

# PCAP magic numbers
PCAP_MAGIC_NATIVE = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1
PCAP_MAGIC_NSEC_NATIVE = 0xA1B23C4D
PCAP_MAGIC_NSEC_SWAPPED = 0x4D3CB2A1

# Ethernet type
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

# IP protocol numbers
IPPROTO_TCP = 6

# TCP option kinds
TCP_OPT_END = 0
TCP_OPT_NOP = 1
TCP_OPT_MSS = 2


def parse_pcap(file_path: str | Path) -> list[tuple[float, bytes]]:
    """Parse a PCAP file and return list of (timestamp, packet_data) tuples.

    Supports classic PCAP format (not pcapng).

    Args:
        file_path: Path to the PCAP file

    Returns:
        List of (timestamp_seconds, raw_packet_bytes) tuples

    Raises:
        ValueError: If file format is not recognized
    """
    packets: list[tuple[float, bytes]] = []

    with open(file_path, "rb") as f:
        # Read global header (24 bytes)
        global_header = f.read(24)
        if len(global_header) < 24:
            raise ValueError("Truncated PCAP file: global header too short")

        magic = struct.unpack("<I", global_header[0:4])[0]

        # Determine byte order and timestamp resolution
        if magic == PCAP_MAGIC_NATIVE:
            byte_order = "<"
            nsec_resolution = False
        elif magic == PCAP_MAGIC_SWAPPED:
            byte_order = ">"
            nsec_resolution = False
        elif magic == PCAP_MAGIC_NSEC_NATIVE:
            byte_order = "<"
            nsec_resolution = True
        elif magic == PCAP_MAGIC_NSEC_SWAPPED:
            byte_order = ">"
            nsec_resolution = True
        else:
            raise ValueError(f"Unknown PCAP magic: 0x{magic:08X}")

        # Parse rest of global header
        # version_major, version_minor, thiszone, sigfigs, snaplen, linktype
        # Note: thiszone is signed int, others are unsigned
        header_fmt = f"{byte_order}HHiIII"
        header_data = struct.unpack(header_fmt, global_header[4:24])
        linktype = header_data[5]

        if linktype != 1:  # DLT_EN10MB (Ethernet)
            raise ValueError(f"Unsupported link type: {linktype} (expected Ethernet)")

        # Read packets
        packet_header_fmt = f"{byte_order}IIII"
        packet_header_size = 16

        while True:
            packet_header = f.read(packet_header_size)
            if len(packet_header) < packet_header_size:
                break  # EOF

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(packet_header_fmt, packet_header)

            # Calculate timestamp
            if nsec_resolution:
                timestamp = ts_sec + ts_usec / 1e9
            else:
                timestamp = ts_sec + ts_usec / 1e6

            # Read packet data
            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                break  # Truncated

            packets.append((timestamp, packet_data))

    return packets


def parse_ethernet(data: bytes) -> tuple[int, bytes] | None:
    """Parse Ethernet frame and return (ethertype, payload).

    Handles VLAN tags.
    """
    if len(data) < 14:
        return None

    ethertype = struct.unpack(">H", data[12:14])[0]
    payload = data[14:]

    # Handle VLAN tag
    if ethertype == ETHERTYPE_VLAN:
        if len(payload) < 4:
            return None
        ethertype = struct.unpack(">H", payload[2:4])[0]
        payload = payload[4:]

    return ethertype, payload


def parse_ipv4(data: bytes) -> tuple[str, str, int, bytes] | None:
    """Parse IPv4 header and return (src_ip, dst_ip, protocol, payload)."""
    if len(data) < 20:
        return None

    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4

    if version != 4 or len(data) < ihl:
        return None

    protocol = data[9]
    src_ip = ".".join(str(b) for b in data[12:16])
    dst_ip = ".".join(str(b) for b in data[16:20])
    payload = data[ihl:]

    return src_ip, dst_ip, protocol, payload


def parse_ipv6(data: bytes) -> tuple[str, str, int, bytes] | None:
    """Parse IPv6 header and return (src_ip, dst_ip, protocol, payload)."""
    if len(data) < 40:
        return None

    version = data[0] >> 4
    if version != 6:
        return None

    next_header = data[6]
    # Simplified: assume no extension headers
    src_ip = ":".join(f"{data[8 + i * 2]:02x}{data[9 + i * 2]:02x}" for i in range(8))
    dst_ip = ":".join(f"{data[24 + i * 2]:02x}{data[25 + i * 2]:02x}" for i in range(8))
    payload = data[40:]

    return src_ip, dst_ip, next_header, payload


def parse_tcp_options(options_data: bytes) -> dict:
    """Parse TCP options and extract MSS if present."""
    result: dict = {}
    i = 0
    while i < len(options_data):
        kind = options_data[i]
        if kind == TCP_OPT_END:
            break
        if kind == TCP_OPT_NOP:
            i += 1
            continue
        if i + 1 >= len(options_data):
            break
        length = options_data[i + 1]
        if length < 2 or i + length > len(options_data):
            break
        if kind == TCP_OPT_MSS and length == 4:
            result["mss"] = struct.unpack(">H", options_data[i + 2 : i + 4])[0]
        i += length
    return result


def parse_tcp(
    data: bytes,
) -> tuple[int, int, int, int, int, bytes, dict] | None:
    """Parse TCP header.

    Returns:
        (src_port, dst_port, seq, ack, flags, payload, options_dict) or None
    """
    if len(data) < 20:
        return None

    src_port, dst_port = struct.unpack(">HH", data[0:4])
    seq, ack = struct.unpack(">II", data[4:12])
    data_offset = (data[12] >> 4) * 4
    flags = data[13]

    if len(data) < data_offset:
        return None

    # Parse options if header > 20 bytes
    options = {}
    if data_offset > 20:
        options = parse_tcp_options(data[20:data_offset])

    payload = data[data_offset:]
    return src_port, dst_port, seq, ack, flags, payload, options


# Flow Analysis


def extract_flows(packets: list[tuple[float, bytes]]) -> dict[tuple, TcpFlow]:
    """Extract TCP flows from parsed packets.

    Returns a dict mapping flow_key to TcpFlow objects.
    """
    flows: dict[tuple, TcpFlow] = {}

    base_timestamp = packets[0][0] if packets else 0

    for timestamp, packet_data in packets:
        eth_result = parse_ethernet(packet_data)
        if eth_result is None:
            continue
        ethertype, eth_payload = eth_result

        if ethertype == ETHERTYPE_IPV4:
            ip_result = parse_ipv4(eth_payload)
        elif ethertype == ETHERTYPE_IPV6:
            ip_result = parse_ipv6(eth_payload)
        else:
            continue

        if ip_result is None:
            continue
        src_ip, dst_ip, protocol, ip_payload = ip_result

        if protocol != IPPROTO_TCP:
            continue

        tcp_result = parse_tcp(ip_payload)
        if tcp_result is None:
            continue
        src_port, dst_port, seq, ack, flags, payload, options = tcp_result

        # Get or create flow
        flow_key = (src_ip, dst_ip, src_port, dst_port)
        if flow_key not in flows:
            flows[flow_key] = TcpFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
            )

        flow = flows[flow_key]

        # Extract MSS from SYN
        if flags & 0x02 and "mss" in options:  # SYN flag
            flow.mss = options["mss"]

        segment = TcpSegment(
            seq=seq,
            ack=ack,
            flags=flags,
            payload_len=len(payload),
            payload=payload,
            timestamp=timestamp - base_timestamp,
        )
        flow.segments.append(segment)

    return flows


def group_connections(flows: dict[tuple, TcpFlow]) -> list[tuple[TcpFlow | None, TcpFlow | None]]:
    """Group flows into connections (client->server, server->client pairs).

    Heuristic: The side that sends the first SYN is the client.
    """
    connections: list[tuple[TcpFlow | None, TcpFlow | None]] = []
    processed: set[tuple] = set()

    for flow_key, flow in flows.items():
        if flow_key in processed:
            continue

        # Find reverse flow
        reverse_key = flow.reverse_key
        reverse_flow = flows.get(reverse_key)

        # Determine which is client (sends first SYN)
        client_flow = flow
        server_flow = reverse_flow

        # Check for SYN in each flow
        flow_has_syn = any(s.is_syn and not s.is_ack for s in flow.segments)
        reverse_has_syn = reverse_flow and any(
            s.is_syn and not s.is_ack for s in reverse_flow.segments
        )

        if reverse_has_syn and not flow_has_syn:
            client_flow, server_flow = server_flow, client_flow

        connections.append((client_flow, server_flow))
        processed.add(flow_key)
        if reverse_key in flows:
            processed.add(reverse_key)

    return connections


# TLS Record Parsing


def reassemble_stream(flow: TcpFlow) -> bytes:
    """Reassemble TCP payload stream from segments.

    Simple reassembly: concatenate payloads in order received.
    For local netns captures, this should be sufficient.
    """
    # Sort segments by sequence number for proper ordering
    sorted_segments = sorted(flow.segments, key=lambda s: s.seq)
    return b"".join(s.payload for s in sorted_segments if s.payload_len > 0)


def parse_tls_records(stream: bytes, flow: TcpFlow) -> list[TlsRecord]:
    """Parse TLS record headers from reassembled stream.

    Also maps records to TCP segments.
    """
    records: list[TlsRecord] = []
    offset = 0

    # Build a map of byte offset -> segment index
    sorted_segments = sorted(
        [(i, s) for i, s in enumerate(flow.segments) if s.payload_len > 0],
        key=lambda x: x[1].seq,
    )

    byte_to_segment: list[int] = []
    for seg_idx, seg in sorted_segments:
        byte_to_segment.extend([seg_idx] * seg.payload_len)

    while offset + 5 <= len(stream):
        # TLS record header: content_type (1) + version (2) + length (2)
        content_type = stream[offset]
        version = struct.unpack(">H", stream[offset + 1 : offset + 3])[0]
        length = struct.unpack(">H", stream[offset + 3 : offset + 5])[0]

        # Validate content type
        if content_type not in (20, 21, 22, 23):
            break  # Not a valid TLS record

        # Validate length (max TLS record is 16KB + header overhead)
        if length > 18432:
            break

        # Stop if the record is incomplete.
        if offset + 5 + length > len(stream):
            break

        # Find which segments this record spans
        record_start = offset
        record_end = offset + 5 + length
        segment_indices: list[int] = []
        if byte_to_segment:
            for byte_offset in range(record_start, min(record_end, len(byte_to_segment))):
                seg_idx = byte_to_segment[byte_offset]
                if not segment_indices or segment_indices[-1] != seg_idx:
                    segment_indices.append(seg_idx)

        record = TlsRecord(
            content_type=content_type,
            version=version,
            length=length,
            offset=offset,
            segment_indices=segment_indices,
        )
        records.append(record)

        offset += 5 + length

    return records


# Metrics Computation


def compute_flow_metrics(flow: TcpFlow | None, direction: str) -> FlowMetrics | None:
    """Compute metrics for a single flow direction."""
    if flow is None:
        return None

    segments_with_payload = [s for s in flow.segments if s.payload_len > 0]
    payload_sizes = [s.payload_len for s in segments_with_payload]

    # Count full MSS segments
    mss = flow.mss
    full_mss_count = 0
    if mss:
        full_mss_count = sum(1 for size in payload_sizes if size >= mss - 1)

    # Parse TLS records
    stream = reassemble_stream(flow)
    tls_records = parse_tls_records(stream, flow)

    # Count records spanning multiple segments
    records_spanning = sum(1 for r in tls_records if len(r.segment_indices) > 1)

    return FlowMetrics(
        direction=direction,
        mss=mss,
        segment_count=len(flow.segments),
        segments_with_payload=len(segments_with_payload),
        total_payload_bytes=sum(payload_sizes),
        payload_sizes=payload_sizes,
        full_mss_segments=full_mss_count,
        max_payload_size=max(payload_sizes) if payload_sizes else 0,
        min_payload_size=min(payload_sizes) if payload_sizes else 0,
        tls_records=[
            {
                "content_type": r.content_type_name,
                "length": r.length,
                "segments_spanned": len(r.segment_indices),
            }
            for r in tls_records
        ],
        records_spanning_segments=records_spanning,
    )


def compute_connection_metrics(
    client_flow: TcpFlow | None, server_flow: TcpFlow | None
) -> ConnectionMetrics | None:
    """Compute metrics for a complete connection."""
    c2s = compute_flow_metrics(client_flow, "client_to_server")
    s2c = compute_flow_metrics(server_flow, "server_to_client")

    if c2s is None and s2c is None:
        return None

    # Create empty metrics if one direction is missing
    if c2s is None:
        c2s = FlowMetrics(
            direction="client_to_server",
            mss=None,
            segment_count=0,
            segments_with_payload=0,
            total_payload_bytes=0,
            payload_sizes=[],
            full_mss_segments=0,
            max_payload_size=0,
            min_payload_size=0,
            tls_records=[],
            records_spanning_segments=0,
        )
    if s2c is None:
        s2c = FlowMetrics(
            direction="server_to_client",
            mss=None,
            segment_count=0,
            segments_with_payload=0,
            total_payload_bytes=0,
            payload_sizes=[],
            full_mss_segments=0,
            max_payload_size=0,
            min_payload_size=0,
            tls_records=[],
            records_spanning_segments=0,
        )

    # Retransmission and out-of-order detection require sequence analysis.
    return ConnectionMetrics(
        client_to_server=c2s,
        server_to_client=s2c,
        handshake_segments_total=c2s.segments_with_payload + s2c.segments_with_payload,
        retransmissions=0,
        out_of_order=0,
    )


# Main Analysis Function


def analyze_pcap(
    pcap_path: str | Path,
    metadata_path: str | Path | None = None,
) -> PacketizationResult:
    """Analyze a PCAP file and produce packetization metrics.

    Args:
        pcap_path: Path to the PCAP file
        metadata_path: Optional path to metadata.json from capture script

    Returns:
        PacketizationResult with all computed metrics
    """
    pcap_path = Path(pcap_path)

    packets = parse_pcap(pcap_path)
    if not packets:
        raise ValueError(f"No packets found in {pcap_path}")

    timestamps = [t for t, _ in packets]
    capture_duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0

    # Extract flows and group into connections
    flows = extract_flows(packets)
    connections = group_connections(flows)

    # Compute per-connection metrics
    conn_metrics: list[ConnectionMetrics] = []
    for client_flow, server_flow in connections:
        metrics = compute_connection_metrics(client_flow, server_flow)
        if metrics:
            conn_metrics.append(metrics)

    kem_algo = None
    sig_algo = None
    mtu = None
    iterations = None
    cert_der_size = None
    openssl_version = None

    if metadata_path and Path(metadata_path).exists():
        with open(metadata_path) as f:
            metadata = json.load(f)
            capture_info = metadata.get("capture_info", {})
            kem_algo = capture_info.get("kem_algorithm")
            sig_algo = capture_info.get("sig_algorithm")
            mtu = capture_info.get("mtu")
            iterations = capture_info.get("iterations")
            cert_der_size = capture_info.get("cert_der_size_bytes")
            env = metadata.get("environment", {})
            openssl_version = env.get("openssl_version")

    # Aggregate statistics
    client_mss = None
    server_mss = None
    client_segments: list[int] = []
    server_segments: list[int] = []
    max_payload_exceeds_mss = False

    for conn in conn_metrics:
        if conn.client_to_server.mss:
            client_mss = conn.client_to_server.mss
        if conn.server_to_client.mss:
            server_mss = conn.server_to_client.mss

        client_segments.append(conn.client_to_server.segments_with_payload)
        server_segments.append(conn.server_to_client.segments_with_payload)

        # Check for offload artifacts
        c2s_mss = conn.client_to_server.mss or 1460
        s2c_mss = conn.server_to_client.mss or 1460
        if conn.client_to_server.max_payload_size > c2s_mss:
            max_payload_exceeds_mss = True
        if conn.server_to_client.max_payload_size > s2c_mss:
            max_payload_exceeds_mss = True

    # Check MSS vs MTU
    mss_matches_mtu = True
    if mtu and client_mss:
        expected_mss = mtu - 40  # IPv4 + TCP headers
        if abs(client_mss - expected_mss) > 12:  # Allow for TCP options
            mss_matches_mtu = False

    return PacketizationResult(
        pcap_file=str(pcap_path),
        analysis_timestamp=datetime.now().isoformat(),
        capture_duration_sec=capture_duration,
        kem_algorithm=kem_algo,
        sig_algorithm=sig_algo,
        mtu=mtu,
        iterations=iterations,
        cert_der_size_bytes=cert_der_size,
        openssl_version=openssl_version,
        connections=conn_metrics,
        client_mss=client_mss,
        server_mss=server_mss,
        avg_client_segments=(
            sum(client_segments) / len(client_segments) if client_segments else None
        ),
        avg_server_segments=(
            sum(server_segments) / len(server_segments) if server_segments else None
        ),
        max_payload_exceeds_mss=max_payload_exceeds_mss,
        mss_matches_mtu=mss_matches_mtu,
    )


# JSON Output


def result_to_dict(result: PacketizationResult) -> dict:
    """Convert PacketizationResult to a JSON-serializable dictionary."""

    def flow_metrics_to_dict(fm: FlowMetrics) -> dict:
        return {
            "direction": fm.direction,
            "mss": fm.mss,
            "segment_count": fm.segment_count,
            "segments_with_payload": fm.segments_with_payload,
            "total_payload_bytes": fm.total_payload_bytes,
            "payload_size_distribution": {
                "min": fm.min_payload_size,
                "max": fm.max_payload_size,
                "full_mss_count": fm.full_mss_segments,
            },
            "tls_records": fm.tls_records,
            "records_spanning_segments": fm.records_spanning_segments,
        }

    def conn_metrics_to_dict(cm: ConnectionMetrics) -> dict:
        return {
            "client_to_server": flow_metrics_to_dict(cm.client_to_server),
            "server_to_client": flow_metrics_to_dict(cm.server_to_client),
            "handshake_segments_total": cm.handshake_segments_total,
            "retransmissions": cm.retransmissions,
            "out_of_order": cm.out_of_order,
        }

    return {
        "metadata": {
            "pcap_file": result.pcap_file,
            "analysis_timestamp": result.analysis_timestamp,
            "capture_duration_sec": result.capture_duration_sec,
        },
        "test_parameters": {
            "kem_algorithm": result.kem_algorithm,
            "sig_algorithm": result.sig_algorithm,
            "mtu": result.mtu,
            "iterations": result.iterations,
            "cert_der_size_bytes": result.cert_der_size_bytes,
        },
        "environment": {
            "openssl_version": result.openssl_version,
        },
        "aggregated": {
            "client_mss": result.client_mss,
            "server_mss": result.server_mss,
            "avg_client_segments_with_payload": result.avg_client_segments,
            "avg_server_segments_with_payload": result.avg_server_segments,
            "connection_count": len(result.connections),
        },
        "validation": {
            "max_payload_exceeds_mss": result.max_payload_exceeds_mss,
            "mss_matches_mtu": result.mss_matches_mtu,
        },
        "connections": [conn_metrics_to_dict(c) for c in result.connections],
    }


def format_json(result: PacketizationResult, indent: int = 2) -> str:
    """Format result as JSON string."""
    return json.dumps(result_to_dict(result), indent=indent)


def format_text(result: PacketizationResult) -> str:
    """Format result as human-readable text."""
    lines = []
    lines.append("=" * 60)
    lines.append("Packetization Analysis Results")
    lines.append("=" * 60)
    lines.append("")

    # Test parameters
    lines.append("Test Parameters:")
    lines.append(f"  KEM Algorithm:    {result.kem_algorithm or 'N/A'}")
    lines.append(f"  Sig Algorithm:    {result.sig_algorithm or 'N/A'}")
    lines.append(f"  MTU:              {result.mtu or 'N/A'}")
    lines.append(f"  Iterations:       {result.iterations or 'N/A'}")
    lines.append(f"  Cert DER Size:    {result.cert_der_size_bytes or 'N/A'} bytes")
    lines.append("")

    # MSS and segment counts
    lines.append("Aggregated Metrics:")
    lines.append(f"  Client MSS:       {result.client_mss or 'N/A'}")
    lines.append(f"  Server MSS:       {result.server_mss or 'N/A'}")
    lines.append(f"  Connections:      {len(result.connections)}")
    if result.avg_client_segments:
        lines.append(f"  Avg Client Segs:  {result.avg_client_segments:.1f}")
    if result.avg_server_segments:
        lines.append(f"  Avg Server Segs:  {result.avg_server_segments:.1f}")
    lines.append("")

    # Validation
    lines.append("Validation:")
    if result.max_payload_exceeds_mss:
        lines.append("  WARNING: Payload > MSS detected (possible offload artifacts)")
    else:
        lines.append("  Payload sizes OK (none exceed MSS)")
    if not result.mss_matches_mtu:
        lines.append("  WARNING: MSS does not match expected MTU-40")
    else:
        lines.append("  MSS matches MTU expectations")
    lines.append("")

    # Per-connection summary
    if result.connections:
        lines.append("Connection Summary:")
        lines.append("-" * 60)
        for i, conn in enumerate(result.connections, 1):
            c2s = conn.client_to_server
            s2c = conn.server_to_client
            lines.append(f"  Connection {i}:")
            lines.append(
                f"    Client->Server: {c2s.segments_with_payload} segments, "
                f"{c2s.total_payload_bytes} bytes"
            )
            lines.append(
                f"    Server->Client: {s2c.segments_with_payload} segments, "
                f"{s2c.total_payload_bytes} bytes"
            )
            lines.append(f"    TLS Records (C->S): {len(c2s.tls_records)}")
            lines.append(f"    TLS Records (S->C): {len(s2c.tls_records)}")
            if s2c.records_spanning_segments:
                lines.append(f"    Records spanning 2+ segments: {s2c.records_spanning_segments}")

    return "\n".join(lines)


# CLI Entry Point (for standalone use)


def main() -> None:
    """Command-line interface for standalone pcap analysis."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Analyze TLS handshake pcap for packetization metrics"
    )
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument(
        "-m",
        "--metadata",
        help="Path to metadata.json from capture script",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    args = parser.parse_args()

    try:
        result = analyze_pcap(args.pcap_file, args.metadata)

        output = format_json(result) if args.format == "json" else format_text(result)

        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Results written to {args.output}")
        else:
            print(output)

    except Exception as e:
        print(f"Error: {e}", file=__import__("sys").stderr)
        __import__("sys").exit(1)


if __name__ == "__main__":
    main()
