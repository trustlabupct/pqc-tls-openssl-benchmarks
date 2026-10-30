"""Tests for TLS handshake output parsing."""

from pqc_bench.parsers.handshake import (
    HandshakeResult,
    HandshakeSummary,
    extract_tls_info,
    parse_handshake_output,
    parse_handshake_output_with_summary,
    parse_result_line,
    parse_tls_info_line,
)


class TestParseHandshakeOutput:
    """Tests for parse_handshake_output function."""

    def test_empty_output(self):
        """Empty output returns empty list."""
        assert parse_handshake_output("") == []

    def test_single_handshake(self):
        """Parse single handshake timing."""
        output = "handshake 1: 12345 us"
        results = parse_handshake_output(output)
        assert len(results) == 1
        assert results[0].iteration == 1
        assert results[0].duration_us == 12345.0

    def test_multiple_handshakes(self):
        """Parse multiple handshake timings."""
        output = """---
handshake 1: 12345 us
handshake 2: 11234 us
handshake 3: 11567 us
---"""
        results = parse_handshake_output(output)
        assert len(results) == 3
        assert results[0].iteration == 1
        assert results[0].duration_us == 12345.0
        assert results[1].iteration == 2
        assert results[1].duration_us == 11234.0
        assert results[2].iteration == 3
        assert results[2].duration_us == 11567.0

    def test_fractional_microseconds(self):
        """Parse handshake with fractional microseconds."""
        output = "handshake 5: 12345.67 us"
        results = parse_handshake_output(output)
        assert len(results) == 1
        assert results[0].duration_us == 12345.67

    def test_case_insensitive(self):
        """Pattern matching is case insensitive."""
        output = "HANDSHAKE 1: 12345 US"
        results = parse_handshake_output(output)
        assert len(results) == 1
        assert results[0].duration_us == 12345.0

    def test_ignores_other_lines(self):
        """Non-handshake lines are ignored."""
        output = """Running TLS 1.3 handshakes with mlkem768...
---
handshake 1: 12345 us
Error: Handshake 2 failed
handshake 3: 11234 us
---
RESULT: success=2 fail=1 total=3"""
        results = parse_handshake_output(output)
        assert len(results) == 2
        assert results[0].iteration == 1
        assert results[1].iteration == 3

    def test_microseconds_variant(self):
        """Parse 'microseconds' instead of 'us'."""
        output = "handshake 1: 12345 microseconds"
        results = parse_handshake_output(output)
        assert len(results) == 1
        assert results[0].duration_us == 12345.0


class TestParseResultLine:
    """Tests for parse_result_line function."""

    def test_no_result_line(self):
        """Returns None when no RESULT line present."""
        output = "handshake 1: 12345 us"
        assert parse_result_line(output) is None

    def test_basic_result_line(self):
        """Parse basic RESULT line."""
        output = "RESULT: success=10 fail=0 total=10"
        result = parse_result_line(output)
        assert result == (10, 0, 10)

    def test_result_with_failures(self):
        """Parse RESULT line with failures."""
        output = "RESULT: success=87 fail=13 total=100"
        result = parse_result_line(output)
        assert result == (87, 13, 100)

    def test_result_in_multiline_output(self):
        """Find RESULT line in larger output."""
        output = """---
handshake 1: 12345 us
handshake 2: 11234 us
---
RESULT: success=2 fail=0 total=2
Completed: 2/2 successful handshakes"""
        result = parse_result_line(output)
        assert result == (2, 0, 2)

    def test_case_insensitive(self):
        """RESULT matching is case insensitive."""
        output = "result: success=5 fail=2 total=7"
        result = parse_result_line(output)
        assert result == (5, 2, 7)


class TestParseTlsInfoLine:
    """Tests for parse_tls_info_line function."""

    def test_no_tls_info(self):
        """Returns None when no TLS_INFO line present."""
        output = "handshake 1: 12345 us"
        assert parse_tls_info_line(output) is None

    def test_basic_tls_info(self):
        """Parse basic TLS_INFO line."""
        output = (
            "TLS_INFO: protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 group=mlkem768 sig=mldsa65"
        )
        result = parse_tls_info_line(output)
        assert result is not None
        assert result["protocol"] == "TLSv1.3"
        assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
        assert result["key_exchange"] == "mlkem768"
        assert result["signature"] == "mldsa65"

    def test_hybrid_group(self):
        """Parse TLS_INFO with hybrid group name."""
        output = (
            "TLS_INFO: protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 "
            "group=X25519MLKEM768 sig=mldsa65"
        )
        result = parse_tls_info_line(output)
        assert result is not None
        assert result["key_exchange"] == "X25519MLKEM768"

    def test_group_with_spaces(self):
        """Parse TLS_INFO with group containing descriptive text."""
        output = (
            "TLS_INFO: protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 "
            "group=X25519 (253 bits) sig=mldsa65"
        )
        result = parse_tls_info_line(output)
        assert result is not None
        assert result["key_exchange"] is not None
        assert "X25519" in result["key_exchange"]

    def test_unknown_values_become_none(self):
        """Unknown values are converted to None."""
        output = "TLS_INFO: protocol=unknown cipher=unknown group=unknown sig=unknown"
        result = parse_tls_info_line(output)
        assert result is not None
        assert result["protocol"] is None
        assert result["cipher"] is None
        assert result["key_exchange"] is None
        assert result["signature"] is None

    def test_tls_info_in_multiline_output(self):
        """Find TLS_INFO line in larger output."""
        output = """---
handshake 1: 12345 us
TLS_INFO: protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 group=mlkem768 sig=mldsa65
handshake 2: 11234 us
---"""
        result = parse_tls_info_line(output)
        assert result is not None
        assert result["protocol"] == "TLSv1.3"


class TestExtractTlsInfo:
    """Tests for extract_tls_info function (raw s_client output)."""

    def test_empty_output(self):
        """Empty output returns all None values."""
        result = extract_tls_info("")
        assert result["protocol"] is None
        assert result["cipher"] is None
        assert result["key_exchange"] is None
        assert result["signature"] is None

    def test_full_s_client_output(self):
        """Parse realistic s_client output."""
        output = """CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:CN = localhost
   i:CN = localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
... (certificate data) ...
-----END CERTIFICATE-----
subject=CN = localhost
issuer=CN = localhost
---
No client certificate CA names sent
Peer signature type: mldsa65
Server Temp Key: X25519, 253 bits
---
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
---"""
        result = extract_tls_info(output)
        assert result["protocol"] == "TLSv1.3"
        assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
        assert result["key_exchange"] == "X25519,"  # Note: captures until space
        assert result["signature"] == "mldsa65"


class TestParseHandshakeOutputWithSummary:
    """Tests for parse_handshake_output_with_summary function."""

    def test_empty_output(self):
        """Empty output returns empty summary."""
        summary = parse_handshake_output_with_summary("")
        assert len(summary.results) == 0
        assert summary.success_count == 0
        assert summary.fail_count == 0
        assert summary.total_count == 0
        assert summary.first_handshake_info is None

    def test_full_output_no_failures(self):
        """Parse complete output with no failures."""
        output = """---
handshake 1: 12345 us
TLS_INFO: protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 group=mlkem768 sig=mldsa65
handshake 2: 11234 us
handshake 3: 11567 us
---
RESULT: success=3 fail=0 total=3"""
        summary = parse_handshake_output_with_summary(output)

        assert len(summary.results) == 3
        assert summary.success_count == 3
        assert summary.fail_count == 0
        assert summary.total_count == 3
        assert summary.first_handshake_info is not None
        assert summary.first_handshake_info["protocol"] == "TLSv1.3"
        assert summary.first_handshake_info["key_exchange"] == "mlkem768"

    def test_output_with_failures(self):
        """Parse output with some failures."""
        output = """---
handshake 1: 12345 us
TLS_INFO: protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 group=mlkem768 sig=mldsa65
handshake 3: 11567 us
handshake 5: 11890 us
---
RESULT: success=3 fail=2 total=5"""
        summary = parse_handshake_output_with_summary(output)

        # Only 3 results parsed (failures don't produce timing lines)
        assert len(summary.results) == 3
        assert summary.success_count == 3
        assert summary.fail_count == 2
        assert summary.total_count == 5

    def test_legacy_output_no_result_line(self):
        """Handle legacy output without RESULT line."""
        output = """---
handshake 1: 12345 us
handshake 2: 11234 us
---"""
        summary = parse_handshake_output_with_summary(output)

        # Fallback behavior: infer counts from parsed results
        assert len(summary.results) == 2
        assert summary.success_count == 2
        assert summary.fail_count == 0
        assert summary.total_count == 2

    def test_high_failure_rate(self):
        """Parse output with high failure rate."""
        output = """---
handshake 1: 12345 us
TLS_INFO: protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 group=mlkem768 sig=mldsa65
---
RESULT: success=1 fail=9 total=10"""
        summary = parse_handshake_output_with_summary(output)

        assert len(summary.results) == 1
        assert summary.success_count == 1
        assert summary.fail_count == 9
        assert summary.total_count == 10


class TestHandshakeSummaryDataclass:
    """Tests for HandshakeSummary dataclass."""

    def test_creation(self):
        """HandshakeSummary can be created with all fields."""
        results = [HandshakeResult(iteration=1, duration_us=12345.0)]
        tls_info: dict[str, str | None] = {
            "protocol": "TLSv1.3",
            "cipher": "AES",
            "key_exchange": "X25519",
            "signature": "mldsa65",
        }

        summary = HandshakeSummary(
            results=results,
            success_count=1,
            fail_count=0,
            total_count=1,
            first_handshake_info=tls_info,
        )

        assert len(summary.results) == 1
        assert summary.first_handshake_info is not None
        assert summary.first_handshake_info["protocol"] == "TLSv1.3"

    def test_first_handshake_info_optional(self):
        """first_handshake_info can be None."""
        summary = HandshakeSummary(
            results=[],
            success_count=0,
            fail_count=0,
            total_count=0,
            first_handshake_info=None,
        )
        assert summary.first_handshake_info is None
