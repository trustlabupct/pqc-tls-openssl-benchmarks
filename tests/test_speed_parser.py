"""Tests for OpenSSL speed output parser."""

import pytest

from pqc_bench.parsers.speed import (
    _parse_detailed_output,
    _parse_machine_readable,
    _parse_summary_table,
    get_algorithm_sizes,
    parse_speed_output,
)


class TestMachineReadableParser:
    """Tests for -mr (machine readable) output format parser."""

    def test_oqs_provider_format(self):
        """Parse oqs-provider machine readable format (+DTP/+R)."""
        output = """Doing mlkem768 keygen ops for 3s:
+DTP:mlkem768:keygen:1
+R15:63850:mlkem768:1.00
+DTP:mlkem768:encaps:1
+R16:68545:mlkem768:0.99
+DTP:mlkem768:decaps:1
+R17:58234:mlkem768:1.01
"""
        results = _parse_machine_readable(output)

        assert len(results) == 3

        keygen = next(r for r in results if r.operation == "keygen")
        assert keygen.algorithm == "mlkem768"
        assert keygen.ops_count == 63850
        assert keygen.duration_sec == 1.00
        assert keygen.ops_per_sec == pytest.approx(63850.0)

        encaps = next(r for r in results if r.operation == "encaps")
        assert encaps.ops_count == 68545

        decaps = next(r for r in results if r.operation == "decaps")
        assert decaps.ops_count == 58234

    def test_signature_with_signs_normalization(self):
        """Parse signature output with 'signs' normalized to 'sign'."""
        output = """Doing mldsa65 keygen ops for 3s:
+DTP:mldsa65:keygen:1
+R10:19234:mldsa65:1.00
+DTP:mldsa65:signs:1
+R11:8456:mldsa65:1.00
+DTP:mldsa65:verify:1
+R12:22345:mldsa65:1.00
"""
        results = _parse_machine_readable(output)

        assert len(results) == 3
        operations = {r.operation for r in results}
        assert operations == {"keygen", "sign", "verify"}  # 'signs' -> 'sign'

    def test_hyphenated_algorithm_name(self):
        """Parse algorithm names with hyphens (e.g., ML-KEM-768)."""
        output = """+DTP:ML-KEM-768:keygen:1
+R15:63850:ML-KEM-768:1.00
"""
        results = _parse_machine_readable(output)

        assert len(results) == 1
        assert results[0].algorithm == "ML-KEM-768"

    def test_plus_in_algorithm_name(self):
        """Parse algorithm names with plus signs (e.g., SPHINCS+)."""
        output = """+DTP:SPHINCS+-SHA2-128f:keygen:1
+R15:1234:SPHINCS+-SHA2-128f:1.00
"""
        results = _parse_machine_readable(output)

        assert len(results) == 1
        assert results[0].algorithm == "SPHINCS+-SHA2-128f"

    def test_standard_openssl_format(self):
        """Parse standard OpenSSL -mr format (+F lines)."""
        output = """+F:0:mlkem768:keygen:63850:1.00
+F:1:mlkem768:encaps:68545:0.99
+F:2:mlkem768:decaps:58234:1.01
"""
        results = _parse_machine_readable(output)

        assert len(results) == 3
        assert all(r.algorithm == "mlkem768" for r in results)

    def test_empty_output(self):
        """Empty output returns empty list."""
        assert _parse_machine_readable("") == []
        assert _parse_machine_readable("\n\n") == []

    def test_malformed_lines_skipped(self):
        """Malformed lines are skipped gracefully."""
        output = """Some random text
+DTP:mlkem768:keygen:1
Invalid line here
+R15:63850:mlkem768:1.00
More garbage
"""
        results = _parse_machine_readable(output)

        # Should still parse the valid result
        assert len(results) == 1
        assert results[0].operation == "keygen"


class TestDetailedOutputParser:
    """Tests for detailed (non-mr) output format parser."""

    def test_basic_kem_output(self):
        """Parse basic KEM detailed output."""
        output = """Doing mlkem768 KEM keygen ops for 3s: 132077 mlkem768 KEM keygen ops in 2.98s
Doing mlkem768 KEM encaps ops for 3s: 145234 mlkem768 KEM encaps ops in 3.00s
Doing mlkem768 KEM decaps ops for 3s: 121456 mlkem768 KEM decaps ops in 2.99s
"""
        results = _parse_detailed_output(output)

        assert len(results) == 3
        operations = {r.operation for r in results}
        assert operations == {"keygen", "encaps", "decaps"}

        keygen = next(r for r in results if r.operation == "keygen")
        assert keygen.algorithm == "mlkem768"
        assert keygen.ops_count == 132077
        assert keygen.duration_sec == pytest.approx(2.98)

    def test_signature_output(self):
        """Parse signature detailed output."""
        output = """12345 mldsa65 sign ops in 3.00s
22345 mldsa65 verify ops in 3.00s
"""
        results = _parse_detailed_output(output)

        assert len(results) == 2
        operations = {r.operation for r in results}
        assert operations == {"sign", "verify"}

    def test_hyphenated_algorithm(self):
        """Parse hyphenated algorithm names."""
        output = """12345 ML-KEM-768 keygen ops in 3.00s
"""
        results = _parse_detailed_output(output)

        assert len(results) == 1
        assert results[0].algorithm == "ML-KEM-768"

    def test_sphincs_plus(self):
        """Parse SPHINCS+ algorithm names with plus sign."""
        output = """1234 SPHINCS+-SHA2-128f sign ops in 3.00s
"""
        results = _parse_detailed_output(output)

        assert len(results) == 1
        assert results[0].algorithm == "SPHINCS+-SHA2-128f"


class TestSummaryTableParser:
    """Tests for summary table output format parser."""

    def test_kem_summary_table(self):
        """Parse KEM summary table output."""
        output = """                   keygen    encaps    decaps keygens/s  encaps/s  decaps/s
            mlkem768 0.000015s 0.000014s 0.000016s   66666.7   71428.6   62500.0
"""
        results = _parse_summary_table(output, duration_hint=3.0)

        assert len(results) == 3
        operations = {r.operation for r in results}
        assert operations == {"keygen", "encaps", "decaps"}

    def test_signature_summary_table(self):
        """Parse signature summary table output."""
        output = """                   keygen      sign    verify keygens/s    sign/s  verify/s
             mldsa65 0.000050s 0.000120s 0.000045s   20000.0    8333.3   22222.2
"""
        results = _parse_summary_table(output, duration_hint=3.0)

        assert len(results) == 3
        operations = {r.operation for r in results}
        assert operations == {"keygen", "sign", "verify"}


class TestParseSpeedOutput:
    """Tests for the main parse_speed_output function."""

    def test_prefers_machine_readable(self):
        """Machine readable format is preferred when present."""
        output = """+DTP:mlkem768:keygen:1
+R15:63850:mlkem768:1.00
Some other text that might confuse other parsers
"""
        results = parse_speed_output(output)

        assert len(results) == 1
        assert results[0].operation == "keygen"

    def test_falls_back_to_detailed(self):
        """Falls back to detailed parser when -mr not present."""
        output = """132077 mlkem768 keygen ops in 2.98s
"""
        results = parse_speed_output(output)

        assert len(results) == 1
        assert results[0].operation == "keygen"

    def test_calculates_ops_per_sec(self):
        """ops_per_sec is calculated correctly."""
        output = """+DTP:mlkem768:keygen:1
+R15:100000:mlkem768:1.00
"""
        results = parse_speed_output(output)

        assert len(results) == 1
        assert results[0].ops_per_sec == pytest.approx(100000.0)
        assert results[0].us_per_op == pytest.approx(10.0)  # 1_000_000 / 100_000


class TestGetAlgorithmSizes:
    """Tests for hardcoded algorithm size lookup."""

    def test_known_kem_sizes(self):
        """Known KEM sizes are returned correctly."""
        sizes = get_algorithm_sizes("mlkem768", is_kem=True)

        assert sizes["public_key_bytes"] == 1184
        assert sizes["secret_key_bytes"] == 2400
        assert sizes["ciphertext_bytes"] == 1088
        assert sizes["source"] == "fallback"

    def test_known_sig_sizes(self):
        """Known signature sizes are returned correctly."""
        sizes = get_algorithm_sizes("mldsa65", is_kem=False)

        assert sizes["public_key_bytes"] == 1952
        assert sizes["secret_key_bytes"] == 4032
        assert sizes["signature_bytes"] == 3309
        assert sizes["source"] == "fallback"

    def test_unknown_algorithm(self):
        """Unknown algorithm returns None values."""
        sizes = get_algorithm_sizes("unknown_algo", is_kem=True)

        assert sizes["public_key_bytes"] is None
        assert sizes["source"] == "unknown"
