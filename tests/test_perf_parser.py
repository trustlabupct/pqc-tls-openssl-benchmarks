"""Tests for perf stat output parser."""

import pytest

from pqc_bench.models import PerfMetrics
from pqc_bench.runner import _parse_perf_output


class TestPerfParser:
    """Tests for _parse_perf_output function."""

    def test_basic_perf_output(self):
        """Parse basic perf stat output."""
        output = """
 Performance counter stats for './benchmark':

     1,234,567,890      cycles
       987,654,321      instructions              #    0.80  insn per cycle
           123,456      cache-misses
            12,345      branch-misses

       1.234567890 seconds time elapsed
"""
        metrics = _parse_perf_output(output)

        assert metrics.cycles == 1234567890
        assert metrics.instructions == 987654321
        assert metrics.ipc == pytest.approx(0.80)
        assert metrics.cache_misses == 123456
        assert metrics.branch_misses == 12345

    def test_german_locale_periods(self):
        """Parse perf output with period as thousands separator (German locale)."""
        output = """
 Performance counter stats for './benchmark':

     1.234.567.890      cycles
       987.654.321      instructions              #    0,80  insn per cycle
           123.456      cache-misses
            12.345      branch-misses
"""
        metrics = _parse_perf_output(output)

        assert metrics.cycles == 1234567890
        assert metrics.instructions == 987654321
        assert metrics.ipc == pytest.approx(0.80)
        assert metrics.cache_misses == 123456
        assert metrics.branch_misses == 12345

    def test_space_as_thousands_separator(self):
        """Parse perf output with space as thousands separator."""
        output = """
 Performance counter stats for './benchmark':

     1 234 567 890      cycles
       987 654 321      instructions              #    0.80  insn per cycle
"""
        metrics = _parse_perf_output(output)

        assert metrics.cycles == 1234567890
        assert metrics.instructions == 987654321

    def test_apostrophe_as_thousands_separator(self):
        """Parse perf output with apostrophe as thousands separator (Swiss locale)."""
        output = """
     1'234'567'890      cycles
       987'654'321      instructions              #    0.80  insn per cycle
"""
        metrics = _parse_perf_output(output)

        assert metrics.cycles == 1234567890
        assert metrics.instructions == 987654321

    def test_not_counted_values_skipped(self):
        """<not counted> values are skipped gracefully."""
        output = """
     1,234,567,890      cycles
         <not counted>  instructions
           <not counted>  cache-misses
            12,345      branch-misses
"""
        metrics = _parse_perf_output(output)

        assert metrics.cycles == 1234567890
        assert metrics.instructions is None  # Skipped
        assert metrics.cache_misses is None  # Skipped
        assert metrics.branch_misses == 12345

    def test_not_supported_values_skipped(self):
        """<not supported> values are skipped gracefully."""
        output = """
     1,234,567,890      cycles
       <not supported>  instructions
"""
        metrics = _parse_perf_output(output)

        assert metrics.cycles == 1234567890
        assert metrics.instructions is None

    def test_na_values_skipped(self):
        """N/A values are skipped gracefully."""
        output = """
     1,234,567,890      cycles
               N/A      instructions
"""
        metrics = _parse_perf_output(output)

        assert metrics.cycles == 1234567890
        assert metrics.instructions is None

    def test_empty_output(self):
        """Empty output returns PerfMetrics with all None values."""
        metrics = _parse_perf_output("")

        assert metrics.cycles is None
        assert metrics.instructions is None
        assert metrics.ipc is None
        assert metrics.cache_misses is None
        assert metrics.branch_misses is None

    def test_partial_output(self):
        """Partial output (missing some metrics) is parsed correctly."""
        output = """
     1,234,567,890      cycles
"""
        metrics = _parse_perf_output(output)

        assert metrics.cycles == 1234567890
        assert metrics.instructions is None
        assert metrics.cache_misses is None

    def test_ipc_with_comma_decimal(self):
        """IPC with comma as decimal separator (European locale)."""
        output = """
       987,654,321      instructions              #    1,23  insn per cycle
"""
        metrics = _parse_perf_output(output)

        assert metrics.ipc == pytest.approx(1.23)

    def test_instructions_without_ipc(self):
        """Instructions line without IPC annotation."""
        output = """
       987,654,321      instructions
"""
        metrics = _parse_perf_output(output)

        assert metrics.instructions == 987654321
        assert metrics.ipc is None

    def test_real_perf_output(self):
        """Parse real perf stat output from Linux."""
        output = """
 Performance counter stats for 'openssl speed -mr mlkem768':

        45,678,901      cycles
        23,456,789      instructions                     #    0.51  insn per cycle
             5,432      cache-misses
             1,234      branch-misses

       0.023456789 seconds time elapsed

       0.019876543 seconds user
       0.003579246 seconds sys
"""
        metrics = _parse_perf_output(output)

        assert metrics.cycles == 45678901
        assert metrics.instructions == 23456789
        assert metrics.ipc == pytest.approx(0.51)
        assert metrics.cache_misses == 5432
        assert metrics.branch_misses == 1234


class TestPerfMetricsToDict:
    """Tests for PerfMetrics.to_dict() method."""

    def test_full_metrics(self):
        """All metrics present are included in dict."""
        metrics = PerfMetrics(
            cycles=1000000,
            instructions=800000,
            ipc=0.8,
            cache_misses=100,
            branch_misses=50,
        )
        d = metrics.to_dict()

        assert d == {
            "cycles": 1000000,
            "instructions": 800000,
            "ipc": 0.8,
            "cache_misses": 100,
            "branch_misses": 50,
        }

    def test_partial_metrics(self):
        """Only non-None metrics are included in dict."""
        metrics = PerfMetrics(
            cycles=1000000,
            instructions=None,
            ipc=None,
            cache_misses=100,
            branch_misses=None,
        )
        d = metrics.to_dict()

        assert d == {
            "cycles": 1000000,
            "cache_misses": 100,
        }

    def test_empty_metrics(self):
        """All None metrics returns empty dict."""
        metrics = PerfMetrics()
        d = metrics.to_dict()

        assert d == {}
