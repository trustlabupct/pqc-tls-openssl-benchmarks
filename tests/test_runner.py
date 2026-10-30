"""Integration tests for the runner module with mocked subprocess."""

from unittest.mock import MagicMock, patch

import pytest

from pqc_bench.models import Operation
from pqc_bench.runner import (
    BenchmarkConfig,
    SingleRunResult,
    _aggregate_samples_to_results,
    _run_openssl_speed_once,
    _run_openssl_speed_samples,
)

# Sample machine-readable output from oqs-provider
SAMPLE_MR_OUTPUT_STDOUT = """+DTP:mlkem768:keygen:1
+R15:63850:mlkem768:1.00
+DTP:mlkem768:encaps:1
+R16:68545:mlkem768:0.99
+DTP:mlkem768:decaps:1
+R17:54321:mlkem768:1.01
"""

# Same output but in stderr (some OpenSSL/provider versions do this)
SAMPLE_MR_OUTPUT_STDERR = SAMPLE_MR_OUTPUT_STDOUT

# Sample perf stat output
SAMPLE_PERF_OUTPUT = """
 Performance counter stats for 'openssl speed -mr mlkem768':

     1,234,567,890      cycles                    #    3.456 GHz
       987,654,321      instructions              #    0.80  insn per cycle
         1,234,567      cache-misses
           123,456      branch-misses

       0.357213405 seconds time elapsed
"""


class TestRunOpensslSpeedOnce:
    """Tests for _run_openssl_speed_once with mocked subprocess."""

    @patch("pqc_bench.runner.subprocess.run")
    @patch("pqc_bench.runner._check_perf_available")
    def test_direct_mode_stdout_only(self, mock_perf_check, mock_run):
        """Direct mode parses output from stdout when no perf."""
        mock_perf_check.return_value = False
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=SAMPLE_MR_OUTPUT_STDOUT,
            stderr="",
        )

        config = BenchmarkConfig(include_perf=False)
        success, output, perf_metrics = _run_openssl_speed_once("mlkem768", config)

        assert success is True
        assert "+DTP:mlkem768:keygen" in output
        assert perf_metrics is None

    @patch("pqc_bench.runner.subprocess.run")
    @patch("pqc_bench.runner._check_perf_available")
    def test_direct_mode_output_in_stderr(self, mock_perf_check, mock_run):
        """Direct mode handles -mr output in stderr (without perf)."""
        mock_perf_check.return_value = False
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr=SAMPLE_MR_OUTPUT_STDERR,
        )

        config = BenchmarkConfig(include_perf=False)
        success, output, perf_metrics = _run_openssl_speed_once("mlkem768", config)

        assert success is True
        # Combined output should include stderr content
        assert "+DTP:mlkem768:keygen" in output

    @patch("pqc_bench.runner.subprocess.run")
    @patch("pqc_bench.runner._check_perf_available")
    def test_direct_mode_with_perf_stdout(self, mock_perf_check, mock_run):
        """Direct mode + perf: speed output in stdout, perf in stderr."""
        mock_perf_check.return_value = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=SAMPLE_MR_OUTPUT_STDOUT,
            stderr=SAMPLE_PERF_OUTPUT,
        )

        config = BenchmarkConfig(include_perf=True)
        success, output, perf_metrics = _run_openssl_speed_once("mlkem768", config)

        assert success is True
        assert "+DTP:mlkem768:keygen" in output
        assert perf_metrics is not None
        assert perf_metrics.cycles == 1234567890
        assert perf_metrics.instructions == 987654321

    @patch("pqc_bench.runner.subprocess.run")
    @patch("pqc_bench.runner._check_perf_available")
    def test_direct_mode_with_perf_stderr_only(self, mock_perf_check, mock_run):
        """Direct mode + perf: speed output in stderr (nasty case)."""
        # This is the problematic case: -mr output goes to stderr,
        # and perf also writes to stderr
        mock_perf_check.return_value = True
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr=SAMPLE_MR_OUTPUT_STDERR + SAMPLE_PERF_OUTPUT,
        )

        config = BenchmarkConfig(include_perf=True)
        success, output, perf_metrics = _run_openssl_speed_once("mlkem768", config)

        assert success is True
        # Combined output should include speed results
        assert "+DTP:mlkem768:keygen" in output
        # Perf metrics should still be parsed
        assert perf_metrics is not None
        assert perf_metrics.cycles == 1234567890

    @patch("pqc_bench.runner.subprocess.run")
    @patch("pqc_bench.runner._check_perf_available")
    def test_direct_mode_nonzero_exit(self, mock_perf_check, mock_run):
        """Non-zero exit code returns failure."""
        mock_perf_check.return_value = False
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Error: algorithm not found",
        )

        config = BenchmarkConfig(include_perf=False)
        success, output, perf_metrics = _run_openssl_speed_once("unknown_algo", config)

        assert success is False
        assert "algorithm not found" in output
        assert perf_metrics is None

    @patch("pqc_bench.runner.subprocess.run")
    @patch("pqc_bench.runner._check_perf_available")
    def test_timeout_handling(self, mock_perf_check, mock_run):
        """Timeout is handled gracefully."""
        import subprocess

        mock_perf_check.return_value = False
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="openssl", timeout=300)

        config = BenchmarkConfig(timeout=300)
        success, output, perf_metrics = _run_openssl_speed_once("mlkem768", config)

        assert success is False
        assert "Timeout" in output
        assert "300" in output


class TestRunOpensslSpeedSamples:
    """Tests for _run_openssl_speed_samples with mocked subprocess."""

    @patch("pqc_bench.runner._run_openssl_speed_once")
    def test_warmup_discarded(self, mock_run_once):
        """Warm-up runs are discarded."""
        # Return success for all runs
        mock_run_once.return_value = (True, SAMPLE_MR_OUTPUT_STDOUT, None)

        config = BenchmarkConfig(samples=3, warm_up=2)
        samples, perf, error = _run_openssl_speed_samples(
            "mlkem768", config, expected_ops={"keygen", "encaps", "decaps"}
        )

        assert error is None
        # 2 warm-up + 3 samples = 5 total calls
        assert mock_run_once.call_count == 5
        # Only 3 samples returned (warm-ups discarded)
        assert len(samples) == 3

    @patch("pqc_bench.runner._run_openssl_speed_once")
    def test_error_during_warmup(self, mock_run_once):
        """Error during warm-up aborts the run."""
        mock_run_once.return_value = (False, "Provider error", None)

        config = BenchmarkConfig(samples=3, warm_up=2)
        samples, perf, error = _run_openssl_speed_samples("mlkem768", config)

        assert error == "Provider error"
        assert samples == []

    @patch("pqc_bench.runner._run_openssl_speed_once")
    def test_missing_expected_ops(self, mock_run_once):
        """Missing expected operations returns error."""
        # Output only has keygen, missing encaps and decaps
        partial_output = """+DTP:mlkem768:keygen:1
+R15:63850:mlkem768:1.00
"""
        mock_run_once.return_value = (True, partial_output, None)

        config = BenchmarkConfig(samples=1, warm_up=0)
        samples, perf, error = _run_openssl_speed_samples(
            "mlkem768", config, expected_ops={"keygen", "encaps", "decaps"}
        )

        assert error is not None
        assert "missing operations" in error.lower()

    @patch("pqc_bench.runner._run_openssl_speed_once")
    def test_perf_metrics_collected(self, mock_run_once):
        """Perf metrics are collected from each sample."""
        from pqc_bench.models import PerfMetrics

        perf1 = PerfMetrics(cycles=1000000, instructions=800000)
        perf2 = PerfMetrics(cycles=1100000, instructions=850000)
        perf3 = PerfMetrics(cycles=1050000, instructions=820000)

        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            # First 2 calls are warm-up
            if call_count[0] <= 2:
                return (True, SAMPLE_MR_OUTPUT_STDOUT, None)
            # Next 3 are samples with perf
            perf = [perf1, perf2, perf3][call_count[0] - 3]
            return (True, SAMPLE_MR_OUTPUT_STDOUT, perf)

        mock_run_once.side_effect = side_effect

        config = BenchmarkConfig(samples=3, warm_up=2, include_perf=True)
        samples, perf_metrics, error = _run_openssl_speed_samples(
            "mlkem768", config, expected_ops={"keygen", "encaps", "decaps"}
        )

        assert error is None
        assert len(samples) == 3
        assert len(perf_metrics) == 3
        assert perf_metrics[0].cycles == 1000000
        assert perf_metrics[2].cycles == 1050000


class TestAggregateSamplesToResults:
    """Tests for _aggregate_samples_to_results."""

    def test_empty_samples(self):
        """Empty samples returns empty results."""
        results = _aggregate_samples_to_results([], "mlkem768")
        assert results == []

    def test_single_sample(self):
        """Single sample produces results."""
        samples = [
            [
                SingleRunResult(
                    operation="keygen", us_per_op=15.5, ops_per_sec=64516.0, ops_count=193548
                ),
                SingleRunResult(
                    operation="encaps", us_per_op=14.5, ops_per_sec=68966.0, ops_count=206897
                ),
                SingleRunResult(
                    operation="decaps", us_per_op=18.5, ops_per_sec=54054.0, ops_count=162162
                ),
            ]
        ]

        results = _aggregate_samples_to_results(samples, "mlkem768")

        assert len(results) == 3
        ops = {r.operation for r in results}
        assert ops == {Operation.KEYGEN, Operation.ENCAPS, Operation.DECAPS}

        keygen = next(r for r in results if r.operation == Operation.KEYGEN)
        assert keygen.median_us == 15.5
        assert keygen.sample_count == 1

    def test_multiple_samples_percentiles(self):
        """Multiple samples compute correct percentiles."""
        # 5 samples with varying keygen times
        samples = [
            [
                SingleRunResult(
                    operation="keygen", us_per_op=15.0, ops_per_sec=66666.7, ops_count=200000
                )
            ],
            [
                SingleRunResult(
                    operation="keygen", us_per_op=16.0, ops_per_sec=62500.0, ops_count=187500
                )
            ],
            [
                SingleRunResult(
                    operation="keygen", us_per_op=14.0, ops_per_sec=71428.6, ops_count=214286
                )
            ],
            [
                SingleRunResult(
                    operation="keygen", us_per_op=17.0, ops_per_sec=58823.5, ops_count=176471
                )
            ],
            [
                SingleRunResult(
                    operation="keygen", us_per_op=15.5, ops_per_sec=64516.1, ops_count=193548
                )
            ],
        ]

        results = _aggregate_samples_to_results(samples, "mlkem768")

        assert len(results) == 1
        keygen = results[0]
        assert keygen.operation == Operation.KEYGEN
        assert keygen.sample_count == 5
        # Sorted: [14.0, 15.0, 15.5, 16.0, 17.0], median is middle value
        assert keygen.median_us == 15.5
        assert keygen.min_us == 14.0
        assert keygen.max_us == 17.0
        assert keygen.stdev_us is not None
        assert keygen.stdev_us > 0

    def test_raw_timings_stored(self):
        """Raw timings are stored for reproducibility."""
        samples = [
            [
                SingleRunResult(
                    operation="keygen", us_per_op=15.0, ops_per_sec=66666.7, ops_count=200000
                )
            ],
            [
                SingleRunResult(
                    operation="keygen", us_per_op=16.0, ops_per_sec=62500.0, ops_count=187500
                )
            ],
        ]

        results = _aggregate_samples_to_results(samples, "mlkem768")

        keygen = results[0]
        assert keygen.timings_us is not None
        assert len(keygen.timings_us) == 2
        assert 15.0 in keygen.timings_us
        assert 16.0 in keygen.timings_us

    def test_iteration_count_summed(self):
        """Iteration count is summed across samples."""
        samples = [
            [
                SingleRunResult(
                    operation="keygen", us_per_op=15.0, ops_per_sec=66666.7, ops_count=100000
                )
            ],
            [
                SingleRunResult(
                    operation="keygen", us_per_op=16.0, ops_per_sec=62500.0, ops_count=90000
                )
            ],
        ]

        results = _aggregate_samples_to_results(samples, "mlkem768")

        keygen = results[0]
        assert keygen.iteration_count == 190000


class TestBenchmarkConfig:
    """Tests for BenchmarkConfig."""

    def test_default_values(self):
        """Default config values are sensible."""
        config = BenchmarkConfig()
        assert config.samples == 10
        assert config.warm_up == 2
        assert config.seconds_per_sample == 3
        assert config.timeout == 300
        assert config.include_tls is False
        assert config.include_perf is False
        assert config.pin_cpu is None

    @patch.dict("os.environ", {"PQC_BENCH_OPENSSL": "/custom/openssl"})
    def test_env_override_openssl(self):
        """Environment variable overrides openssl path."""
        config = BenchmarkConfig()
        assert config.openssl_path == "/custom/openssl"

    @patch.dict("os.environ", {"PQC_BENCH_PROVIDER_PATH": "/custom/provider"})
    def test_env_override_provider(self):
        """Environment variable overrides provider path."""
        config = BenchmarkConfig()
        assert config.provider_path == "/custom/provider"


def _check_openssl_oqs_available() -> bool:
    """Check if OpenSSL with oqs-provider is available."""
    try:
        from pqc_bench.checker import check_all_dependencies

        result = check_all_dependencies()
        return result.overall_valid
    except Exception:
        return False


@pytest.mark.integration
class TestRunnerIntegration:
    """Integration tests that require actual OpenSSL with oqs-provider."""

    @pytest.mark.skipif(
        not _check_openssl_oqs_available(),
        reason="Requires OpenSSL with oqs-provider",
    )
    def test_real_kem_benchmark(self):
        """Run actual KEM benchmark with real OpenSSL."""
        from pqc_bench.algorithms.registry import Algorithm, AlgorithmType
        from pqc_bench.runner import run_kem_benchmark

        algo = Algorithm(
            name="mlkem768",
            display_name="ML-KEM-768",
            type=AlgorithmType.KEM,
            security_level=3,
        )
        config = BenchmarkConfig(samples=2, warm_up=1, seconds_per_sample=1)
        result = run_kem_benchmark(algo, config)

        assert result.error is None
        assert len(result.results) == 3  # keygen, encaps, decaps
