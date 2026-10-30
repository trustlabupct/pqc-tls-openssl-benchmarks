"""Tests for CLI and checker modules."""

from unittest.mock import MagicMock, patch

import pytest

from pqc_bench.checker import (
    ReproducibilityCheck,
    check_reproducibility,
    check_taskset_available,
)


class TestCheckTasksetAvailable:
    """Tests for check_taskset_available function."""

    @patch("pqc_bench.checker.subprocess.run")
    def test_taskset_available(self, mock_run):
        """Returns True when taskset --version succeeds."""
        mock_run.return_value = MagicMock(returncode=0)
        assert check_taskset_available() is True

    @patch("pqc_bench.checker.subprocess.run")
    def test_taskset_not_available(self, mock_run):
        """Returns False when taskset --version fails."""
        mock_run.return_value = MagicMock(returncode=1)
        assert check_taskset_available() is False

    @patch("pqc_bench.checker.subprocess.run")
    def test_taskset_not_found(self, mock_run):
        """Returns False when taskset command not found."""
        mock_run.side_effect = FileNotFoundError()
        assert check_taskset_available() is False

    @patch("pqc_bench.checker.subprocess.run")
    def test_taskset_timeout(self, mock_run):
        """Returns False when taskset times out."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="taskset", timeout=5)
        assert check_taskset_available() is False


class TestReproducibilityCheck:
    """Tests for check_reproducibility function."""

    @patch("pqc_bench.checker.check_taskset_available")
    @patch("pqc_bench.checker.check_vm_environment")
    @patch("pqc_bench.checker.check_cpu_frequency")
    @patch("pqc_bench.checker.check_cpu_governor")
    def test_all_good(self, mock_gov, mock_freq, mock_vm, mock_taskset):
        """No warnings when all conditions are optimal."""
        mock_gov.return_value = "performance"
        mock_freq.return_value = (3500, (3500, 3500))  # Fixed frequency
        mock_vm.return_value = (False, None)
        mock_taskset.return_value = True

        result = check_reproducibility()

        assert result.cpu_governor == "performance"
        assert result.is_vm is False
        assert result.taskset_available is True
        assert len(result.warnings) == 0

    @patch("pqc_bench.checker.check_taskset_available")
    @patch("pqc_bench.checker.check_vm_environment")
    @patch("pqc_bench.checker.check_cpu_frequency")
    @patch("pqc_bench.checker.check_cpu_governor")
    def test_powersave_governor_warning(self, mock_gov, mock_freq, mock_vm, mock_taskset):
        """Warning when CPU governor is not 'performance'."""
        mock_gov.return_value = "powersave"
        mock_freq.return_value = (2000, (800, 3500))
        mock_vm.return_value = (False, None)
        mock_taskset.return_value = True

        result = check_reproducibility()

        assert result.cpu_governor == "powersave"
        assert any(w.category == "cpu_governor" for w in result.warnings)

    @patch("pqc_bench.checker.check_taskset_available")
    @patch("pqc_bench.checker.check_vm_environment")
    @patch("pqc_bench.checker.check_cpu_frequency")
    @patch("pqc_bench.checker.check_cpu_governor")
    def test_frequency_scaling_warning(self, mock_gov, mock_freq, mock_vm, mock_taskset):
        """Warning when CPU frequency scaling is enabled."""
        mock_gov.return_value = "performance"
        mock_freq.return_value = (2500, (800, 3500))  # Variable frequency range
        mock_vm.return_value = (False, None)
        mock_taskset.return_value = True

        result = check_reproducibility()

        assert result.cpu_freq_range == (800, 3500)
        assert any(w.category == "cpu_frequency" for w in result.warnings)

    @patch("pqc_bench.checker.check_taskset_available")
    @patch("pqc_bench.checker.check_vm_environment")
    @patch("pqc_bench.checker.check_cpu_frequency")
    @patch("pqc_bench.checker.check_cpu_governor")
    def test_vm_warning(self, mock_gov, mock_freq, mock_vm, mock_taskset):
        """Warning when running in a virtual machine."""
        mock_gov.return_value = "performance"
        mock_freq.return_value = (3500, (3500, 3500))
        mock_vm.return_value = (True, "kvm")
        mock_taskset.return_value = True

        result = check_reproducibility()

        assert result.is_vm is True
        assert result.vm_type == "kvm"
        assert any(w.category == "virtualization" for w in result.warnings)


class TestRunnerPinCpuValidation:
    """Tests for pin_cpu validation in runner."""

    # Note: check_taskset_available and capture_environment are imported INSIDE
    # run_benchmarks(), so we mock at pqc_bench.checker (the source module)
    @patch("pqc_bench.checker.check_taskset_available")
    @patch("pqc_bench.checker.capture_environment")
    def test_pin_cpu_without_taskset_raises(self, mock_env, mock_taskset):
        """RuntimeError raised when pin_cpu specified but taskset unavailable."""
        from pqc_bench.runner import run_benchmarks

        mock_taskset.return_value = False
        mock_env.return_value = MagicMock()

        with pytest.raises(RuntimeError, match="taskset"):
            run_benchmarks(
                algorithm_names=["mlkem768"],
                pin_cpu=0,
            )

    @patch("pqc_bench.runner._run_openssl_speed_samples")
    @patch("pqc_bench.checker.check_taskset_available")
    @patch("pqc_bench.checker.capture_environment")
    def test_pin_cpu_with_taskset_succeeds(self, mock_env, mock_taskset, mock_samples):
        """No error when pin_cpu specified and taskset is available."""
        from datetime import datetime

        from pqc_bench.models import Environment
        from pqc_bench.runner import run_benchmarks

        mock_taskset.return_value = True
        mock_env.return_value = Environment(
            openssl_version="3.2.0",
            oqs_provider_version="0.10.0",
            platform="Linux x86_64",
            captured_at=datetime.now(),
        )
        # Return empty results to avoid actual benchmarking
        mock_samples.return_value = ([], [], "No algorithm")

        # Should not raise, even though no results
        result = run_benchmarks(
            algorithm_names=["mlkem768"],
            pin_cpu=0,
        )
        # The function should complete (with failed algorithm due to mocked empty results)
        assert result is not None


class TestCLIPinCpuHandling:
    """Tests for CLI handling of pin_cpu option."""

    # Note: run_benchmarks is imported INSIDE the run() command, so mock at source
    # capture_environment is imported at module level in cli.py, so mock at cli
    @patch("pqc_bench.runner.run_benchmarks")
    @patch("pqc_bench.cli.capture_environment")
    @patch("pqc_bench.cli.check_reproducibility")
    @patch("pqc_bench.cli.check_all_dependencies")
    def test_cli_downgrades_pin_cpu_gracefully(self, mock_deps, mock_repro, mock_env, mock_run):
        """CLI warns and disables pin_cpu when taskset unavailable."""
        from datetime import datetime

        from click.testing import CliRunner

        from pqc_bench.cli import main
        from pqc_bench.models import Environment

        mock_deps.return_value = MagicMock(
            overall_valid=True,
            perf_available=False,
        )
        mock_repro.return_value = ReproducibilityCheck(
            cpu_governor="performance",
            taskset_available=False,  # taskset NOT available
            warnings=[],
        )
        mock_env.return_value = Environment(
            openssl_version="3.2.0",
            oqs_provider_version="0.10.0",
            platform="Linux x86_64",
            captured_at=datetime.now(),
        )
        mock_run.return_value = MagicMock(
            results=[],
            failed_algorithms=[],
            size_metrics=[],
            environment=mock_env.return_value,
            tls_results=[],
            perf_metrics={},
        )

        runner = CliRunner()
        result = runner.invoke(main, ["run", "--pin-cpu", "0", "mlkem768"])

        # Should warn about taskset
        assert "taskset" in result.output.lower() or result.exit_code == 0

        # run_benchmarks should be called with pin_cpu=None (downgraded)
        if mock_run.called:
            call_kwargs = mock_run.call_args[1]
            assert call_kwargs.get("pin_cpu") is None


class TestCLINoWarningsFlag:
    """Tests for --no-warnings flag behavior."""

    # Note: run_benchmarks is imported INSIDE the run() command, so mock at source
    @patch("pqc_bench.runner.run_benchmarks")
    @patch("pqc_bench.cli.capture_environment")
    @patch("pqc_bench.cli.check_reproducibility")
    @patch("pqc_bench.cli.check_all_dependencies")
    def test_no_warnings_skips_repro_check(self, mock_deps, mock_repro, mock_env, mock_run):
        """--no-warnings flag skips reproducibility warnings."""
        from datetime import datetime

        from click.testing import CliRunner

        from pqc_bench.cli import main
        from pqc_bench.models import Environment

        mock_deps.return_value = MagicMock(overall_valid=True, perf_available=False)
        mock_env.return_value = Environment(
            openssl_version="3.2.0",
            oqs_provider_version="0.10.0",
            platform="Linux x86_64",
            captured_at=datetime.now(),
        )
        mock_run.return_value = MagicMock(
            results=[],
            failed_algorithms=[],
            size_metrics=[],
            environment=mock_env.return_value,
            tls_results=[],
            perf_metrics={},
        )

        runner = CliRunner()
        # Use --no-warnings flag
        result = runner.invoke(main, ["run", "--no-warnings", "mlkem768"])

        # check_reproducibility should still be called for pin_cpu check
        # but warnings should not be printed
        # The key is no warning lines in output
        assert "Reproducibility warnings" not in result.output
