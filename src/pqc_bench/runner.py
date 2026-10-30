"""Benchmark runner and orchestration.

This module provides honest benchmark statistics by running multiple samples
of `openssl speed` and computing real percentiles across those samples.
"""

import contextlib
import os
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from .algorithms.registry import Algorithm, AlgorithmType, registry
from .checker import NativePQCCheck, check_native_pqc_support, is_native_algorithm
from .models import BenchmarkResult, Environment, Operation, PerfMetrics, SizeMetrics
from .parsers.handshake import HandshakeResult, parse_handshake_output_with_summary
from .parsers.speed import get_algorithm_sizes, parse_speed_output
from .stats import Stats, calculate_stats


@lru_cache(maxsize=1)
def _get_native_pqc_check(openssl_path: str, library_path: str) -> NativePQCCheck:
    """Get cached native PQC support check.

    Uses lru_cache to avoid repeated subprocess calls for version detection.

    Args:
        openssl_path: Path to OpenSSL binary
        library_path: LD_LIBRARY_PATH for the OpenSSL binary

    Returns:
        NativePQCCheck with availability and supported algorithms
    """
    return check_native_pqc_support(openssl_path, library_path)


def should_use_native(algorithm: str, config: "BenchmarkConfig") -> bool:
    """Determine if an algorithm should use native OpenSSL 3.5+ mode.

    Auto-detects OpenSSL version and checks if the algorithm is natively supported.

    Args:
        algorithm: Algorithm name to check
        config: Benchmark configuration with openssl_path and library_path

    Returns:
        True if native mode should be used for this algorithm
    """
    # Check if OpenSSL 3.5+ is available
    native_check = _get_native_pqc_check(config.openssl_path, config.library_path)
    if not native_check.is_available:
        return False

    # Check if this specific algorithm is natively supported
    return is_native_algorithm(algorithm)


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark execution.

    Attributes:
        samples: Number of repeated benchmark runs (for statistical validity)
        warm_up: Number of warm-up runs (discarded)
        seconds_per_sample: Duration of each openssl speed run
        timeout: Timeout per algorithm in seconds
        include_tls: Whether to include TLS handshake benchmarks
        include_perf: Whether to include CPU cycle counts
        openssl_path: Path to OpenSSL binary (resolved from PQC_BENCH_OPENSSL)
        provider_path: Path to oqs-provider (resolved from PQC_BENCH_PROVIDER_PATH)
        library_path: LD_LIBRARY_PATH for OpenSSL (resolved from PQC_BENCH_LD_LIBRARY_PATH)
        use_native: Use native OpenSSL 3.5+ PQC instead of oqs-provider where available
        verbose: Enable verbose output
        quiet: Suppress non-essential output
        pin_cpu: CPU core to pin benchmarks to (None = no pinning)
    """

    samples: int = 10
    warm_up: int = 2
    seconds_per_sample: int = 3
    timeout: int = 300
    include_tls: bool = False
    include_perf: bool = False
    openssl_path: str = "openssl"
    provider_path: str = ""
    library_path: str = ""
    use_native: bool = False
    verbose: bool = False
    quiet: bool = False
    pin_cpu: int | None = None

    def __post_init__(self):
        """Resolve openssl_path, provider_path, and library_path from environment."""
        self.openssl_path = os.environ.get("PQC_BENCH_OPENSSL", self.openssl_path)
        self.provider_path = os.environ.get("PQC_BENCH_PROVIDER_PATH", self.provider_path)
        self.library_path = os.environ.get("PQC_BENCH_LD_LIBRARY_PATH", self.library_path)


@dataclass
class AlgorithmBenchmarkResult:
    """Result of benchmarking a single algorithm.

    Attributes:
        algorithm: Algorithm that was benchmarked
        results: Benchmark results for each operation
        size_metrics: Size metrics for the algorithm
        error: Error message if benchmark failed
        perf_metrics: List of perf metrics from each sample (when include_perf=True)
    """

    algorithm: Algorithm
    results: list[BenchmarkResult] = field(default_factory=list)
    size_metrics: SizeMetrics | None = None
    error: str | None = None
    perf_metrics: list[PerfMetrics] = field(default_factory=list)


@dataclass
class BenchmarkRunResult:
    """Complete result of a benchmark run.

    Attributes:
        environment: Environment metadata
        results: All benchmark results
        size_metrics: All size metrics
        failed_algorithms: List of algorithms that failed with error messages
        tls_results: TLS handshake benchmark results (when include_tls=True)
        perf_metrics: CPU performance metrics per algorithm (when include_perf=True)
    """

    environment: Environment
    results: list[BenchmarkResult] = field(default_factory=list)
    size_metrics: list[SizeMetrics] = field(default_factory=list)
    failed_algorithms: list[tuple[str, str]] = field(default_factory=list)
    tls_results: list = field(default_factory=list)  # List of TLSBenchmarkResult
    perf_metrics: dict[str, list[PerfMetrics]] = field(
        default_factory=dict
    )  # algorithm -> list of perf samples


def _check_perf_available() -> bool:
    """Check if perf stat is available and usable.

    This is a thin wrapper around checker.check_perf_available() for internal use.
    """
    from .checker import check_perf_available

    return check_perf_available()


def _parse_perf_output(stderr: str) -> PerfMetrics:
    """Parse perf stat output to extract metrics.

    Handles locale variations (commas vs periods for thousands separators)
    and gracefully ignores "<not counted>" or "<not supported>" values.

    Args:
        stderr: perf stat output (perf writes to stderr)

    Returns:
        PerfMetrics with extracted values
    """
    import re

    cycles = None
    instructions = None
    ipc = None
    cache_misses = None
    branch_misses = None

    def parse_int_with_separators(s: str) -> int | None:
        """Parse integer that may have comma/period/space as thousands separator."""
        # Remove common thousands separators (comma, period, space, apostrophe)
        # Be careful: some locales use period as decimal, but perf counts are integers
        cleaned = re.sub(r"[,.\s']", "", s)
        try:
            return int(cleaned)
        except ValueError:
            return None

    for line in stderr.splitlines():
        line = line.strip()

        # Skip lines with "<not counted>", "<not supported>", or "N/A"
        if "<not" in line.lower() or "n/a" in line.lower():
            continue

        # Cycles - match number followed by "cycles" (handles various formats)
        match = re.search(r"([\d,.\s']+)\s+cycles", line)
        if match and cycles is None:
            cycles = parse_int_with_separators(match.group(1))

        # Instructions and IPC
        match = re.search(r"([\d,.\s']+)\s+instructions\s+#\s+([\d.,]+)\s+insn per cycle", line)
        if match:
            instructions = parse_int_with_separators(match.group(1))
            # IPC is a decimal, handle comma as decimal separator
            ipc_str = match.group(2).replace(",", ".")
            with contextlib.suppress(ValueError):
                ipc = float(ipc_str)
        elif instructions is None:
            match = re.search(r"([\d,.\s']+)\s+instructions", line)
            if match:
                instructions = parse_int_with_separators(match.group(1))

        # Cache misses
        match = re.search(r"([\d,.\s']+)\s+cache-misses", line)
        if match and cache_misses is None:
            cache_misses = parse_int_with_separators(match.group(1))

        # Branch misses
        match = re.search(r"([\d,.\s']+)\s+branch-misses", line)
        if match and branch_misses is None:
            branch_misses = parse_int_with_separators(match.group(1))

    return PerfMetrics(
        cycles=cycles,
        instructions=instructions,
        ipc=ipc,
        cache_misses=cache_misses,
        branch_misses=branch_misses,
    )


@dataclass
class SingleRunResult:
    """Result of a single openssl speed run.

    Attributes:
        operation: Operation name (keygen, encaps, decaps, sign, verify)
        us_per_op: Microseconds per operation (from this single run)
        ops_per_sec: Operations per second (from this single run)
        ops_count: Total operations performed in this run
    """

    operation: str
    us_per_op: float
    ops_per_sec: float
    ops_count: int


def _get_script_path(script_name: str) -> Path:
    """Get the path to a benchmark script."""
    return Path(__file__).parent.parent / "scripts" / script_name


def _run_openssl_speed_via_script(
    algorithm: str,
    config: BenchmarkConfig,
    script_name: str,
) -> tuple[bool, str, PerfMetrics | None]:
    """Run OpenSSL speed benchmark via bash script.

    Args:
        algorithm: Algorithm name
        config: Benchmark configuration
        script_name: Name of the script (bench_kem.sh or bench_sig.sh)

    Returns:
        Tuple of (success, output/error, perf_metrics)
    """
    script_path = _get_script_path(script_name)

    if not script_path.exists():
        return False, f"Script not found: {script_path}", None

    # Build environment using resolved paths from config
    env = os.environ.copy()
    env["PQC_BENCH_OPENSSL"] = config.openssl_path
    if config.provider_path:
        env["PQC_BENCH_PROVIDER_PATH"] = config.provider_path
    if config.library_path:
        env["LD_LIBRARY_PATH"] = config.library_path
    env["PQC_BENCH_DURATION"] = str(config.seconds_per_sample)

    # Auto-detect if native mode should be used for this specific algorithm
    # This checks: OpenSSL >= 3.5 AND algorithm is natively supported
    use_native_for_algo = should_use_native(algorithm, config)
    env["PQC_BENCH_USE_NATIVE"] = "1" if use_native_for_algo else "0"

    base_cmd = ["bash", str(script_path), algorithm, str(config.seconds_per_sample)]

    # Wrap with taskset if CPU pinning is requested
    if config.pin_cpu is not None:
        base_cmd = ["taskset", "-c", str(config.pin_cpu)] + base_cmd

    # Wrap with perf if requested and available
    perf_metrics = None
    perf_ok = config.include_perf and _check_perf_available()
    if perf_ok:
        cmd = [
            "perf",
            "stat",
            "-e",
            "cycles,instructions,cache-misses,branch-misses",
            "--",
        ] + base_cmd
    else:
        cmd = base_cmd

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout,
            env=env,
        )
        if result.returncode != 0:
            # Return combined stdout+stderr since scripts redirect stderr to stdout
            combined = (result.stdout or "") + "\n" + (result.stderr or "")
            combined = combined.strip()
            return False, combined or "Unknown error", None

        # Parse perf metrics if perf was used
        if perf_ok:
            perf_metrics = _parse_perf_output(result.stderr)

        return True, result.stdout, perf_metrics
    except subprocess.TimeoutExpired:
        return False, f"Timeout after {config.timeout} seconds", None
    except Exception as e:
        return False, str(e), None


def _run_openssl_speed_once(
    algorithm: str,
    config: BenchmarkConfig,
    script_name: str | None = None,
) -> tuple[bool, str, PerfMetrics | None]:
    """Run a single OpenSSL speed benchmark.

    Uses bash script if script_name is provided and script exists,
    otherwise falls back to direct openssl invocation.

    The scripts are preferred because they handle stderr merging via `2>&1`,
    but the direct fallback should work for most setups.

    Args:
        algorithm: Algorithm name
        config: Benchmark configuration
        script_name: Optional script name (bench_kem.sh or bench_sig.sh)

    Returns:
        Tuple of (success, output/error, perf_metrics)
    """
    # Try script-based execution first if script_name provided
    if script_name:
        script_path = _get_script_path(script_name)
        if script_path.exists():
            return _run_openssl_speed_via_script(algorithm, config, script_name)

    # Fall back to direct invocation
    base_cmd = [config.openssl_path, "speed", "-mr"]  # Use machine-readable output

    # Auto-detect if native mode should be used for this specific algorithm
    use_native_for_algo = should_use_native(algorithm, config)

    # Add provider configuration only if not using native mode for this algorithm
    if not use_native_for_algo:
        if config.provider_path:
            base_cmd.extend(["-provider-path", config.provider_path])
        base_cmd.extend(["-provider", "oqsprovider", "-provider", "default"])

    base_cmd.extend(["-seconds", str(config.seconds_per_sample)])
    base_cmd.append(algorithm)

    # Wrap with taskset if CPU pinning is requested
    if config.pin_cpu is not None:
        base_cmd = ["taskset", "-c", str(config.pin_cpu)] + base_cmd

    # Wrap with perf if requested and available
    perf_metrics = None
    perf_ok = config.include_perf and _check_perf_available()
    if perf_ok:
        cmd = [
            "perf",
            "stat",
            "-e",
            "cycles,instructions,cache-misses,branch-misses",
            "--",
        ] + base_cmd
    else:
        cmd = base_cmd

    # Build environment with LD_LIBRARY_PATH if specified
    env = None
    if config.library_path:
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = config.library_path

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout,
            env=env,
        )
        if result.returncode != 0:
            # Return combined stdout+stderr for better error messages
            combined = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            return False, combined or "Unknown error", None

        # Handle output differently based on whether perf is enabled
        if perf_ok:
            # When perf is enabled, perf writes to stderr.
            # Parse perf metrics from stderr first
            perf_metrics = _parse_perf_output(result.stderr)
            # For speed parsing: combine stdout + stderr to handle cases where
            # OpenSSL/provider writes -mr output to stderr. The speed parser
            # will ignore perf stat lines (they don't match speed patterns).
            output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        else:
            # Without perf, combine stdout + stderr like the scripts do with 2>&1
            # Some OpenSSL/provider versions may write -mr output to stderr
            output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()

        return True, output, perf_metrics
    except subprocess.TimeoutExpired:
        return False, f"Timeout after {config.timeout} seconds", None
    except Exception as e:
        return False, str(e), None


def _run_openssl_speed_samples(
    algorithm: str,
    config: BenchmarkConfig,
    script_name: str | None = None,
    expected_ops: set[str] | None = None,
) -> tuple[list[list[SingleRunResult]], list[PerfMetrics], str | None]:
    """Run multiple samples of OpenSSL speed benchmark.

    This function runs warm_up + samples runs of openssl speed,
    discarding the warm-up runs and returning results from the sample runs.

    Args:
        algorithm: Algorithm name
        config: Benchmark configuration
        script_name: Optional script name (bench_kem.sh or bench_sig.sh)
        expected_ops: Optional set of expected ops (e.g., {"keygen", "encaps", "decaps"})

    Returns:
        Tuple of (list of sample results per run, list of perf metrics, error message or None)
    """
    total_runs = config.warm_up + config.samples
    all_samples: list[list[SingleRunResult]] = []
    all_perf: list[PerfMetrics] = []

    for i in range(total_runs):
        is_warmup = i < config.warm_up

        if config.verbose:
            run_type = "warm-up" if is_warmup else "sample"
            run_num = i + 1 if is_warmup else i - config.warm_up + 1
            print(
                f"  {run_type} {run_num}/{config.warm_up if is_warmup else config.samples}...",
                end=" ",
                flush=True,
            )

        success, output, perf_metrics = _run_openssl_speed_once(algorithm, config, script_name)

        if not success:
            if config.verbose:
                print("FAILED")
            return [], [], output

        if config.verbose:
            print("done")

        # Skip warm-up runs
        if is_warmup:
            continue

        # Parse speed output with duration hint for fallback parsing
        speed_results = parse_speed_output(output, duration_hint=config.seconds_per_sample)
        if not speed_results:
            return [], [], "No results parsed from OpenSSL output"

        # Validate that all expected operations are present
        if expected_ops:
            parsed_ops = {sr.operation for sr in speed_results}
            missing_ops = expected_ops - parsed_ops
            if missing_ops:
                return [], [], f"Incomplete results: missing operations {missing_ops}"

        # Convert to SingleRunResult
        run_results = []
        for sr in speed_results:
            run_results.append(
                SingleRunResult(
                    operation=sr.operation,
                    us_per_op=sr.us_per_op,
                    ops_per_sec=sr.ops_per_sec,
                    ops_count=sr.ops_count,
                )
            )
        all_samples.append(run_results)

        # Store perf metrics if available
        if perf_metrics:
            all_perf.append(perf_metrics)

    return all_samples, all_perf, None


def _aggregate_samples_to_results(
    samples: list[list[SingleRunResult]],
    algorithm_name: str,
) -> list[BenchmarkResult]:
    """Aggregate multiple sample runs into BenchmarkResults with real statistics.

    Args:
        samples: List of sample runs, each containing results for all operations
        algorithm_name: Algorithm name for the results

    Returns:
        List of BenchmarkResult objects with computed percentiles
    """
    if not samples:
        return []

    ops_to_timings: dict[str, list[float]] = {}
    ops_to_ops_counts: dict[str, list[int]] = {}

    for run in samples:
        for result in run:
            if result.operation not in ops_to_timings:
                ops_to_timings[result.operation] = []
                ops_to_ops_counts[result.operation] = []
            ops_to_timings[result.operation].append(result.us_per_op)
            ops_to_ops_counts[result.operation].append(result.ops_count)

    op_map = {
        "keygen": Operation.KEYGEN,
        "encaps": Operation.ENCAPS,
        "decaps": Operation.DECAPS,
        "sign": Operation.SIGN,
        "verify": Operation.VERIFY,
    }

    results = []
    for op_name, timings in ops_to_timings.items():
        operation = op_map.get(op_name)
        if not operation:
            continue

        # Calculate statistics across samples.
        stats = calculate_stats(timings)

        # Total operations across all samples
        total_ops = sum(ops_to_ops_counts.get(op_name, [0]))

        results.append(
            BenchmarkResult(
                algorithm_name=algorithm_name,
                operation=operation,
                median_us=stats.median,
                p95_us=stats.p95,
                p99_us=stats.p99,
                min_us=stats.min,
                max_us=stats.max,
                ops_per_sec=1_000_000 / stats.median if stats.median > 0 else 0,
                iteration_count=total_ops,
                sample_count=stats.count,
                stdev_us=stats.stdev,
                timings_us=timings.copy(),  # Keep individual sample timings for reproducibility.
            )
        )

    return results


def run_kem_benchmark(
    algorithm: Algorithm,
    config: BenchmarkConfig,
) -> AlgorithmBenchmarkResult:
    """Run benchmark for a KEM algorithm.

    Runs multiple samples of openssl speed (via bench_kem.sh) and computes real percentiles.

    Args:
        algorithm: KEM algorithm to benchmark
        config: Benchmark configuration

    Returns:
        AlgorithmBenchmarkResult with results or error
    """
    if config.verbose:
        print(f"Benchmarking KEM: {algorithm.display_name}")
        samples_info = f"{config.samples} samples, {config.warm_up} warm-up"
        print(f"  {samples_info}, {config.seconds_per_sample}s each")

    samples, perf_metrics, error = _run_openssl_speed_samples(
        algorithm.name, config, "bench_kem.sh", expected_ops={"keygen", "encaps", "decaps"}
    )

    if error:
        return AlgorithmBenchmarkResult(
            algorithm=algorithm,
            error=error,
        )

    # Calculate statistics across samples.
    results = _aggregate_samples_to_results(samples, algorithm.name)

    if not results:
        return AlgorithmBenchmarkResult(
            algorithm=algorithm,
            error="No results parsed from OpenSSL output",
        )

    sizes = get_algorithm_sizes(algorithm.name, is_kem=True)
    size_metrics = SizeMetrics(
        algorithm_name=algorithm.name,
        public_key_bytes=sizes.get("public_key_bytes"),
        secret_key_bytes=sizes.get("secret_key_bytes"),
        ciphertext_bytes=sizes.get("ciphertext_bytes"),
        source=sizes.get("source", "unknown"),
    )

    return AlgorithmBenchmarkResult(
        algorithm=algorithm,
        results=results,
        size_metrics=size_metrics,
        perf_metrics=perf_metrics,
    )


def run_sig_benchmark(
    algorithm: Algorithm,
    config: BenchmarkConfig,
) -> AlgorithmBenchmarkResult:
    """Run benchmark for a signature algorithm.

    Runs multiple samples of openssl speed (via bench_sig.sh) and computes real percentiles.

    Args:
        algorithm: Signature algorithm to benchmark
        config: Benchmark configuration

    Returns:
        AlgorithmBenchmarkResult with results or error
    """
    if config.verbose:
        print(f"Benchmarking Signature: {algorithm.display_name}")
        samples_info = f"{config.samples} samples, {config.warm_up} warm-up"
        print(f"  {samples_info}, {config.seconds_per_sample}s each")

    # Check for experimental algorithms and warn
    if algorithm.is_experimental and not config.quiet:
        print(f"Warning: {algorithm.display_name} is experimental")

    samples, perf_metrics, error = _run_openssl_speed_samples(
        algorithm.name, config, "bench_sig.sh", expected_ops={"keygen", "sign", "verify"}
    )

    if error:
        return AlgorithmBenchmarkResult(
            algorithm=algorithm,
            error=error,
        )

    # Calculate statistics across samples.
    results = _aggregate_samples_to_results(samples, algorithm.name)

    if not results:
        return AlgorithmBenchmarkResult(
            algorithm=algorithm,
            error="No results parsed from OpenSSL output",
        )

    sizes = get_algorithm_sizes(algorithm.name, is_kem=False)
    size_metrics = SizeMetrics(
        algorithm_name=algorithm.name,
        public_key_bytes=sizes.get("public_key_bytes"),
        secret_key_bytes=sizes.get("secret_key_bytes"),
        signature_bytes=sizes.get("signature_bytes"),
        source=sizes.get("source", "unknown"),
    )

    return AlgorithmBenchmarkResult(
        algorithm=algorithm,
        results=results,
        size_metrics=size_metrics,
        perf_metrics=perf_metrics,
    )


@dataclass
class TLSBenchmarkResult:
    """Result of a TLS handshake benchmark.

    Attributes:
        kem_algorithm: KEM algorithm used for key exchange
        sig_algorithm: Signature algorithm used for certificates
        results: List of handshake results
        stats: Statistical summary of handshake timings
        success_count: Number of successful handshakes
        fail_count: Number of failed handshakes
        total_count: Total number of handshake attempts
        error: Error message if benchmark failed
        first_handshake_info: TLS connection info from first handshake (for verification)
    """

    kem_algorithm: str
    sig_algorithm: str
    results: list[HandshakeResult] = field(default_factory=list)
    stats: Stats | None = None
    success_count: int = 0
    fail_count: int = 0
    total_count: int = 0
    error: str | None = None
    first_handshake_info: dict[str, str | None] | None = None


def _get_tls_script_path() -> Path:
    """Get the path to the TLS benchmark script."""
    return Path(__file__).parent.parent / "scripts" / "bench_tls.sh"


def run_tls_benchmark(
    kem_algorithm: str,
    sig_algorithm: str = "mldsa65",
    iterations: int = 10,
    config: BenchmarkConfig | None = None,
) -> TLSBenchmarkResult:
    """Run TLS handshake benchmark with specified algorithms.

    Args:
        kem_algorithm: KEM algorithm for key exchange
        sig_algorithm: Signature algorithm for certificates (default: mldsa65)
        iterations: Number of handshakes to perform
        config: Optional benchmark configuration

    Returns:
        TLSBenchmarkResult with handshake timings or error
    """
    config = config or BenchmarkConfig()

    if config.verbose:
        print(f"Running TLS handshake benchmark: {kem_algorithm} + {sig_algorithm}")

    script_path = _get_tls_script_path()

    if not script_path.exists():
        return TLSBenchmarkResult(
            kem_algorithm=kem_algorithm,
            sig_algorithm=sig_algorithm,
            error=f"TLS benchmark script not found: {script_path}",
        )

    # Build environment using resolved paths from config
    env = os.environ.copy()
    env["PQC_BENCH_OPENSSL"] = config.openssl_path
    if config.provider_path:
        env["PQC_BENCH_PROVIDER_PATH"] = config.provider_path
    if config.library_path:
        env["LD_LIBRARY_PATH"] = config.library_path
    env["PQC_BENCH_TLS_ITERATIONS"] = str(iterations)

    try:
        result = subprocess.run(
            ["bash", str(script_path), kem_algorithm, sig_algorithm, str(iterations)],
            capture_output=True,
            text=True,
            timeout=config.timeout,
            env=env,
        )

        if result.returncode != 0:
            return TLSBenchmarkResult(
                kem_algorithm=kem_algorithm,
                sig_algorithm=sig_algorithm,
                error=result.stderr or f"Script exited with code {result.returncode}",
            )

        # Parse handshake output with summary (includes success/fail counts)
        summary = parse_handshake_output_with_summary(result.stdout)

        if not summary.results:
            return TLSBenchmarkResult(
                kem_algorithm=kem_algorithm,
                sig_algorithm=sig_algorithm,
                error="No handshake results parsed from output",
            )

        # Calculate statistics from handshake measurements.
        timings = [hr.duration_us for hr in summary.results]
        stats = calculate_stats(timings)

        return TLSBenchmarkResult(
            kem_algorithm=kem_algorithm,
            sig_algorithm=sig_algorithm,
            results=summary.results,
            stats=stats,
            success_count=summary.success_count,
            fail_count=summary.fail_count,
            total_count=summary.total_count,
            first_handshake_info=summary.first_handshake_info,
        )

    except subprocess.TimeoutExpired:
        return TLSBenchmarkResult(
            kem_algorithm=kem_algorithm,
            sig_algorithm=sig_algorithm,
            error=f"Timeout after {config.timeout} seconds",
        )
    except Exception as e:
        return TLSBenchmarkResult(
            kem_algorithm=kem_algorithm,
            sig_algorithm=sig_algorithm,
            error=str(e),
        )


def run_tls_benchmarks_for_kems(
    kem_algorithms: list[Algorithm],
    sig_algorithm: str = "mldsa65",
    iterations: int = 10,
    config: BenchmarkConfig | None = None,
) -> list[TLSBenchmarkResult]:
    """Run TLS handshake benchmarks for multiple KEM algorithms.

    Args:
        kem_algorithms: List of KEM algorithms to benchmark
        sig_algorithm: Signature algorithm for certificates
        iterations: Number of handshakes per algorithm
        config: Optional benchmark configuration

    Returns:
        List of TLSBenchmarkResult for each algorithm
    """
    results = []
    config = config or BenchmarkConfig()

    for kem in kem_algorithms:
        tls_result = run_tls_benchmark(
            kem_algorithm=kem.name,
            sig_algorithm=sig_algorithm,
            iterations=iterations,
            config=config,
        )
        results.append(tls_result)

    return results


def run_all_benchmarks(config: BenchmarkConfig) -> BenchmarkRunResult:
    """Run benchmarks for all registered algorithms.

    Args:
        config: Benchmark configuration

    Returns:
        BenchmarkRunResult with all results
    """
    # Import registries to ensure all algorithms are registered
    from .algorithms import kem  # noqa: F401

    with contextlib.suppress(ImportError):
        from .algorithms import sig  # noqa: F401

    # Import here to use resolved openssl path from config
    from .checker import capture_environment

    environment = capture_environment(
        config.openssl_path, config.provider_path, config.library_path
    )

    all_results: list[BenchmarkResult] = []
    all_sizes: list[SizeMetrics] = []
    failed: list[tuple[str, str]] = []
    all_perf: dict[str, list[PerfMetrics]] = {}

    # Run KEM benchmarks
    kem_algorithms = registry.get_by_type(AlgorithmType.KEM)
    for algo in kem_algorithms:
        result = run_kem_benchmark(algo, config)
        if result.error:
            failed.append((algo.name, result.error))
        else:
            all_results.extend(result.results)
            if result.size_metrics:
                all_sizes.append(result.size_metrics)
            if result.perf_metrics:
                all_perf[algo.name] = result.perf_metrics

    # Run signature benchmarks
    sig_algorithms = registry.get_by_type(AlgorithmType.SIGNATURE)
    for algo in sig_algorithms:
        result = run_sig_benchmark(algo, config)
        if result.error:
            failed.append((algo.name, result.error))
        else:
            all_results.extend(result.results)
            if result.size_metrics:
                all_sizes.append(result.size_metrics)
            if result.perf_metrics:
                all_perf[algo.name] = result.perf_metrics

    return BenchmarkRunResult(
        environment=environment,
        results=all_results,
        size_metrics=all_sizes,
        failed_algorithms=failed,
        perf_metrics=all_perf,
    )


def run_benchmarks(
    algorithm_names: list[str] | None = None,
    algo_type: str = "all",
    samples: int = 10,
    warm_up: int = 2,
    seconds_per_sample: int = 3,
    timeout: int = 300,
    include_tls: bool = False,
    include_perf: bool = False,
    verbose: bool = False,
    quiet: bool = False,
    pin_cpu: int | None = None,
    openssl_path: str | None = None,
    library_path: str | None = None,
    use_native: bool = False,
) -> BenchmarkRunResult:
    """Run benchmarks with specified parameters.

    Args:
        algorithm_names: Specific algorithm names to benchmark (None = all)
        algo_type: Algorithm type filter ('kem', 'sig', or 'all')
        samples: Number of repeated benchmark runs for statistics
        warm_up: Number of warm-up runs (discarded)
        seconds_per_sample: Duration of each openssl speed run
        timeout: Timeout per algorithm in seconds
        include_tls: Include TLS handshake benchmarks
        include_perf: Include CPU cycle counts
        verbose: Enable verbose output
        quiet: Suppress non-essential output
        pin_cpu: CPU core to pin benchmarks to (None = no pinning)
        openssl_path: Path to OpenSSL binary (None = use env or default)
        library_path: LD_LIBRARY_PATH for OpenSSL (None = use env or default)
        use_native: Use native OpenSSL 3.5+ PQC instead of oqs-provider

    Returns:
        BenchmarkRunResult with all results
    """
    # Import registries
    from .algorithms import kem  # noqa: F401

    with contextlib.suppress(ImportError):
        from .algorithms import sig  # noqa: F401

    config = BenchmarkConfig(
        samples=samples,
        warm_up=warm_up,
        seconds_per_sample=seconds_per_sample,
        timeout=timeout,
        include_tls=include_tls,
        include_perf=include_perf,
        verbose=verbose,
        quiet=quiet,
        pin_cpu=pin_cpu,
        use_native=use_native,
    )
    # Override paths if explicitly provided
    if openssl_path:
        config.openssl_path = openssl_path
    if library_path:
        config.library_path = library_path

    # Validate pin_cpu: if specified, ensure taskset is available
    if config.pin_cpu is not None:
        from .checker import check_taskset_available

        if not check_taskset_available():
            raise RuntimeError(
                f"--pin-cpu={config.pin_cpu} requires taskset, which is not available. "
                "Install util-linux package or remove --pin-cpu option."
            )

    # Import here to use resolved openssl path from config
    from .checker import capture_environment

    environment = capture_environment(
        config.openssl_path, config.provider_path, config.library_path
    )

    all_results: list[BenchmarkResult] = []
    all_sizes: list[SizeMetrics] = []
    failed: list[tuple[str, str]] = []
    all_perf: dict[str, list[PerfMetrics]] = {}

    # Determine which algorithms to benchmark
    if algorithm_names:
        # Specific algorithms requested
        algorithms = []
        for name in algorithm_names:
            algo = registry.get(name)
            if algo:
                algorithms.append(algo)
            else:
                failed.append((name, "Algorithm not found in registry"))
    else:
        # Filter by type
        if algo_type == "kem":
            algorithms = registry.get_by_type(AlgorithmType.KEM)
        elif algo_type == "sig":
            algorithms = registry.get_by_type(AlgorithmType.SIGNATURE)
        else:
            algorithms = registry.get_all()

    # Run benchmarks
    tls_results = []
    for algo in algorithms:
        if algo.type == AlgorithmType.KEM:
            result = run_kem_benchmark(algo, config)
        else:
            result = run_sig_benchmark(algo, config)

        if result.error:
            failed.append((algo.name, result.error))
        else:
            all_results.extend(result.results)
            if result.size_metrics:
                all_sizes.append(result.size_metrics)
            if result.perf_metrics:
                all_perf[algo.name] = result.perf_metrics

    # Run TLS handshake benchmarks if enabled
    if include_tls:
        # Get KEM algorithms for TLS benchmarks
        kem_algorithms = [a for a in algorithms if a.type == AlgorithmType.KEM]
        if not kem_algorithms and not algorithm_names:
            # If no KEM algorithms in the list, get all KEMs
            kem_algorithms = registry.get_by_type(AlgorithmType.KEM)

        tls_iterations = max(10, samples)  # At least 10 handshakes for TLS
        for kem in kem_algorithms:
            tls_result = run_tls_benchmark(
                kem_algorithm=kem.name,
                sig_algorithm="mldsa65",  # Default signature for TLS
                iterations=tls_iterations,
                config=config,
            )
            tls_results.append(tls_result)

            # Convert TLS results to BenchmarkResult format
            if tls_result.stats and not tls_result.error:
                raw_timings = [hr.duration_us for hr in tls_result.results]
                tls_bench_result = BenchmarkResult(
                    algorithm_name=f"{kem.name}+mldsa65",
                    operation=Operation.HANDSHAKE,
                    median_us=tls_result.stats.median,
                    p95_us=tls_result.stats.p95,
                    p99_us=tls_result.stats.p99,
                    min_us=tls_result.stats.min,
                    max_us=tls_result.stats.max,
                    ops_per_sec=1_000_000 / tls_result.stats.median
                    if tls_result.stats.median > 0
                    else 0,
                    iteration_count=len(tls_result.results),
                    sample_count=len(tls_result.results),
                    stdev_us=tls_result.stats.stdev,
                    timings_us=raw_timings,
                    tls_kem=kem.name,
                    tls_sig="mldsa65",
                )
                all_results.append(tls_bench_result)
            elif tls_result.error:
                failed.append((f"tls:{kem.name}", tls_result.error))

    return BenchmarkRunResult(
        environment=environment,
        results=all_results,
        size_metrics=all_sizes,
        failed_algorithms=failed,
        tls_results=tls_results,
        perf_metrics=all_perf,
    )
