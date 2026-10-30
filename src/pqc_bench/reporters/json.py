"""JSON output formatter for benchmark results."""

import json
from datetime import datetime
from typing import Any

from .. import __version__
from ..models import Operation, PerfMetrics
from ..runner import BenchmarkRunResult, TLSBenchmarkResult

# Canonical operation ordering for stable output
OPERATION_ORDER = {
    Operation.KEYGEN: 0,
    Operation.ENCAPS: 1,
    Operation.DECAPS: 2,
    Operation.SIGN: 1,
    Operation.VERIFY: 2,
    Operation.HANDSHAKE: 3,
}


def format_json(run_result: BenchmarkRunResult) -> str:
    """Format benchmark results as JSON.

    Args:
        run_result: Complete benchmark run result

    Returns:
        JSON formatted string
    """
    # Separate speed results from TLS handshake results
    speed_results = [r for r in run_result.results if r.operation != Operation.HANDSHAKE]
    tls_results = [r for r in run_result.results if r.operation == Operation.HANDSHAKE]

    speed_iteration_count = sum(r.iteration_count for r in speed_results)
    tls_iteration_count = sum(r.iteration_count for r in tls_results)
    speed_sample_count = max((r.sample_count for r in speed_results), default=0)

    metadata = {
        "generated_at": datetime.now().isoformat(),
        "version": __version__,
        "speed_iteration_count": speed_iteration_count,
        "speed_sample_count": speed_sample_count,
        "tls_handshake_count": tls_iteration_count,
    }

    environment = {
        "openssl_version": run_result.environment.openssl_version,
        "oqs_provider_version": run_result.environment.oqs_provider_version,
        "platform": run_result.environment.platform,
    }
    if run_result.environment.cpu_model:
        environment["cpu_model"] = run_result.environment.cpu_model
    if run_result.environment.kernel_version:
        environment["kernel_version"] = run_result.environment.kernel_version

    # Group results by algorithm
    results_by_algo: dict[str, dict[str, Any]] = {}
    for result in run_result.results:
        if result.algorithm_name not in results_by_algo:
            results_by_algo[result.algorithm_name] = {
                "algorithm": result.algorithm_name,
                "type": None,  # Will be determined after collecting all operations
                "is_hybrid": False,  # Will be set from registry if available
                "is_experimental": False,
                "is_tls": False,  # Flag for TLS handshake results
                "operations": {},
                "sizes": {},
            }
            # Add structured TLS info if present
            if result.tls_kem is not None:
                results_by_algo[result.algorithm_name]["tls"] = {
                    "kem": result.tls_kem,
                    "sig": result.tls_sig,
                }

        op_data = {
            "median_us": result.median_us,
            "p95_us": result.p95_us,
            "p99_us": result.p99_us,
            "min_us": result.min_us,
            "max_us": result.max_us,
            "ops_per_sec": result.ops_per_sec,
            "sample_count": result.sample_count,
        }
        if result.stdev_us is not None:
            op_data["stdev_us"] = result.stdev_us
        # Keep individual sample timings for reproducibility.
        if result.timings_us is not None:
            op_data["timings_us"] = result.timings_us

        results_by_algo[result.algorithm_name]["operations"][result.operation.value] = op_data

    # Determine algorithm type and flags from registry and operations
    from ..algorithms.registry import AlgorithmType, registry

    for algo_name, algo_data in results_by_algo.items():
        ops = set(algo_data["operations"].keys())

        # Check for TLS handshake-only results first
        if ops == {"handshake"}:
            algo_data["type"] = "tls"
            algo_data["is_tls"] = True
            continue

        # Look up registry for metadata
        algo = registry.get(algo_name)
        if algo:
            algo_data["type"] = "kem" if algo.type == AlgorithmType.KEM else "signature"
            algo_data["is_hybrid"] = algo.is_hybrid
            algo_data["is_experimental"] = algo.is_experimental
        else:
            # Fallback: determine type from collected operations
            # KEMs have encaps/decaps, signatures have sign/verify
            if "encaps" in ops or "decaps" in ops:
                algo_data["type"] = "kem"
            elif "sign" in ops or "verify" in ops:
                algo_data["type"] = "signature"
            else:
                algo_data["type"] = "unknown"

    # Add size metrics (use 'is not None' for correct truthiness check)
    for size_metric in run_result.size_metrics:
        if size_metric.algorithm_name in results_by_algo:
            sizes = {}
            if size_metric.public_key_bytes is not None:
                sizes["public_key_bytes"] = size_metric.public_key_bytes
            if size_metric.secret_key_bytes is not None:
                sizes["secret_key_bytes"] = size_metric.secret_key_bytes
            if size_metric.ciphertext_bytes is not None:
                sizes["ciphertext_bytes"] = size_metric.ciphertext_bytes
            if size_metric.signature_bytes is not None:
                sizes["signature_bytes"] = size_metric.signature_bytes
            # Include source to indicate whether sizes are measured or fallback
            if size_metric.source and size_metric.source != "unknown":
                sizes["source"] = size_metric.source
            results_by_algo[size_metric.algorithm_name]["sizes"] = sizes

    for algo_name, perf_list in run_result.perf_metrics.items():
        if algo_name in results_by_algo and perf_list:
            # Convert PerfMetrics to dicts
            perf_samples = [p.to_dict() for p in perf_list if p.to_dict()]
            if perf_samples:
                results_by_algo[algo_name]["perf_samples"] = perf_samples
                # Compute median perf metrics
                if len(perf_samples) > 0:
                    median_perf = _compute_median_perf(perf_list)
                    if median_perf:
                        results_by_algo[algo_name]["perf_median"] = median_perf

    # Sort operations within each algorithm for stable output
    # Place unknown operation keys after known operations.
    def get_operation_order(op_key: str) -> int:
        """Get sort order for an operation key, with fallback for unknown ops."""
        try:
            return OPERATION_ORDER.get(Operation(op_key), 99)
        except ValueError:
            return 100

    for algo_data in results_by_algo.values():
        sorted_ops = dict(
            sorted(
                algo_data["operations"].items(),
                key=lambda x: get_operation_order(x[0]),
            )
        )
        algo_data["operations"] = sorted_ops

    output = {
        "metadata": metadata,
        "environment": environment,
        "results": list(results_by_algo.values()),
    }

    # Add TLS detailed results if available (includes success/fail counts, connection info)
    if run_result.tls_results:
        output["tls_details"] = _format_tls_details(run_result.tls_results)

    # Add error info if there were failures
    if run_result.failed_algorithms:
        output["error"] = "partial_failure"
        failed_count = len(run_result.failed_algorithms)
        total_count = failed_count + len(results_by_algo)
        output["message"] = f"{failed_count} of {total_count} algorithms failed"
        output["failed_algorithms"] = [
            {"algorithm": name, "reason": error} for name, error in run_result.failed_algorithms
        ]

    return json.dumps(output, indent=2)


def _compute_median_perf(perf_list: list[PerfMetrics]) -> dict[str, Any]:
    """Compute median values from a list of PerfMetrics.

    Args:
        perf_list: List of PerfMetrics from multiple samples

    Returns:
        Dictionary with median values for each metric
    """
    import statistics

    result: dict[str, Any] = {}

    # Extract non-None values for each metric
    cycles = [p.cycles for p in perf_list if p.cycles is not None]
    instructions = [p.instructions for p in perf_list if p.instructions is not None]
    ipcs = [p.ipc for p in perf_list if p.ipc is not None]
    cache_misses = [p.cache_misses for p in perf_list if p.cache_misses is not None]
    branch_misses = [p.branch_misses for p in perf_list if p.branch_misses is not None]

    if cycles:
        result["cycles"] = int(statistics.median(cycles))
    if instructions:
        result["instructions"] = int(statistics.median(instructions))
    if ipcs:
        result["ipc"] = round(statistics.median(ipcs), 2)
    if cache_misses:
        result["cache_misses"] = int(statistics.median(cache_misses))
    if branch_misses:
        result["branch_misses"] = int(statistics.median(branch_misses))

    return result


def _format_tls_details(tls_results: list[TLSBenchmarkResult]) -> list[dict[str, Any]]:
    """Format TLS benchmark results with detailed metadata.

    Includes success/failure counts and first handshake connection info
    for verification purposes.

    Args:
        tls_results: List of TLSBenchmarkResult from the benchmark run

    Returns:
        List of dictionaries with TLS details for each KEM algorithm
    """
    details = []

    for tls in tls_results:
        entry: dict[str, Any] = {
            "kem_algorithm": tls.kem_algorithm,
            "sig_algorithm": tls.sig_algorithm,
            "success_count": tls.success_count,
            "fail_count": tls.fail_count,
            "total_count": tls.total_count,
        }

        if tls.error:
            entry["error"] = tls.error

        # Add first handshake connection info for verification
        if tls.first_handshake_info:
            entry["connection_info"] = {
                k: v for k, v in tls.first_handshake_info.items() if v is not None
            }

        # Add stats summary if available
        if tls.stats:
            entry["stats"] = {
                "median_us": tls.stats.median,
                "p95_us": tls.stats.p95,
                "p99_us": tls.stats.p99,
                "min_us": tls.stats.min,
                "max_us": tls.stats.max,
            }
            if tls.stats.stdev is not None:
                entry["stats"]["stdev_us"] = tls.stats.stdev

        details.append(entry)

    return details
