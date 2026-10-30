"""Text output formatter for benchmark results."""

from typing import Any

from ..models import BenchmarkResult, Operation, SizeMetrics
from ..runner import BenchmarkRunResult

# Canonical operation ordering for stable output
OPERATION_ORDER = {
    Operation.KEYGEN: 0,
    Operation.ENCAPS: 1,
    Operation.DECAPS: 2,
    Operation.SIGN: 1,
    Operation.VERIFY: 2,
    Operation.HANDSHAKE: 3,
}


def format_text(run_result: BenchmarkRunResult) -> str:
    """Format benchmark results as human-readable text.

    Args:
        run_result: Complete benchmark run result

    Returns:
        Formatted text output
    """
    lines = []

    # Header
    lines.append("PQC Benchmark Results")
    lines.append("=" * 60)
    lines.append(
        f"Environment: OpenSSL {run_result.environment.openssl_version}, "
        f"oqs-provider {run_result.environment.oqs_provider_version}, "
        f"{run_result.environment.platform}"
    )
    if run_result.environment.cpu_model:
        lines.append(f"CPU: {run_result.environment.cpu_model}")

    # Show sample count from speed results only (exclude TLS handshakes)
    speed_results = [r for r in run_result.results if r.operation != Operation.HANDSHAKE]
    if speed_results:
        sample_count = max((r.sample_count for r in speed_results), default=0)
        lines.append(f"Samples per algorithm: {sample_count}")
    lines.append("")

    # Group results by algorithm
    results_by_algo: dict[str, list[BenchmarkResult]] = {}
    for result in run_result.results:
        if result.algorithm_name not in results_by_algo:
            results_by_algo[result.algorithm_name] = []
        results_by_algo[result.algorithm_name].append(result)

    sizes_by_algo: dict[str, SizeMetrics] = {s.algorithm_name: s for s in run_result.size_metrics}

    # Format each algorithm's results
    for algo_name, results in sorted(results_by_algo.items()):
        # Sort operations for stable output
        results = sorted(results, key=lambda r: OPERATION_ORDER.get(r.operation, 99))

        # Determine type based on operations
        ops = {r.operation for r in results}
        if ops == {Operation.HANDSHAKE}:
            algo_type = "TLS"
        else:
            is_kem = any(r.operation in (Operation.ENCAPS, Operation.DECAPS) for r in results)
            algo_type = "KEM" if is_kem else "Signature"

        lines.append(f"Algorithm: {algo_name} ({algo_type})")

        for result in results:
            stdev_info = ""
            if result.stdev_us is not None:
                stdev_info = f", stdev={result.stdev_us:.1f}"
            lines.append(
                f"  {result.operation.value:<10} "
                f"{result.median_us:>8.1f} us (median), "
                f"{result.p95_us:>8.1f} us (p95), "
                f"{result.p99_us:>8.1f} us (p99){stdev_info}"
            )

        # Add size info (use 'is not None' for correct check)
        if algo_name in sizes_by_algo:
            sizes = sizes_by_algo[algo_name]
            size_parts = []
            if sizes.public_key_bytes is not None:
                size_parts.append(f"pk={sizes.public_key_bytes}B")
            if sizes.secret_key_bytes is not None:
                size_parts.append(f"sk={sizes.secret_key_bytes}B")
            if sizes.ciphertext_bytes is not None:
                size_parts.append(f"ct={sizes.ciphertext_bytes}B")
            if sizes.signature_bytes is not None:
                size_parts.append(f"sig={sizes.signature_bytes}B")
            if size_parts:
                lines.append(f"  Sizes: {', '.join(size_parts)}")

        lines.append("")

    # Report failures
    if run_result.failed_algorithms:
        lines.append("Failed Algorithms")
        lines.append("-" * 40)
        for algo_name, error in run_result.failed_algorithms:
            lines.append(f"  {algo_name}: {error}")
        lines.append("")

    # Summary
    total_success = len(results_by_algo)
    total_failed = len(run_result.failed_algorithms)
    lines.append(f"Summary: {total_success} algorithms benchmarked, {total_failed} failed")

    return "\n".join(lines)


def format_json_to_markdown(data: dict[str, Any]) -> str:
    """Convert JSON benchmark data to markdown format.

    Args:
        data: JSON data from benchmark results

    Returns:
        Markdown formatted string
    """
    lines = []

    # Header
    lines.append("# PQC Benchmark Results")
    lines.append("")

    # Environment
    env = data.get("environment", {})
    lines.append("## Environment")
    lines.append("")
    lines.append(f"- **OpenSSL Version**: {env.get('openssl_version', 'unknown')}")
    lines.append(f"- **OQS Provider**: {env.get('oqs_provider_version', 'unknown')}")
    lines.append(f"- **Platform**: {env.get('platform', 'unknown')}")
    if env.get("cpu_model"):
        lines.append(f"- **CPU**: {env.get('cpu_model')}")
    lines.append("")

    # Results table
    results = data.get("results", [])
    if results:
        lines.append("## Results")
        lines.append("")
        lines.append("| Algorithm | Type | Operation | Median (us) | P95 (us) | P99 (us) |")
        lines.append("|-----------|------|-----------|-------------|----------|----------|")

        for r in results:
            algo = r.get("algorithm", "")
            algo_type = r.get("type", "")
            for op_name, op_data in r.get("operations", {}).items():
                median = op_data.get("median_us", 0)
                p95 = op_data.get("p95_us", 0)
                p99 = op_data.get("p99_us", 0)
                lines.append(
                    f"| {algo} | {algo_type} | {op_name} | {median:.1f} | {p95:.1f} | {p99:.1f} |"
                )

        lines.append("")

    return "\n".join(lines)
