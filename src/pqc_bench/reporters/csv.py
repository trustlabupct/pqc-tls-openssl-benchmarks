"""CSV output formatter for benchmark results."""

import csv
import io
from typing import Any

from ..models import Operation
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


def format_csv(run_result: BenchmarkRunResult) -> str:
    """Format benchmark results as CSV.

    Args:
        run_result: Complete benchmark run result

    Returns:
        CSV formatted string
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header (includes TLS-specific columns at the end)
    writer.writerow(
        [
            "algorithm",
            "type",
            "is_hybrid",
            "is_tls",
            "operation",
            "median_us",
            "p95_us",
            "p99_us",
            "min_us",
            "max_us",
            "stdev_us",
            "ops_per_sec",
            "sample_count",
            "public_key_bytes",
            "secret_key_bytes",
            "ciphertext_bytes",
            "signature_bytes",
            "tls_success_count",
            "tls_fail_count",
            "tls_protocol",
            "tls_cipher",
        ]
    )

    sizes_by_algo = {s.algorithm_name: s for s in run_result.size_metrics}

    # Create TLS details lookup (by kem_algorithm name)
    tls_by_kem: dict[str, TLSBenchmarkResult] = {}
    for tls in run_result.tls_results:
        tls_by_kem[tls.kem_algorithm] = tls

    # Group results by algorithm to determine type correctly
    algo_operations: dict[str, set[Operation]] = {}
    for result in run_result.results:
        if result.algorithm_name not in algo_operations:
            algo_operations[result.algorithm_name] = set()
        algo_operations[result.algorithm_name].add(result.operation)

    # Determine algorithm type and flags from registry first, then fallback to operations
    from ..algorithms.registry import AlgorithmType, registry

    algo_types: dict[str, str] = {}
    algo_info: dict[str, dict] = {}

    for algo_name, ops in algo_operations.items():
        # Check for TLS handshake-only results first
        if ops == {Operation.HANDSHAKE}:
            algo_types[algo_name] = "tls"
            algo_info[algo_name] = {"is_hybrid": False, "is_tls": True}
            continue

        # Try registry first
        algo = registry.get(algo_name)
        if algo:
            algo_types[algo_name] = "kem" if algo.type == AlgorithmType.KEM else "signature"
            algo_info[algo_name] = {"is_hybrid": algo.is_hybrid, "is_tls": False}
        else:
            # Fallback to operation-based detection
            if Operation.ENCAPS in ops or Operation.DECAPS in ops:
                algo_types[algo_name] = "kem"
            elif Operation.SIGN in ops or Operation.VERIFY in ops:
                algo_types[algo_name] = "signature"
            else:
                algo_types[algo_name] = "unknown"
            algo_info[algo_name] = {"is_hybrid": False, "is_tls": False}

    # Sort results for stable output
    sorted_results = sorted(
        run_result.results,
        key=lambda r: (r.algorithm_name, OPERATION_ORDER.get(r.operation, 99)),
    )

    for result in sorted_results:
        algo_type = algo_types.get(result.algorithm_name, "unknown")
        info = algo_info.get(result.algorithm_name, {})
        is_hybrid = info.get("is_hybrid", False)
        is_tls = info.get("is_tls", False)

        # Get size metrics (use 'is not None' for correct check)
        sizes = sizes_by_algo.get(result.algorithm_name)
        pk = sizes.public_key_bytes if sizes and sizes.public_key_bytes is not None else ""
        sk = sizes.secret_key_bytes if sizes and sizes.secret_key_bytes is not None else ""
        ct = sizes.ciphertext_bytes if sizes and sizes.ciphertext_bytes is not None else ""
        sig = sizes.signature_bytes if sizes and sizes.signature_bytes is not None else ""

        # Get TLS-specific info if this is a handshake result
        tls_success = ""
        tls_fail = ""
        tls_protocol = ""
        tls_cipher = ""
        if result.operation == Operation.HANDSHAKE and result.tls_kem:
            tls = tls_by_kem.get(result.tls_kem)
            if tls:
                tls_success = tls.success_count
                tls_fail = tls.fail_count
                if tls.first_handshake_info:
                    tls_protocol = tls.first_handshake_info.get("protocol") or ""
                    tls_cipher = tls.first_handshake_info.get("cipher") or ""

        writer.writerow(
            [
                result.algorithm_name,
                algo_type,
                str(is_hybrid).lower(),
                str(is_tls).lower(),
                result.operation.value,
                f"{result.median_us:.2f}",
                f"{result.p95_us:.2f}",
                f"{result.p99_us:.2f}",
                f"{result.min_us:.2f}",
                f"{result.max_us:.2f}",
                f"{result.stdev_us:.2f}" if result.stdev_us is not None else "",
                f"{result.ops_per_sec:.2f}",
                result.sample_count,
                pk,
                sk,
                ct,
                sig,
                tls_success,
                tls_fail,
                tls_protocol,
                tls_cipher,
            ]
        )

    return output.getvalue()


def format_json_to_csv(data: dict[str, Any]) -> str:
    """Convert JSON benchmark data to CSV format.

    Args:
        data: JSON data from benchmark results

    Returns:
        CSV formatted string
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header (includes TLS-specific columns)
    writer.writerow(
        [
            "algorithm",
            "type",
            "is_hybrid",
            "is_tls",
            "operation",
            "median_us",
            "p95_us",
            "p99_us",
            "min_us",
            "max_us",
            "stdev_us",
            "ops_per_sec",
            "sample_count",
            "public_key_bytes",
            "secret_key_bytes",
            "ciphertext_bytes",
            "signature_bytes",
            "tls_success_count",
            "tls_fail_count",
            "tls_protocol",
            "tls_cipher",
        ]
    )

    # Build TLS details lookup from tls_details section
    tls_by_kem: dict[str, dict] = {}
    for tls in data.get("tls_details", []):
        tls_by_kem[tls.get("kem_algorithm", "")] = tls

    for result in data.get("results", []):
        algo = result.get("algorithm", "")
        algo_type = result.get("type", "")
        is_hybrid = result.get("is_hybrid", False)
        is_tls = result.get("is_tls", False)
        sizes = result.get("sizes", {})
        tls_info = result.get("tls", {})

        for op_name, op_data in result.get("operations", {}).items():
            # Get TLS-specific info for handshake operations
            tls_success = ""
            tls_fail = ""
            tls_protocol = ""
            tls_cipher = ""
            if op_name == "handshake" and tls_info.get("kem"):
                tls = tls_by_kem.get(tls_info["kem"], {})
                tls_success = tls.get("success_count", "")
                tls_fail = tls.get("fail_count", "")
                conn_info = tls.get("connection_info", {})
                tls_protocol = conn_info.get("protocol", "")
                tls_cipher = conn_info.get("cipher", "")

            writer.writerow(
                [
                    algo,
                    algo_type,
                    str(is_hybrid).lower(),
                    str(is_tls).lower(),
                    op_name,
                    f"{op_data.get('median_us', 0):.2f}",
                    f"{op_data.get('p95_us', 0):.2f}",
                    f"{op_data.get('p99_us', 0):.2f}",
                    f"{op_data.get('min_us', 0):.2f}",
                    f"{op_data.get('max_us', 0):.2f}",
                    f"{op_data.get('stdev_us', 0):.2f}"
                    if op_data.get("stdev_us") is not None
                    else "",
                    f"{op_data.get('ops_per_sec', 0):.2f}",
                    op_data.get("sample_count", ""),
                    sizes.get("public_key_bytes", ""),
                    sizes.get("secret_key_bytes", ""),
                    sizes.get("ciphertext_bytes", ""),
                    sizes.get("signature_bytes", ""),
                    tls_success,
                    tls_fail,
                    tls_protocol,
                    tls_cipher,
                ]
            )

    return output.getvalue()
