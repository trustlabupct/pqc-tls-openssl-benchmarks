"""Parser for TLS handshake benchmark output."""

import re
from dataclasses import dataclass


@dataclass
class HandshakeResult:
    """Parsed result from TLS handshake benchmark.

    Attributes:
        iteration: Iteration number
        duration_us: Handshake duration in microseconds
        kem_algorithm: KEM algorithm used
        sig_algorithm: Signature algorithm used
    """

    iteration: int
    duration_us: float
    kem_algorithm: str | None = None
    sig_algorithm: str | None = None


@dataclass
class HandshakeSummary:
    """Summary of TLS handshake benchmark results including success/failure counts.

    Attributes:
        results: List of successful handshake results
        success_count: Number of successful handshakes
        fail_count: Number of failed handshakes
        total_count: Total number of handshake attempts
        first_handshake_info: TLS connection info from first handshake (for verification)
    """

    results: list[HandshakeResult]
    success_count: int
    fail_count: int
    total_count: int
    first_handshake_info: dict[str, str | None] | None = None


def parse_result_line(output: str) -> tuple[int, int, int] | None:
    """Parse the RESULT status line from bench_tls.sh output.

    Parses output like:
    "RESULT: success=87 fail=13 total=100"

    Args:
        output: Raw output from bench_tls.sh script

    Returns:
        Tuple of (success_count, fail_count, total_count) or None if not found
    """
    pattern = r"RESULT:\s*success=(\d+)\s+fail=(\d+)\s+total=(\d+)"

    for line in output.splitlines():
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))

    return None


def parse_handshake_output(output: str) -> list[HandshakeResult]:
    """Parse TLS handshake benchmark output.

    Parses output like:
    "handshake 1: 1234 us"
    "handshake 2: 1198 us"

    Args:
        output: Raw output from bench_tls.sh script

    Returns:
        List of HandshakeResult objects for each handshake
    """
    results = []

    # Pattern for handshake timing output
    # Format: "handshake N: X us"
    pattern = r"handshake\s+(\d+):\s+([\d.]+)\s*(?:us|microseconds?)"

    for line in output.splitlines():
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            iteration = int(match.group(1))
            duration_us = float(match.group(2))

            results.append(
                HandshakeResult(
                    iteration=iteration,
                    duration_us=duration_us,
                )
            )

    return results


def extract_tls_info(output: str) -> dict[str, str | None]:
    """Extract TLS connection information from s_client output.

    Args:
        output: Raw output from openssl s_client

    Returns:
        Dictionary with TLS connection details
    """
    info: dict[str, str | None] = {
        "protocol": None,
        "cipher": None,
        "key_exchange": None,
        "signature": None,
    }

    # Protocol pattern
    protocol_match = re.search(r"Protocol\s*:\s*(\S+)", output)
    if protocol_match:
        info["protocol"] = protocol_match.group(1)

    # Cipher pattern
    cipher_match = re.search(r"Cipher\s*:\s*(\S+)", output)
    if cipher_match:
        info["cipher"] = cipher_match.group(1)

    # Key exchange from connection info
    kex_match = re.search(r"Server Temp Key:\s*(\S+)", output)
    if kex_match:
        info["key_exchange"] = kex_match.group(1)

    # Signature algorithm
    sig_match = re.search(r"Peer signature type:\s*(\S+)", output)
    if sig_match:
        info["signature"] = sig_match.group(1)

    return info


def parse_tls_info_line(output: str) -> dict[str, str | None] | None:
    """Parse the TLS_INFO line from bench_tls.sh output.

    Parses output like:
    "TLS_INFO: protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 group=X25519 sig=mldsa65"

    Args:
        output: Raw output from bench_tls.sh script

    Returns:
        Dictionary with TLS connection details or None if not found
    """
    pattern = r"TLS_INFO:\s*protocol=(\S+)\s+cipher=(\S+)\s+group=(.+?)\s+sig=(\S+)"

    for line in output.splitlines():
        match = re.search(pattern, line)
        if match:
            return {
                "protocol": match.group(1) if match.group(1) != "unknown" else None,
                "cipher": match.group(2) if match.group(2) != "unknown" else None,
                "key_exchange": match.group(3).strip() if match.group(3) != "unknown" else None,
                "signature": match.group(4) if match.group(4) != "unknown" else None,
            }

    return None


def parse_handshake_output_with_summary(output: str) -> HandshakeSummary:
    """Parse TLS handshake benchmark output including success/failure counts.

    Parses both individual handshake timings and the RESULT summary line.

    Args:
        output: Raw output from bench_tls.sh script

    Returns:
        HandshakeSummary with results and success/failure counts
    """
    results = parse_handshake_output(output)
    result_counts = parse_result_line(output)
    tls_info = parse_tls_info_line(output)

    if result_counts:
        success_count, fail_count, total_count = result_counts
    else:
        # Fallback: infer from parsed results (legacy compatibility)
        success_count = len(results)
        fail_count = 0
        total_count = success_count

    return HandshakeSummary(
        results=results,
        success_count=success_count,
        fail_count=fail_count,
        total_count=total_count,
        first_handshake_info=tls_info,
    )
