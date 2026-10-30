"""Parser for OpenSSL speed command output."""

import re
from dataclasses import dataclass


@dataclass
class SpeedResult:
    """Parsed result from openssl speed output.

    Attributes:
        algorithm: Algorithm name
        operation: Operation type (keygen, encaps, decaps, sign, verify)
        ops_count: Number of operations performed
        duration_sec: Duration of the benchmark in seconds
        ops_per_sec: Calculated operations per second
        us_per_op: Calculated microseconds per operation
    """

    algorithm: str
    operation: str
    ops_count: int
    duration_sec: float
    ops_per_sec: float
    us_per_op: float


def parse_speed_output(output: str, duration_hint: float = 3.0) -> list[SpeedResult]:
    """Parse OpenSSL speed command output.

    Supports three output formats:
    1. Machine-readable (-mr flag): "+F:...:algorithm:...:ops:time"
    2. Detailed output: "N <algorithm> <operation> ops in X.XXs"
    3. Summary table (fallback): "algorithm time1 time2 time3 ops1 ops2 ops3"

    Args:
        output: Raw output from openssl speed command
        duration_hint: Expected duration in seconds (used for summary table fallback)

    Returns:
        List of SpeedResult objects for each operation found
    """
    # Try machine-readable format first (most reliable)
    results = _parse_machine_readable(output)
    if results:
        return results

    # Try detailed output format
    results = _parse_detailed_output(output)
    if results:
        return results

    # Fallback to summary table (least reliable)
    return _parse_summary_table(output, duration_hint)


def _parse_machine_readable(output: str) -> list[SpeedResult]:
    """Parse OpenSSL speed -mr (machine readable) output.

    oqs-provider machine-readable format:
    +DTP:algorithm:operation:count  (doing operation)
    +Rxx:ops_count:algorithm:time   (result for operation)
    +Fxx:...                        (final summary, ignored)

    Example lines:
    +DTP:mlkem768:keygen:1
    +R15:63850:mlkem768:1.00
    +DTP:mlkem768:encaps:1
    +R16:68545:mlkem768:0.99

    Standard OpenSSL -mr format (for reference):
    +F:index:algorithm:operation:ops_count:time_seconds

    Args:
        output: Raw output from openssl speed -mr command

    Returns:
        List of SpeedResult objects
    """
    results = []

    # Track current operation from +DTP lines
    current_operation = None

    for line in output.splitlines():
        line = line.strip()

        # Parse +DTP lines to know what operation is being measured
        # Format: +DTP:algorithm:operation:count
        if line.startswith("+DTP:"):
            parts = line.split(":")
            if len(parts) >= 3:
                # parts[1] is algorithm name (unused here, we get it from +R line)
                current_operation = parts[2].lower()
                # Normalize operation names (oqs-provider uses "signs" not "sign")
                if current_operation == "signs":
                    current_operation = "sign"
            continue

        # Parse +R lines for actual results
        # Format: +Rxx:ops_count:algorithm:time
        if line.startswith("+R"):
            # Match pattern like +R15:63850:mlkem768:1.00 or +R15:63850:ML-KEM-768:1.00
            match = re.match(r"^\+R\d+:(\d+):([A-Za-z0-9_+-]+):([\d.]+)", line)
            if match and current_operation:
                ops_count = int(match.group(1))
                algorithm = match.group(2)
                duration = float(match.group(3))

                if duration > 0 and ops_count > 0:
                    ops_per_sec = ops_count / duration
                    us_per_op = (duration * 1_000_000) / ops_count

                    results.append(
                        SpeedResult(
                            algorithm=algorithm,
                            operation=current_operation,
                            ops_count=ops_count,
                            duration_sec=duration,
                            ops_per_sec=ops_per_sec,
                            us_per_op=us_per_op,
                        )
                    )
                # Reset for next operation
                current_operation = None
            continue

        # Also try standard OpenSSL -mr format (for compatibility)
        # Format: +F:index:algorithm:operation:ops_count:time_seconds
        if line.startswith("+F:"):
            match = re.match(r"^\+F:(\d+):([A-Za-z0-9_+-]+):([A-Za-z0-9_+-]+):(\d+):([\d.]+)", line)
            if match:
                algorithm = match.group(2)
                operation = match.group(3).lower()
                ops_count = int(match.group(4))
                duration = float(match.group(5))

                if duration > 0 and ops_count > 0:
                    ops_per_sec = ops_count / duration
                    us_per_op = (duration * 1_000_000) / ops_count

                    results.append(
                        SpeedResult(
                            algorithm=algorithm,
                            operation=operation,
                            ops_count=ops_count,
                            duration_sec=duration,
                            ops_per_sec=ops_per_sec,
                            us_per_op=us_per_op,
                        )
                    )

    return results


def _parse_detailed_output(output: str) -> list[SpeedResult]:
    """Parse OpenSSL speed detailed output format.

    Parses output like:
    "Doing mlkem768 keygen ops for 3s: 12345 mlkem768 keygen ops in 3.00s"
    "Doing mlkem768 KEM keygen ops for 3s: 12345 mlkem768 KEM keygen ops in 3.00s"
    "Doing ML-KEM-768 keygen ops for 3s: 12345 ML-KEM-768 keygen ops in 3.00s"

    Args:
        output: Raw output from openssl speed command

    Returns:
        List of SpeedResult objects for each operation found
    """
    results = []

    # Pattern for speed output with optional "KEM"/"sig" prefix
    # Format: "N <algorithm> [KEM|sig] <operation> ops in X.XXs"
    # Algorithm names can contain: letters, digits, underscores, hyphens, plus signs
    # Examples:
    #   "132077 mlkem768 KEM keygen ops in 2.98s"
    #   "12345 mldsa65 sign ops in 3.00s"
    #   "12345 ML-KEM-768 keygen ops in 3.00s"
    #   "12345 SPHINCS+-SHA2-128f sign ops in 3.00s"
    pattern = (
        r"(\d+)\s+([A-Za-z0-9_+-]+)\s+(?:KEM\s+|sig\s+)?([A-Za-z0-9_+-]+)\s+ops?\s+in\s+([\d.]+)s"
    )

    for line in output.splitlines():
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            ops_count = int(match.group(1))
            algorithm = match.group(2)
            operation = match.group(3).lower()
            duration = float(match.group(4))

            if duration > 0 and ops_count > 0:
                ops_per_sec = ops_count / duration
                us_per_op = (duration * 1_000_000) / ops_count

                results.append(
                    SpeedResult(
                        algorithm=algorithm,
                        operation=operation,
                        ops_count=ops_count,
                        duration_sec=duration,
                        ops_per_sec=ops_per_sec,
                        us_per_op=us_per_op,
                    )
                )

    return results


def _detect_duration_from_output(output: str) -> float:
    """Try to detect the actual benchmark duration from output.

    Looks for patterns like "for 5s" or "for 10s" in the output.

    Args:
        output: Raw output from openssl speed command

    Returns:
        Detected duration in seconds, or 3.0 as default
    """
    # Look for "for Xs" pattern in "Doing ... for Xs:" lines
    match = re.search(r"for\s+(\d+)s", output)
    if match:
        return float(match.group(1))
    return 3.0


def _parse_summary_table(output: str, duration_hint: float = 3.0) -> list[SpeedResult]:
    """Parse OpenSSL speed summary table format.

    Parses the final summary table like:
    "           mlkem768 0.000023s 0.000020s 0.000024s   44321.1   48990.9   41135.3"

    Args:
        output: Raw output from openssl speed command
        duration_hint: Expected duration (used to estimate ops_count)

    Returns:
        List of SpeedResult objects
    """
    results = []

    # Try to detect actual duration from output
    duration = _detect_duration_from_output(output)
    if duration == 3.0:
        duration = duration_hint  # Use hint if detection failed

    # Detect if this is a signature algorithm by looking for header row
    # KEM header: "keygen    encaps    decaps keygens/s  encaps/s  decaps/s"
    # Sig header: "keygen      sign    verify keygens/s    sign/s  verify/s"
    is_signature = "sign" in output.lower() and "verify" in output.lower()

    # Pattern for summary table line
    # Format: algorithm time1 time2 time3 ops1 ops2 ops3
    # Times are in seconds with 's' suffix
    # The algorithm name is right-padded with spaces
    # Algorithm names can contain: letters, digits, underscores, hyphens, plus signs
    pattern = (
        r"^\s+([A-Za-z0-9_+-]+)\s+([\d.]+)s\s+([\d.]+)s\s+([\d.]+)s"
        r"\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)"
    )

    for line in output.splitlines():
        match = re.search(pattern, line)
        if match:
            algorithm = match.group(1)
            keygen_time = float(match.group(2))
            op2_time = float(match.group(3))
            op3_time = float(match.group(4))
            keygen_ops = float(match.group(5))
            op2_ops = float(match.group(6))
            op3_ops = float(match.group(7))

            # keygen
            if keygen_time > 0:
                results.append(
                    SpeedResult(
                        algorithm=algorithm,
                        operation="keygen",
                        ops_count=round(keygen_ops * duration),
                        duration_sec=duration,
                        ops_per_sec=keygen_ops,
                        us_per_op=keygen_time * 1_000_000,
                    )
                )

            # Second operation (encaps or sign)
            op2_name = "sign" if is_signature else "encaps"
            if op2_time > 0:
                results.append(
                    SpeedResult(
                        algorithm=algorithm,
                        operation=op2_name,
                        ops_count=round(op2_ops * duration),
                        duration_sec=duration,
                        ops_per_sec=op2_ops,
                        us_per_op=op2_time * 1_000_000,
                    )
                )

            # Third operation (decaps or verify)
            op3_name = "verify" if is_signature else "decaps"
            if op3_time > 0:
                results.append(
                    SpeedResult(
                        algorithm=algorithm,
                        operation=op3_name,
                        ops_count=round(op3_ops * duration),
                        duration_sec=duration,
                        ops_per_sec=op3_ops,
                        us_per_op=op3_time * 1_000_000,
                    )
                )

    return results


def parse_size_info(output: str, algorithm: str) -> dict[str, int | None]:
    """Parse key and ciphertext size information from OpenSSL output.

    Attempts to extract size information from various OpenSSL commands.

    Args:
        output: Raw output from openssl command
        algorithm: Algorithm name to match

    Returns:
        Dictionary with keys: public_key_bytes, secret_key_bytes, ciphertext_bytes, signature_bytes
    """
    sizes: dict[str, int | None] = {
        "public_key_bytes": None,
        "secret_key_bytes": None,
        "ciphertext_bytes": None,
        "signature_bytes": None,
    }

    # Pattern for size information in provider output
    # Format varies, but typically includes "public key: N bytes" or similar
    pk_patterns = [
        r"public[_\s]?key[:\s]+(\d+)\s*(?:bytes|B)",
        r"pk[:\s]+(\d+)\s*(?:bytes|B)",
    ]
    sk_patterns = [
        r"secret[_\s]?key[:\s]+(\d+)\s*(?:bytes|B)",
        r"private[_\s]?key[:\s]+(\d+)\s*(?:bytes|B)",
        r"sk[:\s]+(\d+)\s*(?:bytes|B)",
    ]
    ct_patterns = [
        r"ciphertext[:\s]+(\d+)\s*(?:bytes|B)",
        r"ct[:\s]+(\d+)\s*(?:bytes|B)",
    ]
    sig_patterns = [
        r"signature[:\s]+(\d+)\s*(?:bytes|B)",
        r"sig[:\s]+(\d+)\s*(?:bytes|B)",
    ]

    for pattern in pk_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            sizes["public_key_bytes"] = int(match.group(1))
            break

    for pattern in sk_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            sizes["secret_key_bytes"] = int(match.group(1))
            break

    for pattern in ct_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            sizes["ciphertext_bytes"] = int(match.group(1))
            break

    for pattern in sig_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            sizes["signature_bytes"] = int(match.group(1))
            break

    return sizes


# Known sizes for standard algorithms (fallback when not parseable from output)
KNOWN_KEM_SIZES: dict[str, dict[str, int]] = {
    "mlkem512": {"public_key_bytes": 800, "secret_key_bytes": 1632, "ciphertext_bytes": 768},
    "mlkem768": {"public_key_bytes": 1184, "secret_key_bytes": 2400, "ciphertext_bytes": 1088},
    "mlkem1024": {"public_key_bytes": 1568, "secret_key_bytes": 3168, "ciphertext_bytes": 1568},
    "frodo640aes": {"public_key_bytes": 9616, "secret_key_bytes": 19888, "ciphertext_bytes": 9720},
    "frodo976aes": {
        "public_key_bytes": 15632,
        "secret_key_bytes": 31296,
        "ciphertext_bytes": 15744,
    },
    "frodo1344aes": {
        "public_key_bytes": 21520,
        "secret_key_bytes": 43088,
        "ciphertext_bytes": 21632,
    },
    "frodo640shake": {
        "public_key_bytes": 9616,
        "secret_key_bytes": 19888,
        "ciphertext_bytes": 9720,
    },
    "frodo976shake": {
        "public_key_bytes": 15632,
        "secret_key_bytes": 31296,
        "ciphertext_bytes": 15744,
    },
    "frodo1344shake": {
        "public_key_bytes": 21520,
        "secret_key_bytes": 43088,
        "ciphertext_bytes": 21632,
    },
    "bikel1": {"public_key_bytes": 1541, "secret_key_bytes": 3114, "ciphertext_bytes": 1573},
    "bikel3": {"public_key_bytes": 3083, "secret_key_bytes": 6198, "ciphertext_bytes": 3115},
    "bikel5": {"public_key_bytes": 5122, "secret_key_bytes": 10276, "ciphertext_bytes": 5154},
}

KNOWN_SIG_SIZES: dict[str, dict[str, int]] = {
    "mldsa44": {"public_key_bytes": 1312, "secret_key_bytes": 2560, "signature_bytes": 2420},
    "mldsa65": {"public_key_bytes": 1952, "secret_key_bytes": 4032, "signature_bytes": 3309},
    "mldsa87": {"public_key_bytes": 2592, "secret_key_bytes": 4896, "signature_bytes": 4627},
    "falcon512": {"public_key_bytes": 897, "secret_key_bytes": 1281, "signature_bytes": 666},
    "falcon1024": {"public_key_bytes": 1793, "secret_key_bytes": 2305, "signature_bytes": 1280},
    "falconpadded512": {"public_key_bytes": 897, "secret_key_bytes": 1281, "signature_bytes": 666},
    "falconpadded1024": {
        "public_key_bytes": 1793,
        "secret_key_bytes": 2305,
        "signature_bytes": 1280,
    },
    "sphincssha2128fsimple": {
        "public_key_bytes": 32,
        "secret_key_bytes": 64,
        "signature_bytes": 17088,
    },
    "sphincssha2128ssimple": {
        "public_key_bytes": 32,
        "secret_key_bytes": 64,
        "signature_bytes": 7856,
    },
    "sphincssha2192fsimple": {
        "public_key_bytes": 48,
        "secret_key_bytes": 96,
        "signature_bytes": 35664,
    },
    "mayo1": {"public_key_bytes": 1168, "secret_key_bytes": 24, "signature_bytes": 321},
    "mayo2": {"public_key_bytes": 5488, "secret_key_bytes": 24, "signature_bytes": 180},
    "mayo3": {"public_key_bytes": 2656, "secret_key_bytes": 32, "signature_bytes": 577},
    "mayo5": {"public_key_bytes": 5008, "secret_key_bytes": 40, "signature_bytes": 838},
}


def get_algorithm_sizes(algorithm: str, is_kem: bool = True) -> dict:
    """Get known sizes for an algorithm.

    Args:
        algorithm: Algorithm name
        is_kem: Whether this is a KEM algorithm

    Returns:
        Dictionary with size information including 'source' key
    """
    sizes: dict = {
        "public_key_bytes": None,
        "secret_key_bytes": None,
        "ciphertext_bytes": None,
        "signature_bytes": None,
        "source": "unknown",
    }

    known = KNOWN_KEM_SIZES if is_kem else KNOWN_SIG_SIZES
    if algorithm in known:
        sizes.update(known[algorithm])
        sizes["source"] = "fallback"  # These are hardcoded reference values

    return sizes
