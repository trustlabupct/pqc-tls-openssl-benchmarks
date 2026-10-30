"""Data models for benchmark results and metrics."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4


class Operation(str, Enum):
    """Operations that can be benchmarked."""

    # KEM operations
    KEYGEN = "keygen"
    ENCAPS = "encaps"
    DECAPS = "decaps"

    # Signature operations
    SIGN = "sign"
    VERIFY = "verify"

    # TLS operations
    HANDSHAKE = "handshake"


class OutputFormat(str, Enum):
    """Available output formats."""

    TEXT = "text"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"


@dataclass
class PerfMetrics:
    """CPU performance metrics from perf stat.

    These metrics represent the entire benchmark run for an algorithm,
    not per-operation metrics (since perf wraps the whole openssl speed command).

    Attributes:
        cycles: Total CPU cycles
        instructions: Total instructions executed
        ipc: Instructions per cycle
        cache_misses: L1 cache misses
        branch_misses: Branch prediction misses
    """

    cycles: int | None = None
    instructions: int | None = None
    ipc: float | None = None
    cache_misses: int | None = None
    branch_misses: int | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary, omitting None values."""
        result = {}
        if self.cycles is not None:
            result["cycles"] = self.cycles
        if self.instructions is not None:
            result["instructions"] = self.instructions
        if self.ipc is not None:
            result["ipc"] = self.ipc
        if self.cache_misses is not None:
            result["cache_misses"] = self.cache_misses
        if self.branch_misses is not None:
            result["branch_misses"] = self.branch_misses
        return result


@dataclass
class BenchmarkResult:
    """Aggregated statistics for a benchmark run.

    Statistics are computed across multiple samples (repeated openssl speed runs).
    Each sample runs for a fixed duration (e.g., 3 seconds) and reports average
    us_per_op. Percentiles are computed across these sample averages.

    Attributes:
        algorithm_name: Reference to Algorithm.name (or combined name for TLS)
        operation: Operation type (keygen, encaps, etc.)
        median_us: Median latency in microseconds (across samples)
        p95_us: 95th percentile latency (across samples)
        p99_us: 99th percentile latency (across samples)
        min_us: Minimum latency observed (across samples)
        max_us: Maximum latency observed (across samples)
        ops_per_sec: Operations per second (derived from median)
        iteration_count: Total operations across all samples
        sample_count: Number of repeated benchmark runs (samples)
        stdev_us: Standard deviation across samples (None if < 2 samples)
        timings_us: Raw sample timings for reproducibility (optional)
        tls_kem: KEM algorithm name for TLS handshake results (optional)
        tls_sig: Signature algorithm name for TLS handshake results (optional)
    """

    algorithm_name: str
    operation: Operation
    median_us: float
    p95_us: float
    p99_us: float
    min_us: float
    max_us: float
    ops_per_sec: float
    iteration_count: int
    sample_count: int = 1
    stdev_us: float | None = None
    timings_us: list[float] | None = None
    tls_kem: str | None = None
    tls_sig: str | None = None

    def __post_init__(self) -> None:
        """Validate benchmark result constraints."""
        if self.median_us <= 0:
            raise ValueError(f"Median latency must be positive, got {self.median_us}")
        if self.sample_count < 1:
            raise ValueError(f"Sample count must be at least 1, got {self.sample_count}")


@dataclass
class SizeMetrics:
    """Size measurements for an algorithm.

    Attributes:
        algorithm_name: Reference to Algorithm.name
        public_key_bytes: Public key size in bytes (None if unknown)
        secret_key_bytes: Secret/private key size in bytes (None if unknown)
        ciphertext_bytes: Ciphertext size (KEM only)
        signature_bytes: Signature size (signature only)
        source: Where sizes came from ("measured", "fallback", or "unknown")
    """

    algorithm_name: str
    public_key_bytes: int | None = None
    secret_key_bytes: int | None = None
    ciphertext_bytes: int | None = None
    signature_bytes: int | None = None
    source: str = "unknown"

    def __post_init__(self) -> None:
        """Validate size metrics."""
        if self.public_key_bytes is not None and self.public_key_bytes <= 0:
            raise ValueError("public_key_bytes must be positive when specified")
        if self.secret_key_bytes is not None and self.secret_key_bytes <= 0:
            raise ValueError("secret_key_bytes must be positive when specified")


@dataclass
class Environment:
    """Runtime environment metadata for reproducibility.

    Attributes:
        openssl_version: OpenSSL version string (must be 3.x)
        oqs_provider_version: OQS-provider version (must be >= 0.6.0)
        platform: OS and architecture
        cpu_model: CPU model name
        kernel_version: Kernel version (Linux)
        captured_at: When environment was captured
        liboqs_version: liboqs version (if detectable)
    """

    openssl_version: str
    oqs_provider_version: str
    platform: str
    cpu_model: str | None = None
    kernel_version: str | None = None
    captured_at: datetime = field(default_factory=datetime.now)
    liboqs_version: str | None = None


@dataclass
class Report:
    """A complete benchmark report containing multiple results.

    Attributes:
        id: Unique report identifier
        created_at: Report generation timestamp
        environment: Environment metadata
        results: All benchmark results
        size_metrics: All size measurements
        format: Output format
        includes_hybrid: Whether hybrid algorithms included
        includes_pure_pqc: Whether pure PQC included
    """

    environment: Environment
    results: list[BenchmarkResult]
    size_metrics: list[SizeMetrics]
    format: OutputFormat = OutputFormat.TEXT
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=datetime.now)
    includes_hybrid: bool = False
    includes_pure_pqc: bool = False

    def __post_init__(self) -> None:
        """Validate report completeness per constitution."""
        # Complete reports require hybrid and pure PQC results.
        # Report generation validates this requirement.
        pass
