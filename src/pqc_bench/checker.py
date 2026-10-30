"""Dependency checker for OpenSSL and oqs-provider."""

import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime

from .models import Environment


def _get_resolved_paths() -> tuple[str, str, str]:
    """Get resolved openssl path, provider path, and library path from environment.

    Returns:
        Tuple of (openssl_path, provider_path, library_path)
    """
    openssl_path = os.environ.get("PQC_BENCH_OPENSSL", "openssl")
    provider_path = os.environ.get("PQC_BENCH_PROVIDER_PATH", "")
    library_path = os.environ.get("PQC_BENCH_LD_LIBRARY_PATH", "")
    return openssl_path, provider_path, library_path


def _get_subprocess_env(library_path: str = "") -> dict[str, str] | None:
    """Get environment dict for subprocess calls with LD_LIBRARY_PATH if needed.

    Args:
        library_path: LD_LIBRARY_PATH value to set

    Returns:
        Environment dict with LD_LIBRARY_PATH set, or None if not needed
    """
    if not library_path:
        return None
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = library_path
    return env


# Native PQC algorithms supported in OpenSSL 3.5+ that work with `openssl speed`
#
# OpenSSL 3.5 with oqs-provider 0.9.0+:
# - oqs-provider disables its ML-KEM and ML-DSA implementations.
# - Native algorithms require OpenSSL names, such as ML-KEM-768.
# - Native `openssl speed` supports ML-KEM.
# - Native `openssl speed` does not support ML-DSA.
#
# For ML-DSA benchmarking, use OpenSSL 3.4 with oqs-provider
#
# Reference: https://github.com/open-quantum-safe/oqs-provider#using-with-openssl-350
NATIVE_KEMS = {
    # Standalone ML-KEM (disabled in oqs-provider with OpenSSL 3.5)
    "mlkem512",
    "mlkem768",
    "mlkem1024",
    # Native OpenSSL 3.5 algorithm names
    "ml-kem-512",
    "ml-kem-768",
    "ml-kem-1024",
    # Native hybrid KEMs (also disabled in oqs-provider with OpenSSL 3.5)
    "x25519mlkem768",
    "x448mlkem1024",
    "secp256r1mlkem768",
    "secp384r1mlkem1024",
}

# ML-DSA is natively supported in OpenSSL 3.5 but `openssl speed` doesn't work
# for signature algorithms. oqs-provider also disables its ML-DSA when OpenSSL 3.5
# is detected. Therefore ML-DSA benchmarking requires OpenSSL 3.4 with oqs-provider.
#
# SLH-DSA (SPHINCS+ FIPS 205) may also be native in future OpenSSL versions.
NATIVE_SIGS: set[str] = set()  # OpenSSL 3.5 speed benchmarks do not support native signatures.


def is_native_algorithm(algorithm: str) -> bool:
    """Check if an algorithm is natively supported in OpenSSL 3.5+.

    Args:
        algorithm: Algorithm name to check

    Returns:
        True if the algorithm is natively supported
    """
    algo_lower = algorithm.lower()
    return algo_lower in NATIVE_KEMS or algo_lower in NATIVE_SIGS


@dataclass
class NativePQCCheck:
    """Result of checking for native OpenSSL PQC support.

    Attributes:
        is_available: Whether native PQC is available (OpenSSL >= 3.5)
        openssl_version: Detected OpenSSL version
        supported_kems: List of natively supported KEM algorithms
        supported_sigs: List of natively supported signature algorithms
    """

    is_available: bool
    openssl_version: str | None = None
    supported_kems: list[str] = field(default_factory=list)
    supported_sigs: list[str] = field(default_factory=list)


def check_native_pqc_support(
    openssl_path: str = "openssl",
    library_path: str = "",
) -> NativePQCCheck:
    """Check if OpenSSL has native PQC support (version 3.5+).

    Args:
        openssl_path: Path to OpenSSL binary
        library_path: LD_LIBRARY_PATH for the OpenSSL binary

    Returns:
        NativePQCCheck with availability and supported algorithms
    """
    # Build environment with library path if specified
    env = os.environ.copy()
    if library_path:
        env["LD_LIBRARY_PATH"] = library_path

    # Get OpenSSL version
    try:
        result = subprocess.run(
            [openssl_path, "version"],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        if result.returncode != 0:
            return NativePQCCheck(is_available=False)

        version_match = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.?(\d*)", result.stdout)
        if not version_match:
            return NativePQCCheck(is_available=False)

        major = int(version_match.group(1))
        minor = int(version_match.group(2))
        version_str = f"{major}.{minor}"
        if version_match.group(3):
            version_str += f".{version_match.group(3)}"

        # Native PQC requires OpenSSL 3.5+
        if major < 3 or (major == 3 and minor < 5):
            return NativePQCCheck(
                is_available=False,
                openssl_version=version_str,
            )

    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return NativePQCCheck(is_available=False)

    # OpenSSL 3.5+ detected - check which algorithms are actually available
    supported_kems = []
    supported_sigs = []

    # Check for ML-KEM support by listing KEM algorithms
    try:
        result = subprocess.run(
            [openssl_path, "list", "-kem-algorithms"],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        if result.returncode == 0:
            output_lower = result.stdout.lower()
            for kem in ["mlkem512", "mlkem768", "mlkem1024"]:
                if kem in output_lower or kem.replace("mlkem", "ml-kem-") in output_lower:
                    supported_kems.append(kem)
            # Check hybrid KEMs
            for hybrid in [
                "x25519mlkem768",
                "x448mlkem1024",
                "secp256r1mlkem768",
                "secp384r1mlkem1024",
            ]:
                if hybrid in output_lower:
                    supported_kems.append(hybrid)
    except Exception:
        pass

    # Check for ML-DSA/SLH-DSA support by listing signature algorithms
    try:
        result = subprocess.run(
            [openssl_path, "list", "-signature-algorithms"],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        if result.returncode == 0:
            output_lower = result.stdout.lower()
            for sig in ["mldsa44", "mldsa65", "mldsa87"]:
                if sig in output_lower or sig.replace("mldsa", "ml-dsa-") in output_lower:
                    supported_sigs.append(sig)
            # Check SLH-DSA variants
            for variant in [
                "sha2-128s",
                "sha2-128f",
                "sha2-192s",
                "sha2-192f",
                "sha2-256s",
                "sha2-256f",
                "shake-128s",
                "shake-128f",
                "shake-192s",
                "shake-192f",
                "shake-256s",
                "shake-256f",
            ]:
                if f"slh-dsa-{variant}" in output_lower:
                    supported_sigs.append(f"slh-dsa-{variant}")
    except Exception:
        pass

    return NativePQCCheck(
        is_available=True,
        openssl_version=version_str,
        supported_kems=supported_kems,
        supported_sigs=supported_sigs,
    )


@dataclass
class ReproducibilityWarning:
    """Warning about conditions that may affect benchmark reproducibility.

    Attributes:
        category: Category of warning (cpu_governor, vm, frequency, etc.)
        message: Human-readable warning message
        recommendation: Suggested fix
    """

    category: str
    message: str
    recommendation: str


@dataclass
class ReproducibilityCheck:
    """Results of reproducibility environment checks.

    Attributes:
        cpu_governor: Current CPU governor setting (e.g., 'performance', 'powersave')
        cpu_freq_mhz: Current CPU frequency in MHz (if detectable)
        cpu_freq_range: Min-max CPU frequency range as tuple (if detectable)
        is_vm: Whether running in a virtual machine
        vm_type: Type of VM if detected (e.g., 'kvm', 'vmware', 'docker')
        taskset_available: Whether taskset command is available
        warnings: List of reproducibility warnings
    """

    cpu_governor: str | None = None
    cpu_freq_mhz: int | None = None
    cpu_freq_range: tuple[int, int] | None = None
    is_vm: bool = False
    vm_type: str | None = None
    taskset_available: bool = False
    warnings: list[ReproducibilityWarning] = field(default_factory=list)


def check_cpu_governor() -> str | None:
    """Check the current CPU frequency governor.

    Returns:
        Governor name (e.g., 'performance', 'powersave') or None if not detectable
    """
    try:
        # Try reading from first CPU's scaling_governor
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return None


def check_cpu_frequency() -> tuple[int | None, tuple[int, int] | None]:
    """Check current CPU frequency and available range.

    Returns:
        Tuple of (current_freq_mhz, (min_freq_mhz, max_freq_mhz)) or (None, None)
    """
    current_freq = None
    freq_range = None

    try:
        # Current frequency
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq") as f:
            current_freq = int(f.read().strip()) // 1000  # Convert kHz to MHz
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    try:
        # Frequency range
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq") as f:
            min_freq = int(f.read().strip()) // 1000
        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq") as f:
            max_freq = int(f.read().strip()) // 1000
        freq_range = (min_freq, max_freq)
    except (FileNotFoundError, PermissionError, ValueError):
        pass

    return current_freq, freq_range


def check_vm_environment() -> tuple[bool, str | None]:
    """Detect if running inside a virtual machine or container.

    Returns:
        Tuple of (is_vm, vm_type)
    """
    # Check for common VM indicators
    vm_indicators = [
        (
            "/sys/class/dmi/id/product_name",
            ["VirtualBox", "VMware", "KVM", "QEMU", "Xen", "Hyper-V"],
        ),
        (
            "/sys/class/dmi/id/sys_vendor",
            ["VMware", "QEMU", "Xen", "Microsoft Corporation", "innotek GmbH"],
        ),
    ]

    for path, keywords in vm_indicators:
        try:
            with open(path) as f:
                content = f.read().strip().lower()
                for keyword in keywords:
                    if keyword.lower() in content:
                        return True, keyword
        except (FileNotFoundError, PermissionError):
            pass

    # Check for Docker/container
    try:
        with open("/proc/1/cgroup") as f:
            content = f.read()
            if "docker" in content or "lxc" in content or "kubepods" in content:
                return True, "container"
    except (FileNotFoundError, PermissionError):
        pass

    # Check for systemd-detect-virt
    try:
        result = subprocess.run(
            ["systemd-detect-virt"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            virt_type = result.stdout.strip()
            if virt_type and virt_type != "none":
                return True, virt_type
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return False, None


def check_taskset_available() -> bool:
    """Check if taskset command is available for CPU pinning.

    Returns:
        True if taskset is available
    """
    try:
        result = subprocess.run(
            ["taskset", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_reproducibility() -> ReproducibilityCheck:
    """Perform comprehensive reproducibility environment checks.

    Returns:
        ReproducibilityCheck with all findings and warnings
    """
    warnings = []

    # Check CPU governor
    governor = check_cpu_governor()
    if governor and governor != "performance":
        warnings.append(
            ReproducibilityWarning(
                category="cpu_governor",
                message=f"CPU governor is '{governor}', not 'performance'",
                recommendation="Set to 'performance': sudo cpupower frequency-set -g performance",
            )
        )

    # Check CPU frequency
    freq_mhz, freq_range = check_cpu_frequency()
    if freq_range and freq_range[0] != freq_range[1]:
        warnings.append(
            ReproducibilityWarning(
                category="cpu_frequency",
                message=f"CPU frequency scaling enabled ({freq_range[0]}-{freq_range[1]} MHz)",
                recommendation="Disable frequency scaling or set fixed frequency for consistency",
            )
        )

    # Check VM environment
    is_vm, vm_type = check_vm_environment()
    if is_vm:
        warnings.append(
            ReproducibilityWarning(
                category="virtualization",
                message=f"Running in virtualized environment ({vm_type})",
                recommendation="Run on bare metal for most accurate benchmarks",
            )
        )

    # Check taskset availability
    taskset_available = check_taskset_available()

    return ReproducibilityCheck(
        cpu_governor=governor,
        cpu_freq_mhz=freq_mhz,
        cpu_freq_range=freq_range,
        is_vm=is_vm,
        vm_type=vm_type,
        taskset_available=taskset_available,
        warnings=warnings,
    )


@dataclass
class DependencyCheck:
    """Result of a dependency check.

    Attributes:
        name: Name of the dependency
        version: Detected version (None if not found)
        required_version: Minimum required version
        is_valid: Whether the dependency meets requirements
        error_message: Error message if not valid
    """

    name: str
    version: str | None
    required_version: str
    is_valid: bool
    error_message: str | None = None


@dataclass
class SystemCheck:
    """Complete system dependency check results.

    Attributes:
        openssl: OpenSSL check result
        oqs_provider: OQS-provider check result
        perf_available: Whether perf stat is available
        overall_valid: Whether all required dependencies met
    """

    openssl: DependencyCheck
    oqs_provider: DependencyCheck
    perf_available: bool
    overall_valid: bool


def _run_command(
    cmd: list[str], timeout: int = 10, env: dict[str, str] | None = None
) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, and stderr.

    Args:
        cmd: Command and arguments to run
        timeout: Timeout in seconds
        env: Environment variables for the subprocess (None = inherit)

    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _parse_version(version_string: str) -> tuple[int, int, int]:
    """Parse version string into tuple of (major, minor, patch).

    Args:
        version_string: Version string like "3.2.1"

    Returns:
        Tuple of (major, minor, patch)
    """
    match = re.search(r"(\d+)\.(\d+)\.?(\d+)?", version_string)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3)) if match.group(3) else 0
        return (major, minor, patch)
    raise ValueError(f"Could not parse version from: {version_string}")


def validate_openssl_version(
    openssl_path: str = "openssl", library_path: str = ""
) -> DependencyCheck:
    """Validate that OpenSSL 3.x is installed.

    Args:
        openssl_path: Path to OpenSSL binary
        library_path: LD_LIBRARY_PATH for the OpenSSL binary

    Returns:
        DependencyCheck with validation result
    """
    env = _get_subprocess_env(library_path)
    exit_code, stdout, stderr = _run_command([openssl_path, "version"], env=env)

    if exit_code != 0:
        return DependencyCheck(
            name="OpenSSL",
            version=None,
            required_version=">=3.0.0",
            is_valid=False,
            error_message=f"OpenSSL not found or failed: {stderr}",
        )

    # Parse version from output like "OpenSSL 3.2.0 23 Nov 2023"
    version_match = re.search(r"OpenSSL\s+(\d+\.\d+\.?\d*)", stdout)
    if not version_match:
        return DependencyCheck(
            name="OpenSSL",
            version=None,
            required_version=">=3.0.0",
            is_valid=False,
            error_message=f"Could not parse OpenSSL version from: {stdout}",
        )

    version = version_match.group(1)
    try:
        major, _, _ = _parse_version(version)
        is_valid = major >= 3
        error_message = None if is_valid else f"OpenSSL 3.x required, found {version}"
    except ValueError as e:
        is_valid = False
        error_message = str(e)

    return DependencyCheck(
        name="OpenSSL",
        version=version,
        required_version=">=3.0.0",
        is_valid=is_valid,
        error_message=error_message,
    )


def validate_oqs_provider(
    openssl_path: str = "openssl", provider_path: str = "", library_path: str = ""
) -> DependencyCheck:
    """Validate that oqs-provider is installed and available.

    Note: Version enforcement is best-effort. The required_version field indicates
    the minimum version this tool was tested with. If version cannot be determined
    from the provider listing, we set version_check_skipped=True in the error_message
    and still mark is_valid=True (provider is functional, version just unknown).

    Args:
        openssl_path: Path to OpenSSL binary
        provider_path: Path to oqs-provider module directory
        library_path: LD_LIBRARY_PATH for the OpenSSL binary

    Returns:
        DependencyCheck with validation result
    """
    # Build command with provider path if specified
    cmd = [openssl_path, "list", "-providers"]
    if provider_path:
        cmd.extend(["-provider-path", provider_path])
    cmd.extend(["-provider", "oqsprovider", "-provider", "default"])

    env = _get_subprocess_env(library_path)
    exit_code, stdout, stderr = _run_command(cmd, env=env)

    if exit_code != 0:
        return DependencyCheck(
            name="oqs-provider",
            version=None,
            required_version="detected",
            is_valid=False,
            error_message=f"oqs-provider not available: {stderr}",
        )

    # Check if oqsprovider appears in the output
    if "oqsprovider" not in stdout.lower():
        return DependencyCheck(
            name="oqs-provider",
            version=None,
            required_version="detected",
            is_valid=False,
            error_message="oqs-provider not found in provider list",
        )

    # Try to extract version from oqs-provider section specifically
    # Output format:
    #   oqsprovider
    #     name: OpenSSL OQS Provider
    #     version: 0.10.1-dev
    version = None
    # Find the oqsprovider section and extract its version
    oqs_section_match = re.search(
        r"oqsprovider\s+name:.*?version:\s*([\d.]+(?:-\w+)?)",
        stdout,
        re.IGNORECASE | re.DOTALL,
    )
    if oqs_section_match:
        version = oqs_section_match.group(1)

    # Build version string with detection status
    if version:
        version_str = version
        # Accept any detected provider version.
        return DependencyCheck(
            name="oqs-provider",
            version=version_str,
            required_version="detected",
            is_valid=True,
            error_message=None,
        )
    else:
        # The provider is available. Its version is unknown.
        version_str = "detected"
        if provider_path:
            version_str = f"detected at {provider_path}"

        return DependencyCheck(
            name="oqs-provider",
            version=version_str,
            required_version="detected",
            is_valid=True,
            error_message="version_check_skipped: version not available in provider listing",
        )


def check_perf_available() -> bool:
    """Check if perf stat is available and actually usable.

    Tests actual usability by running a simple command with perf stat,
    not just checking if the help works.

    Returns:
        True if perf stat can be used for measurements
    """
    # Use the same approach as runner._check_perf_available()
    # Verify that perf can collect counters.
    try:
        result = subprocess.run(
            ["perf", "stat", "-e", "cycles", "--", "true"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def check_all_dependencies(
    openssl_path: str = "", provider_path: str = "", library_path: str = ""
) -> SystemCheck:
    """Check all system dependencies.

    Uses environment variables PQC_BENCH_OPENSSL, PQC_BENCH_PROVIDER_PATH,
    and PQC_BENCH_LD_LIBRARY_PATH if explicit paths are not provided.

    Args:
        openssl_path: Path to OpenSSL binary (empty = use env or default)
        provider_path: Path to oqs-provider module (empty = use env or default)
        library_path: LD_LIBRARY_PATH for OpenSSL (empty = use env or default)

    Returns:
        SystemCheck with all validation results
    """
    # Resolve paths from environment if not provided
    env_openssl, env_provider, env_library = _get_resolved_paths()
    openssl_path = openssl_path or env_openssl
    provider_path = provider_path or env_provider
    library_path = library_path or env_library

    openssl_check = validate_openssl_version(openssl_path, library_path)
    oqs_check = validate_oqs_provider(openssl_path, provider_path, library_path)
    perf_available = check_perf_available()

    overall_valid = openssl_check.is_valid and oqs_check.is_valid

    return SystemCheck(
        openssl=openssl_check,
        oqs_provider=oqs_check,
        perf_available=perf_available,
        overall_valid=overall_valid,
    )


def capture_environment(
    openssl_path: str = "", provider_path: str = "", library_path: str = ""
) -> Environment:
    """Capture current environment metadata.

    Uses environment variables PQC_BENCH_OPENSSL and PQC_BENCH_PROVIDER_PATH
    if explicit paths are not provided.

    Args:
        openssl_path: Path to OpenSSL binary (empty = use env or default)
        provider_path: Path to oqs-provider module (empty = use env or default)
        library_path: LD_LIBRARY_PATH for OpenSSL (empty = use env or default)

    Returns:
        Environment object with system information
    """
    # Resolve paths from environment if not provided
    env_openssl, env_provider, env_library = _get_resolved_paths()
    openssl_path = openssl_path or env_openssl
    provider_path = provider_path or env_provider
    library_path = library_path or env_library

    # Build environment with library path if specified
    cmd_env = None
    if library_path:
        cmd_env = os.environ.copy()
        cmd_env["LD_LIBRARY_PATH"] = library_path

    # Get OpenSSL version (with library_path if specified)
    try:
        result = subprocess.run(
            [openssl_path, "version"],
            capture_output=True,
            text=True,
            timeout=10,
            env=cmd_env,
        )
        if result.returncode == 0:
            version_match = re.search(r"OpenSSL\s+(\d+\.\d+\.?\d*)", result.stdout)
            openssl_version = version_match.group(1) if version_match else "unknown"
        else:
            openssl_version = "unknown"
    except Exception:
        openssl_version = "unknown"

    # Get OQS-provider version
    oqs_check = validate_oqs_provider(openssl_path, provider_path, library_path)
    oqs_version = oqs_check.version or "unknown"

    # Get platform info
    platform_info = f"{platform.system()} {platform.machine()}"

    # Get CPU model
    cpu_model = None
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_model = line.split(":")[1].strip()
                    break
    except (FileNotFoundError, PermissionError):
        pass

    # Get kernel version
    kernel_version = None
    try:
        exit_code, stdout, _ = _run_command(["uname", "-r"])
        if exit_code == 0:
            kernel_version = stdout.strip()
    except Exception:
        pass

    return Environment(
        openssl_version=openssl_version,
        oqs_provider_version=oqs_version,
        platform=platform_info,
        cpu_model=cpu_model,
        kernel_version=kernel_version,
        captured_at=datetime.now(),
    )
