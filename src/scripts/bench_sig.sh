#!/bin/bash
# Signature Benchmark Script for PQC Benchmarking Suite
# Invokes OpenSSL speed command for signature algorithms
# Supports both oqs-provider and native OpenSSL 3.5+ PQC
#
# With OpenSSL 3.5+:
# - oqs-provider automatically disables its ML-DSA implementations
# - Native OpenSSL 3.5's `speed` command does NOT work for ML-DSA (bug)
# - Therefore ML-DSA benchmarking requires OpenSSL 3.4 with oqs-provider
# - Falcon, SPHINCS+, Mayo, etc. still work via oqs-provider

set -euo pipefail

# Configuration
OPENSSL="${PQC_BENCH_OPENSSL:-openssl}"
PROVIDER_PATH="${PQC_BENCH_PROVIDER_PATH:-}"
DURATION="${PQC_BENCH_DURATION:-3}"
USE_NATIVE="${PQC_BENCH_USE_NATIVE:-0}"

# Algorithms that are disabled in oqs-provider when running with OpenSSL 3.5
# These algorithms exist natively in OpenSSL 3.5, but `speed` doesn't work for them
# Compare algorithm names in lowercase.
NATIVE_DISABLED_SIGS="mldsa44 mldsa65 mldsa87"

# SLH-DSA (SPHINCS+ FIPS 205) variants also native in OpenSSL 3.5
# These may or may not work with native speed command
NATIVE_SLHDSA="slh-dsa-sha2-128s slh-dsa-sha2-128f slh-dsa-sha2-192s slh-dsa-sha2-192f slh-dsa-sha2-256s slh-dsa-sha2-256f"
NATIVE_SLHDSA="$NATIVE_SLHDSA slh-dsa-shake-128s slh-dsa-shake-128f slh-dsa-shake-192s slh-dsa-shake-192f slh-dsa-shake-256s slh-dsa-shake-256f"

# Usage
usage() {
  echo "Usage: $0 <algorithm> [seconds]"
  echo ""
  echo "Arguments:"
  echo "  algorithm    Signature algorithm name (e.g., falcon512, sphincssha2128fsimple)"
  echo "  seconds      Number of seconds to run (default: 3)"
  echo ""
  echo "Environment variables:"
  echo "  PQC_BENCH_OPENSSL        Path to OpenSSL binary (default: openssl)"
  echo "  PQC_BENCH_PROVIDER_PATH  Path to oqs-provider module"
  echo "  PQC_BENCH_DURATION       Benchmark duration in seconds (default: 3)"
  echo "  PQC_BENCH_USE_NATIVE     Use native OpenSSL 3.5+ PQC (1=yes, 0=no, default: 0)"
  echo ""
  echo "Notes:"
  echo "  - ML-DSA (mldsa*) does NOT work with OpenSSL 3.5 speed benchmark"
  echo "  - For ML-DSA, use OpenSSL 3.4 with oqs-provider"
  echo "  - Falcon, SPHINCS+, Mayo work via oqs-provider"
  exit 1
}

# Check if algorithm is native-disabled (oqs-provider disables when OpenSSL 3.5 detected)
is_native_disabled_algorithm() {
  local algo="$1"
  local algo_lower="${algo,,}" # lowercase
  for native in $NATIVE_DISABLED_SIGS; do
    if [[ "$native" == "$algo_lower" ]]; then
      return 0
    fi
  done
  return 1
}

# Check arguments
if [[ $# -lt 1 ]]; then
  usage
fi

ALGORITHM="$1"
DURATION="${2:-$DURATION}"

# For signature algorithms, we almost always use oqs-provider because:
# 1. ML-DSA: OpenSSL 3.5 speed benchmarks do not support it. oqs-provider also disables it.
# 2. Other sigs (Falcon, SPHINCS+, Mayo): Only available via oqs-provider
#
# If USE_NATIVE=1 and the algorithm is ML-DSA, this will fail because:
# - oqs-provider disables it
# - Native speed doesn't work
# The calling code should detect this and fall back to OpenSSL 3.4

# Note: We don't skip provider for signature algorithms since none of them
# work with native OpenSSL 3.5 speed command

# Build provider arguments as array to handle spaces in paths
PROVIDER_ARGS=(-provider oqsprovider -provider default)
if [[ -n "$PROVIDER_PATH" ]]; then
  PROVIDER_ARGS=(-provider-path "$PROVIDER_PATH" "${PROVIDER_ARGS[@]}")
fi

# Run OpenSSL speed benchmark with machine-readable output (-mr)
# Output format: "+F:index:algorithm:operation:ops_count:time_seconds"
exec "$OPENSSL" speed \
  -mr \
  "${PROVIDER_ARGS[@]}" \
  -seconds "$DURATION" \
  "$ALGORITHM" 2>&1
