#!/bin/bash
# KEM Benchmark Script for PQC Benchmarking Suite
# Invokes OpenSSL speed command for KEM algorithms
# Supports both oqs-provider and native OpenSSL 3.5+ PQC
#
# With OpenSSL 3.5+, oqs-provider automatically disables its ML-KEM
# implementations and defers to native OpenSSL. This script handles both cases:
# - Native mode (OpenSSL 3.5+): Uses native algorithm names like ML-KEM-768
# - oqs-provider mode: Uses oqs-provider names like frodo640aes, bikel1

set -euo pipefail

# Configuration
OPENSSL="${PQC_BENCH_OPENSSL:-openssl}"
PROVIDER_PATH="${PQC_BENCH_PROVIDER_PATH:-}"
DURATION="${PQC_BENCH_DURATION:-3}"
USE_NATIVE="${PQC_BENCH_USE_NATIVE:-0}"

# Algorithms that are ONLY available natively in OpenSSL 3.5+ (not via oqs-provider)
# oqs-provider 0.9.0+ disables these when running with OpenSSL 3.5
# Compare algorithm names in lowercase.
NATIVE_ONLY_KEMS="mlkem512 mlkem768 mlkem1024"

# Native hybrid KEMs in OpenSSL 3.5+ (also disabled in oqs-provider with OpenSSL 3.5)
NATIVE_HYBRID_KEMS="x25519mlkem768 x448mlkem1024 secp256r1mlkem768 secp384r1mlkem1024"

# Usage
usage() {
  echo "Usage: $0 <algorithm> [seconds]"
  echo ""
  echo "Arguments:"
  echo "  algorithm    KEM algorithm name (e.g., mlkem768, frodo640aes)"
  echo "  seconds      Number of seconds to run (default: 3)"
  echo ""
  echo "Environment variables:"
  echo "  PQC_BENCH_OPENSSL        Path to OpenSSL binary (default: openssl)"
  echo "  PQC_BENCH_PROVIDER_PATH  Path to oqs-provider module"
  echo "  PQC_BENCH_DURATION       Benchmark duration in seconds (default: 3)"
  echo "  PQC_BENCH_USE_NATIVE     Use native OpenSSL 3.5+ PQC (1=yes, 0=no, default: 0)"
  echo ""
  echo "Notes:"
  echo "  - With OpenSSL 3.5+, mlkem* algorithms use native implementation"
  echo "  - oqs-provider algorithms (frodo*, bike*) always use oqs-provider"
  exit 1
}

# Check if algorithm requires native mode (disabled in oqs-provider with OpenSSL 3.5)
is_native_only_algorithm() {
  local algo="$1"
  local algo_lower="${algo,,}" # lowercase

  # Check standalone ML-KEM
  for native in $NATIVE_ONLY_KEMS; do
    if [[ "$native" == "$algo_lower" ]]; then
      return 0
    fi
  done

  # Check native hybrids
  for native in $NATIVE_HYBRID_KEMS; do
    if [[ "$native" == "$algo_lower" ]]; then
      return 0
    fi
  done

  return 1
}

# Map algorithm name to native OpenSSL 3.5 format
# oqs-provider uses: mlkem768
# Native OpenSSL uses: ML-KEM-768
map_to_native_name() {
  local algo="$1"
  local algo_lower="${algo,,}"

  case "$algo_lower" in
    mlkem512) echo "ML-KEM-512" ;;
    mlkem768) echo "ML-KEM-768" ;;
    mlkem1024) echo "ML-KEM-1024" ;;
    # Native hybrids - exact case matters for OpenSSL
    x25519mlkem768) echo "X25519MLKEM768" ;;
    x448mlkem1024) echo "X448MLKEM1024" ;;
    secp256r1mlkem768) echo "SecP256r1MLKEM768" ;;
    secp384r1mlkem1024) echo "SecP384r1MLKEM1024" ;;
    # Already in native format or unknown - pass through
    *) echo "$algo" ;;
  esac
}

# Check arguments
if [[ $# -lt 1 ]]; then
  usage
fi

ALGORITHM="$1"
DURATION="${2:-$DURATION}"

# Select native or provider mode for this algorithm.
# Native mode is used if:
# 1. USE_NATIVE=1 AND algorithm is a native-only algorithm (ML-KEM, native hybrids)
# 2. Algorithm is disabled in oqs-provider when running with OpenSSL 3.5
SKIP_PROVIDER=0
if [[ "$USE_NATIVE" == "1" ]] && is_native_only_algorithm "$ALGORITHM"; then
  SKIP_PROVIDER=1
  # Map to native algorithm name format
  ALGORITHM=$(map_to_native_name "$ALGORITHM")
fi

# Build provider arguments as array to handle spaces in paths
if [[ "$SKIP_PROVIDER" == "1" ]]; then
  # Native mode: no oqs-provider needed
  PROVIDER_ARGS=()
else
  # oqs-provider mode (for FrodoKEM, BIKE, and oqs-provider hybrids)
  PROVIDER_ARGS=(-provider oqsprovider -provider default)
  if [[ -n "$PROVIDER_PATH" ]]; then
    PROVIDER_ARGS=(-provider-path "$PROVIDER_PATH" "${PROVIDER_ARGS[@]}")
  fi
fi

# Run OpenSSL speed benchmark with machine-readable output (-mr)
# Output format: "+F:index:algorithm:operation:ops_count:time_seconds"
if [[ ${#PROVIDER_ARGS[@]} -eq 0 ]]; then
  exec "$OPENSSL" speed \
    -mr \
    -seconds "$DURATION" \
    "$ALGORITHM" 2>&1
else
  exec "$OPENSSL" speed \
    -mr \
    "${PROVIDER_ARGS[@]}" \
    -seconds "$DURATION" \
    "$ALGORITHM" 2>&1
fi
