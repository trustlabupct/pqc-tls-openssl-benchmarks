#!/bin/bash
# TLS Handshake Benchmark Script for PQC Benchmarking Suite
# Measures TLS handshake timing using openssl s_server and s_client
# Supports both oqs-provider and native OpenSSL 3.5+ PQC

set -euo pipefail

# Configuration
OPENSSL="${PQC_BENCH_OPENSSL:-openssl}"
PROVIDER_PATH="${PQC_BENCH_PROVIDER_PATH:-}"
PORT="${PQC_BENCH_TLS_PORT:-4433}"
ITERATIONS="${PQC_BENCH_TLS_ITERATIONS:-10}"
USE_NATIVE="${PQC_BENCH_USE_NATIVE:-0}"
TEMP_DIR=""
SERVER_PID=""
MIN_SUCCESS_RATE=80 # Require at least 80% successful handshakes

# Optional override for hosts with broken system OpenSSL configs.
if [[ -n "${PQC_BENCH_OPENSSL_CONF:-}" ]]; then
  export OPENSSL_CONF="$PQC_BENCH_OPENSSL_CONF"
fi

# Algorithms natively supported in OpenSSL 3.5+
# KEMs
NATIVE_KEMS="mlkem512 mlkem768 mlkem1024 ML-KEM-512 ML-KEM-768 ML-KEM-1024 MLKEM512 MLKEM768 MLKEM1024 X25519MLKEM768 X448MLKEM1024 SecP256r1MLKEM768 SecP384r1MLKEM1024"
# Signatures
NATIVE_MLDSA="mldsa44 mldsa65 mldsa87 ML-DSA-44 ML-DSA-65 ML-DSA-87 MLDSA44 MLDSA65 MLDSA87"
NATIVE_SLHDSA="SLH-DSA-SHA2-128s SLH-DSA-SHA2-128f SLH-DSA-SHA2-192s SLH-DSA-SHA2-192f SLH-DSA-SHA2-256s SLH-DSA-SHA2-256f"
NATIVE_SLHDSA="$NATIVE_SLHDSA SLH-DSA-SHAKE-128s SLH-DSA-SHAKE-128f SLH-DSA-SHAKE-192s SLH-DSA-SHAKE-192f SLH-DSA-SHAKE-256s SLH-DSA-SHAKE-256f"
NATIVE_SIGS="$NATIVE_MLDSA $NATIVE_SLHDSA"

# Cleanup function
cleanup() {
  # Kill the server using its PID (not pkill which could kill unrelated processes)
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]]; then
    rm -rf "$TEMP_DIR"
  fi
}

trap cleanup EXIT

# Usage
usage() {
  echo "Usage: $0 <kem_algorithm> [sig_algorithm] [iterations]"
  echo ""
  echo "Arguments:"
  echo "  kem_algorithm    KEM algorithm for key exchange (e.g., mlkem768)"
  echo "  sig_algorithm    Signature algorithm for certificates (default: mldsa65)"
  echo "  iterations       Number of handshakes to perform (default: 10)"
  echo ""
  echo "Environment variables:"
  echo "  PQC_BENCH_OPENSSL         Path to OpenSSL binary (default: openssl)"
  echo "  PQC_BENCH_PROVIDER_PATH   Path to oqs-provider module"
  echo "  PQC_BENCH_TLS_PORT        Port for TLS server (default: 4433)"
  echo "  PQC_BENCH_TLS_ITERATIONS  Number of handshakes (default: 10)"
  echo "  PQC_BENCH_USE_NATIVE      Use native OpenSSL 3.5+ PQC (1=yes, 0=no, default: 0)"
  exit 1
}

# Check if algorithm is natively supported (KEM)
is_native_kem() {
  local algo="$1"
  local algo_lower="${algo,,}" # lowercase
  for native in $NATIVE_KEMS; do
    if [[ "${native,,}" == "$algo_lower" ]]; then
      return 0
    fi
  done
  return 1
}

# Check if algorithm is natively supported (Signature)
is_native_sig() {
  local algo="$1"
  local algo_lower="${algo,,}" # lowercase
  for native in $NATIVE_SIGS; do
    if [[ "${native,,}" == "$algo_lower" ]]; then
      return 0
    fi
  done
  return 1
}

# Wait for server to be ready with retry loop
wait_for_server() {
  local max_attempts=20
  local attempt=0

  while [[ $attempt -lt $max_attempts ]]; do
    # Check if server process is still running
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      return 1
    fi
    # Check if port is listening using nc or checking /proc
    if nc -z localhost "$PORT" 2>/dev/null ||
      ss -tln 2>/dev/null | grep -q ":$PORT "; then
      # Small delay to ensure server is fully ready
      sleep 0.1
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  return 1
}

# Check arguments
if [[ $# -lt 1 ]]; then
  usage
fi

KEM_ALGORITHM="$1"
SIG_ALGORITHM="${2:-mldsa65}"
ITERATIONS="${3:-$ITERATIONS}"

# Select native or provider mode for these algorithms.
# Native TLS requires native support for both the KEM and signature algorithm.
# to fully skip oqs-provider
SKIP_PROVIDER=0
if [[ "$USE_NATIVE" == "1" ]]; then
  if is_native_kem "$KEM_ALGORITHM" && is_native_sig "$SIG_ALGORITHM"; then
    SKIP_PROVIDER=1
  fi
fi

# Build provider arguments as array to handle spaces in paths
if [[ "$SKIP_PROVIDER" == "1" ]]; then
  # Native mode: no oqs-provider needed
  PROVIDER_ARGS=()
else
  # oqs-provider mode
  PROVIDER_ARGS=(-provider oqsprovider -provider default)
  if [[ -n "$PROVIDER_PATH" ]]; then
    PROVIDER_ARGS=(-provider-path "$PROVIDER_PATH" "${PROVIDER_ARGS[@]}")
  fi
fi

# Create temporary directory for certificates
TEMP_DIR=$(mktemp -d)
CERT_FILE="$TEMP_DIR/cert.pem"
KEY_FILE="$TEMP_DIR/key.pem"
SERVER_LOG="$TEMP_DIR/server.log"
CERT_LOG="$TEMP_DIR/cert.log"

# Generate self-signed certificate with PQC signature algorithm
echo "Generating certificate with $SIG_ALGORITHM..." >&2
if [[ ${#PROVIDER_ARGS[@]} -eq 0 ]]; then
  # Native mode
  if ! "$OPENSSL" req \
    -x509 \
    -new \
    -newkey "$SIG_ALGORITHM" \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -nodes \
    -days 1 \
    -subj "/CN=localhost" \
    2>"$CERT_LOG"; then
    if [[ -z "${OPENSSL_CONF:-}" ]] && grep -Eq "process_include:No such file or directory|calling stat\\(" "$CERT_LOG"; then
      export OPENSSL_CONF="/dev/null"
      export PQC_BENCH_OPENSSL_CONF="$OPENSSL_CONF"
      if ! OPENSSL_CONF="$OPENSSL_CONF" "$OPENSSL" req \
        -x509 \
        -new \
        -newkey "$SIG_ALGORITHM" \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -nodes \
        -days 1 \
        -subj "/CN=localhost" \
        2>>"$CERT_LOG"; then
        echo "Error: Failed to generate certificate with $SIG_ALGORITHM" >&2
        echo "--- Certificate generation error (last 30 lines) ---" >&2
        tail -30 "$CERT_LOG" >&2
        exit 1
      fi
    else
      echo "Error: Failed to generate certificate with $SIG_ALGORITHM" >&2
      echo "--- Certificate generation error (last 30 lines) ---" >&2
      tail -30 "$CERT_LOG" >&2
      exit 1
    fi
  fi
else
  # oqs-provider mode
  if ! "$OPENSSL" req \
    "${PROVIDER_ARGS[@]}" \
    -x509 \
    -new \
    -newkey "$SIG_ALGORITHM" \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -nodes \
    -days 1 \
    -subj "/CN=localhost" \
    2>"$CERT_LOG"; then
    if [[ -z "${OPENSSL_CONF:-}" ]] && grep -Eq "process_include:No such file or directory|calling stat\\(" "$CERT_LOG"; then
      export OPENSSL_CONF="/dev/null"
      export PQC_BENCH_OPENSSL_CONF="$OPENSSL_CONF"
      if ! OPENSSL_CONF="$OPENSSL_CONF" "$OPENSSL" req \
        "${PROVIDER_ARGS[@]}" \
        -x509 \
        -new \
        -newkey "$SIG_ALGORITHM" \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -nodes \
        -days 1 \
        -subj "/CN=localhost" \
        2>>"$CERT_LOG"; then
        echo "Error: Failed to generate certificate with $SIG_ALGORITHM" >&2
        echo "--- Certificate generation error (last 30 lines) ---" >&2
        tail -30 "$CERT_LOG" >&2
        exit 1
      fi
    else
      echo "Error: Failed to generate certificate with $SIG_ALGORITHM" >&2
      echo "--- Certificate generation error (last 30 lines) ---" >&2
      tail -30 "$CERT_LOG" >&2
      exit 1
    fi
  fi
fi

if [[ ! -f "$CERT_FILE" ]] || [[ ! -f "$KEY_FILE" ]]; then
  echo "Error: Certificate files not created" >&2
  exit 1
fi

# Start TLS server in background (force TLS 1.3, use -www to stay running)
echo "Starting TLS 1.3 server on port $PORT..." >&2
if [[ ${#PROVIDER_ARGS[@]} -eq 0 ]]; then
  # Native mode
  "$OPENSSL" s_server \
    -accept "$PORT" \
    -cert "$CERT_FILE" \
    -key "$KEY_FILE" \
    -tls1_3 \
    -groups "$KEM_ALGORITHM" \
    -www \
    2>"$SERVER_LOG" &
else
  # oqs-provider mode
  "$OPENSSL" s_server \
    "${PROVIDER_ARGS[@]}" \
    -accept "$PORT" \
    -cert "$CERT_FILE" \
    -key "$KEY_FILE" \
    -tls1_3 \
    -groups "$KEM_ALGORITHM" \
    -www \
    2>"$SERVER_LOG" &
fi

SERVER_PID=$!

# Wait for server to be ready (retry loop instead of sleep)
if ! wait_for_server; then
  echo "Error: TLS server failed to start or become ready" >&2
  echo "--- Server log (last 30 lines) ---" >&2
  tail -30 "$SERVER_LOG" >&2
  exit 1
fi

# Verify server is still running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "Error: TLS server died unexpectedly" >&2
  echo "--- Server log (last 30 lines) ---" >&2
  tail -30 "$SERVER_LOG" >&2
  exit 1
fi

# Run handshake benchmarks
echo "Running $ITERATIONS TLS 1.3 handshakes with $KEM_ALGORITHM..." >&2
echo "---"

SUCCESS_COUNT=0
FAIL_COUNT=0
FIRST_HANDSHAKE_INFO=""

for i in $(seq 1 "$ITERATIONS"); do
  # Time the complete handshake by measuring s_client connect duration
  START_TIME=$(date +%s%N)

  # For the first handshake, capture s_client output for verification
  # Subsequent handshakes discard output to reduce noise
  if [[ $i -eq 1 ]]; then
    # Capture first handshake's s_client output (without -brief to get full info)
    if [[ ${#PROVIDER_ARGS[@]} -eq 0 ]]; then
      CLIENT_OUTPUT=$("$OPENSSL" s_client \
        -connect "localhost:$PORT" \
        -tls1_3 \
        -groups "$KEM_ALGORITHM" \
        </dev/null 2>&1)
    else
      CLIENT_OUTPUT=$("$OPENSSL" s_client \
        "${PROVIDER_ARGS[@]}" \
        -connect "localhost:$PORT" \
        -tls1_3 \
        -groups "$KEM_ALGORITHM" \
        </dev/null 2>&1)
    fi
    CLIENT_STATUS=$?

    if [[ $CLIENT_STATUS -eq 0 ]]; then
      END_TIME=$(date +%s%N)

      # Calculate duration in microseconds
      DURATION_NS=$((END_TIME - START_TIME))
      DURATION_US=$((DURATION_NS / 1000))

      echo "handshake $i: ${DURATION_US} us"
      SUCCESS_COUNT=$((SUCCESS_COUNT + 1))

      # Extract and output TLS connection info for verification
      # Format: TLS_INFO: protocol=X cipher=Y group=Z
      # Note: use '|| true' to prevent grep failures from triggering 'set -e' exit
      # Handle both "Protocol: X" and "Protocol : X" formats
      PROTOCOL=$(echo "$CLIENT_OUTPUT" | grep -oP 'Protocol\s*:\s*\K\S+' | head -1 || true)
      # Handle both "Cipher : X" and "Cipher is X" formats
      CIPHER=$(echo "$CLIENT_OUTPUT" | grep -oP 'Cipher\s*(:|is)\s*\K\S+' | head -1 || true)
      TEMP_KEY=$(echo "$CLIENT_OUTPUT" | grep -oP 'Server Temp Key:\s*\K.*' | head -1 || true)
      PEER_SIG=$(echo "$CLIENT_OUTPUT" | grep -oP 'Peer signature type:\s*\K\S+' | head -1 || true)
      echo "TLS_INFO: protocol=${PROTOCOL:-unknown} cipher=${CIPHER:-unknown} group=${TEMP_KEY:-unknown} sig=${PEER_SIG:-unknown}"
    else
      echo "Error: Handshake $i failed" >&2
      FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
  else
    # Run s_client with TLS 1.3 forced (discard output for speed)
    if [[ ${#PROVIDER_ARGS[@]} -eq 0 ]]; then
      if "$OPENSSL" s_client \
        -connect "localhost:$PORT" \
        -tls1_3 \
        -groups "$KEM_ALGORITHM" \
        -brief \
        </dev/null \
        >/dev/null 2>&1; then

        END_TIME=$(date +%s%N)

        # Calculate duration in microseconds
        DURATION_NS=$((END_TIME - START_TIME))
        DURATION_US=$((DURATION_NS / 1000))

        echo "handshake $i: ${DURATION_US} us"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
      else
        echo "Error: Handshake $i failed" >&2
        FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
    else
      if "$OPENSSL" s_client \
        "${PROVIDER_ARGS[@]}" \
        -connect "localhost:$PORT" \
        -tls1_3 \
        -groups "$KEM_ALGORITHM" \
        -brief \
        </dev/null \
        >/dev/null 2>&1; then

        END_TIME=$(date +%s%N)

        # Calculate duration in microseconds
        DURATION_NS=$((END_TIME - START_TIME))
        DURATION_US=$((DURATION_NS / 1000))

        echo "handshake $i: ${DURATION_US} us"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
      else
        echo "Error: Handshake $i failed" >&2
        FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
    fi
  fi
done

echo "---"
# Output parseable result line to stdout (for Python to parse)
echo "RESULT: success=$SUCCESS_COUNT fail=$FAIL_COUNT total=$ITERATIONS"
echo "Completed: $SUCCESS_COUNT/$ITERATIONS successful handshakes" >&2

# Stop server
kill "$SERVER_PID" 2>/dev/null || true

# Check success rate
MIN_REQUIRED=$((ITERATIONS * MIN_SUCCESS_RATE / 100))
if [[ $SUCCESS_COUNT -lt $MIN_REQUIRED ]]; then
  echo "Error: Too many handshake failures ($FAIL_COUNT/$ITERATIONS failed, need at least $MIN_REQUIRED successes)" >&2
  exit 1
fi

# Exit with partial failure code if some handshakes failed
if [[ $FAIL_COUNT -gt 0 ]]; then
  exit 0 # Still exit 0 but the count is logged
fi
