#!/usr/bin/env bash
# PQC Benchmark Suite - Full Run (crypto + TLS, optional HTTP)
#
# - Auto-detects OpenSSL: uses /opt/openssl-3.5/ if available, otherwise system OpenSSL
# - Runs all 90 algorithms in 17 batches sequentially
# - Automatically uses native OpenSSL 3.5 for ML-KEM when available
# - Falls back to system OpenSSL 3.4.x for ML-DSA (native speed not supported yet)
# - Adds optional end-to-end HTTP benchmarks (OpenSSL + Playwright) when configured
#
# OpenSSL 3.5 + oqs-provider 0.9.0+ behavior:
#   oqs-provider automatically DISABLES its ML-KEM and ML-DSA when OpenSSL 3.5 is detected.
#   This means:
#   - ML-KEM: Must use native OpenSSL 3.5 algorithm names (ML-KEM-768, not mlkem768)
#   - ML-DSA: Native `openssl speed` is not supported. oqs-provider also disables it.
#     Use system OpenSSL 3.4.x with oqs-provider for these benchmarks.
#
# Algorithm support:
#   ML-KEM (native):      mlkem512, mlkem768, mlkem1024 -> converted to ML-KEM-* format
#   ML-KEM hybrids:       X25519MLKEM768, SecP256r1MLKEM768, etc. (native)
#   ML-DSA (fallback):    Native speed doesn't work, uses system OpenSSL + oqs-provider
#   Other KEM:            FrodoKEM, BIKE via oqs-provider (still works with OpenSSL 3.5)
#   Other Sig:            Falcon, SPHINCS+, Mayo via oqs-provider (still works)
#
# Performance note:
#   Recorded runs show native OpenSSL 3.5 ML-KEM at about 2.5 times the latency
#   of oqs-provider's liboqs implementation. Compare results for the same host.
#
# Output files include OpenSSL version in the environment metadata, plus:
#   *-oqs.json    = Run with system OpenSSL (oqs-provider)
#   *-native.json = Run with native OpenSSL 3.5 (comparison)
#
# Reference: https://github.com/open-quantum-safe/oqs-provider#using-with-openssl-350
#
# Usage:
#   ./run-benchmarks.sh [START_BATCH|--http-only]
#
# Examples:
#   ./run-benchmarks.sh           # Run all batches (1-17) + native ML-KEM comparison
#   ./run-benchmarks.sh 11        # Resume from batch 11
#   ./run-benchmarks.sh --http-only    # Skip crypto/TLS and run HTTP only

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# OpenSSL configuration - auto-detect or use environment variables
# Use ${VAR-default} (no colon) to allow explicitly empty values
if [[ -n "${PQC_BENCH_OPENSSL+x}" ]]; then
  # Variable is set (even if empty) - use it
  OPENSSL_PATH="${PQC_BENCH_OPENSSL:-openssl}"
else
  # Variable is unset - try OpenSSL 3.5, fall back to system
  if [[ -x /opt/openssl-3.5/bin/openssl ]]; then
    OPENSSL_PATH="/opt/openssl-3.5/bin/openssl"
  else
    OPENSSL_PATH="openssl"
  fi
fi

if [[ -n "${PQC_BENCH_LD_LIBRARY_PATH+x}" ]]; then
  # Variable is set (even if empty) - use it as-is
  LIBRARY_PATH="${PQC_BENCH_LD_LIBRARY_PATH}"
else
  # Variable is unset - set library path if using custom OpenSSL
  if [[ "$OPENSSL_PATH" == "/opt/openssl-3.5/bin/openssl" ]]; then
    LIBRARY_PATH="/opt/openssl-3.5/lib64"
  else
    LIBRARY_PATH=""
  fi
fi

# Parse optional start batch argument / flags.
START_BATCH="1"
HTTP_ONLY="0"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  echo "Usage: ./run-benchmarks.sh [START_BATCH|--http-only]" >&2
  echo "" >&2
  echo "  START_BATCH:  1-17 to run/resume crypto+TLS batches" >&2
  echo "  --http-only:  skip crypto+TLS and run HTTP only" >&2
  echo "" >&2
  echo "OpenSSL is auto-detected: /opt/openssl-3.5/ if available, otherwise system OpenSSL" >&2
  echo "Native ML-KEM benchmarks are automatically run if OpenSSL >= 3.5" >&2
  echo "" >&2
  echo "Environment variables:" >&2
  echo "  PQC_BENCH_OPENSSL         Path to OpenSSL binary (auto-detects: /opt/openssl-3.5 or system)" >&2
  echo "  PQC_BENCH_LD_LIBRARY_PATH LD_LIBRARY_PATH for OpenSSL (auto-set based on OpenSSL path)" >&2
  echo "  PQC_BENCH_OPENSSL_CONF    OpenSSL config file path (sets OPENSSL_CONF; useful on hosts with broken /etc/ssl/openssl.cnf)" >&2
  echo "  PQC_BENCH_RESULTS_DIR     Output directory (default: results)" >&2
  echo "" >&2
  echo "Examples:" >&2
  echo "  ./run-benchmarks.sh                            # Auto-detect OpenSSL (3.5 if available)" >&2
  echo "  PQC_BENCH_OPENSSL=openssl ./run-benchmarks.sh  # Force system OpenSSL" >&2
  echo "  PQC_BENCH_OPENSSL_CONF=/dev/null ./run-benchmarks.sh --http-only  # Ignore system OpenSSL config" >&2
  echo "  ./run-benchmarks.sh 11                         # Resume from batch 11" >&2
  echo "  ./run-benchmarks.sh --http-only                # HTTP benchmarks only" >&2
  exit 0
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --http-only | http)
      START_BATCH="18"
      HTTP_ONLY="1"
      shift
      ;;
    *)
      if [[ "$1" =~ ^[0-9]+$ ]]; then
        START_BATCH="$1"
      else
        echo "Error: unexpected argument: $1" >&2
        exit 1
      fi
      shift
      ;;
  esac
done

if ! [[ "$START_BATCH" =~ ^[0-9]+$ ]] || [[ "$START_BATCH" -lt 1 ]] || [[ "$START_BATCH" -gt 18 ]]; then
  echo "Error: START_BATCH must be a number between 1 and 17, or use --http-only" >&2
  exit 1
fi
if [[ "$START_BATCH" -eq 18 ]]; then
  HTTP_ONLY="1"
fi

# Verify OpenSSL is available and get version
# Handle both absolute paths and commands in PATH
if [[ "$OPENSSL_PATH" == /* ]]; then
  # Absolute path - check if executable
  if [[ ! -x "$OPENSSL_PATH" ]]; then
    echo "Error: OpenSSL not found at $OPENSSL_PATH" >&2
    echo "Set PQC_BENCH_OPENSSL to the correct path." >&2
    exit 1
  fi
else
  # Command name - check if in PATH
  if ! command -v "$OPENSSL_PATH" >/dev/null 2>&1; then
    echo "Error: OpenSSL command '$OPENSSL_PATH' not found in PATH" >&2
    echo "Set PQC_BENCH_OPENSSL to the correct path." >&2
    exit 1
  fi
fi

OPENSSL_VERSION=$(LD_LIBRARY_PATH="$LIBRARY_PATH" "$OPENSSL_PATH" version 2>/dev/null || echo "unknown")
echo "Using OpenSSL: $OPENSSL_VERSION"
echo "Binary: $OPENSSL_PATH"
echo "Library path: $LIBRARY_PATH"

# Optional override for hosts with broken system OpenSSL configs.
if [[ -n "${PQC_BENCH_OPENSSL_CONF:-}" ]]; then
  export OPENSSL_CONF="$PQC_BENCH_OPENSSL_CONF"
fi

# Check if version >= 3.5 for native PQC support
NATIVE_PQC_AVAILABLE="0"
if [[ "$OPENSSL_VERSION" == *"3.5"* ]] || [[ "$OPENSSL_VERSION" == *"3.6"* ]] || [[ "$OPENSSL_VERSION" == *"3.7"* ]]; then
  NATIVE_PQC_AVAILABLE="1"
  echo "Native PQC support: YES (will run native ML-KEM benchmarks)"
else
  echo "Native PQC support: NO (OpenSSL < 3.5, skipping native benchmarks)"
fi
echo ""

# Export environment for pqc-bench
export PQC_BENCH_OPENSSL="$OPENSSL_PATH"
export PQC_BENCH_LD_LIBRARY_PATH="$LIBRARY_PATH"
if [[ -n "${OPENSSL_CONF:-}" ]]; then
  export PQC_BENCH_OPENSSL_CONF="$OPENSSL_CONF"
fi

if [[ -f .venv/bin/activate ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
else
  echo "Error: .venv not found. Create it and install dependencies first." >&2
  echo "  python -m venv .venv" >&2
  echo "  .venv/bin/pip install -e \".[dev]\"" >&2
  exit 2
fi

RESULTS_DIR="${PQC_BENCH_RESULTS_DIR:-results}"
mkdir -p "$RESULTS_DIR"

# Helper function to run native ML-KEM benchmark
# Usage: run_native_benchmark <label> <output_file> <algorithms...>
run_native_benchmark() {
  local label="$1"
  local output_file="$2"
  shift 2
  local algos=("$@")

  if [[ "$NATIVE_PQC_AVAILABLE" -ne 1 ]]; then
    return 0
  fi

  echo "$label"
  set +e
  pqc-bench run "${algos[@]}" --include-tls --use-native -f json -o "$output_file"
  local rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    echo "       Done at: $(date)"
    return 0
  fi

  if [[ $rc -eq 3 ]]; then
    echo "       Dependency error (exit $rc) — skipping native benchmark." >&2
    return 0
  fi

  echo "       Completed with warnings (exit $rc) at: $(date)" >&2
  return 0
}

run_step() {
  local label="$1"
  shift

  if [[ -n "$label" ]]; then
    echo "$label"
  fi
  set +e
  "$@"
  local rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    echo "       Done at: $(date)"
    return 0
  fi

  if [[ $rc -eq 3 ]]; then
    echo "       Dependency error (exit $rc) — aborting." >&2
    exit "$rc"
  fi

  echo "       Completed with warnings (exit $rc) at: $(date)" >&2
  return 0
}

openssl_req_with_conf_fallback() {
  local openssl_bin="$1"
  local stderr_log="$2"
  shift 2

  if LD_LIBRARY_PATH="$LIBRARY_PATH" "$openssl_bin" req "$@" >/dev/null 2>"$stderr_log"; then
    return 0
  fi

  if [[ -z "${OPENSSL_CONF:-}" ]] && grep -Eq "process_include:No such file or directory|calling stat\\(" "$stderr_log"; then
    export OPENSSL_CONF="/dev/null"
    export PQC_BENCH_OPENSSL_CONF="$OPENSSL_CONF"
    echo "[INFO] Retrying openssl req with OPENSSL_CONF=/dev/null" >&2
    if LD_LIBRARY_PATH="$LIBRARY_PATH" OPENSSL_CONF="$OPENSSL_CONF" "$openssl_bin" req "$@" >/dev/null 2>>"$stderr_log"; then
      return 0
    fi
  fi

  return 1
}

echo "=========================================="
echo "PQC Benchmark Suite - Starting Full Run"
echo "=========================================="
echo "Started at: $(date)"

# Check for packetization-only mode (skip all crypto/TLS/HTTP)
PACKETIZATION_ONLY="${PQC_BENCH_PACKETIZATION_ONLY:-0}"
if [[ "$PACKETIZATION_ONLY" == "1" ]]; then
  echo "Packetization-only mode (skipping crypto/TLS/HTTP batches)"
  echo ""
  # Jump directly to packetization section by setting START_BATCH high
  START_BATCH=99
  HTTP_ONLY=0
elif [[ "$START_BATCH" -gt 1 ]]; then
  if [[ "$HTTP_ONLY" -eq 1 ]]; then
    echo "HTTP-only mode (skipping crypto/TLS batches)"
  else
    echo "Resuming from batch $START_BATCH"
  fi
fi
echo ""

# 1. ML-KEM (3)
if [[ "$START_BATCH" -le 1 ]]; then
  echo "[1/17] ML-KEM (3 algorithms)..."
  run_step "" pqc-bench run mlkem512 mlkem768 mlkem1024 --include-tls -f json -o "$RESULTS_DIR/01-mlkem.json"
  # Native ML-KEM comparison (auto-runs if OpenSSL >= 3.5)
  run_native_benchmark "[1/17] ML-KEM (3 algorithms) - native..." \
    "$RESULTS_DIR/01-mlkem-native.json" \
    mlkem512 mlkem768 mlkem1024
fi

# 2. FrodoKEM (6)
if [[ "$START_BATCH" -le 2 ]]; then
  echo "[2/17] FrodoKEM (6 algorithms)..."
  run_step "" pqc-bench run frodo640aes frodo976aes frodo1344aes frodo640shake frodo976shake frodo1344shake --include-tls -f json -o "$RESULTS_DIR/02-frodo.json"
fi

# 3. BIKE (3)
if [[ "$START_BATCH" -le 3 ]]; then
  echo "[3/17] BIKE (3 algorithms)..."
  run_step "" pqc-bench run bikel1 bikel3 bikel5 --include-tls -f json -o "$RESULTS_DIR/03-bike.json"
fi

# 4. Hybrid KEM - ML-KEM (11 - includes Brainpool curves)
if [[ "$START_BATCH" -le 4 ]]; then
  echo "[4/17] Hybrid KEM - ML-KEM (11 algorithms)..."
  run_step "" pqc-bench run x25519_mlkem512 X25519MLKEM768 x448_mlkem768 p256_mlkem512 SecP256r1MLKEM768 p384_mlkem768 SecP384r1MLKEM1024 p521_mlkem1024 bp256_mlkem512 bp384_mlkem768 bp512_mlkem1024 --include-tls -f json -o "$RESULTS_DIR/04-hybrid-mlkem.json"
  # Native hybrid ML-KEM comparison (only the ones natively supported)
  run_native_benchmark "[4/17] Hybrid KEM - ML-KEM (3 native algorithms)..." \
    "$RESULTS_DIR/04-hybrid-mlkem-native.json" \
    X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024
fi

# 5. Hybrid KEM - Frodo (10)
if [[ "$START_BATCH" -le 5 ]]; then
  echo "[5/17] Hybrid KEM - Frodo (10 algorithms)..."
  run_step "" pqc-bench run p256_frodo640aes x25519_frodo640aes p384_frodo976aes x448_frodo976aes p521_frodo1344aes p256_frodo640shake x25519_frodo640shake p384_frodo976shake x448_frodo976shake p521_frodo1344shake --include-tls -f json -o "$RESULTS_DIR/05-hybrid-frodo.json"
fi

# 6. Hybrid KEM - BIKE (5)
if [[ "$START_BATCH" -le 6 ]]; then
  echo "[6/17] Hybrid KEM - BIKE (5 algorithms)..."
  run_step "" pqc-bench run p256_bikel1 x25519_bikel1 p384_bikel3 x448_bikel3 p521_bikel5 --include-tls -f json -o "$RESULTS_DIR/06-hybrid-bike.json"
fi

# 7. ML-DSA (3)
if [[ "$START_BATCH" -le 7 ]]; then
  echo "[7/17] ML-DSA (3 algorithms)..."
  # ML-DSA requires special handling:
  # - OpenSSL 3.5 native `speed` doesn't support ML-DSA yet
  # - oqs-provider defers to native when OpenSSL 3.5 is used
  # - So we must use system OpenSSL (3.4.x) for ML-DSA benchmarks
  if [[ "$NATIVE_PQC_AVAILABLE" -eq 1 ]]; then
    echo "       Note: Using system OpenSSL for ML-DSA (OpenSSL 3.5 speed doesn't support ML-DSA)"
    # Temporarily use system OpenSSL
    unset PQC_BENCH_OPENSSL
    unset PQC_BENCH_LD_LIBRARY_PATH
    run_step "" pqc-bench run mldsa44 mldsa65 mldsa87 --include-tls -f json -o "$RESULTS_DIR/07-mldsa-oqs.json"
    # Restore OpenSSL 3.5 settings
    export PQC_BENCH_OPENSSL="$OPENSSL_PATH"
    export PQC_BENCH_LD_LIBRARY_PATH="$LIBRARY_PATH"
  else
    run_step "" pqc-bench run mldsa44 mldsa65 mldsa87 --include-tls -f json -o "$RESULTS_DIR/07-mldsa.json"
  fi
fi

# 8. Falcon (4)
if [[ "$START_BATCH" -le 8 ]]; then
  echo "[8/17] Falcon (4 algorithms)..."
  run_step "" pqc-bench run falcon512 falcon1024 falconpadded512 falconpadded1024 --include-tls -f json -o "$RESULTS_DIR/08-falcon.json"
fi

# 9. SPHINCS+ (4)
if [[ "$START_BATCH" -le 9 ]]; then
  echo "[9/17] SPHINCS+ (4 algorithms)..."
  run_step "" pqc-bench run sphincssha2128fsimple sphincssha2128ssimple sphincssha2192fsimple sphincsshake128fsimple --include-tls -f json -o "$RESULTS_DIR/09-sphincs.json"
fi

# 10. Mayo (4)
if [[ "$START_BATCH" -le 10 ]]; then
  echo "[10/17] Mayo (4 algorithms)..."
  run_step "" pqc-bench run mayo1 mayo2 mayo3 mayo5 --include-tls -f json -o "$RESULTS_DIR/10-mayo.json"
fi

# 11. Experimental - CROSS, OV, SNOVA (10)
if [[ "$START_BATCH" -le 11 ]]; then
  echo "[11/17] Experimental - CROSS, OV, SNOVA (10 algorithms)..."
  run_step "" pqc-bench run CROSSrsdp128balanced OV_Is_pkc OV_Ip_pkc OV_Is_pkc_skc OV_Ip_pkc_skc snova2454 snova2454esk snova37172 snova2455 snova2965 --include-tls -f json -o "$RESULTS_DIR/11-experimental.json"
fi

# 12. Hybrid Sig - ML-DSA (4)
if [[ "$START_BATCH" -le 12 ]]; then
  echo "[12/17] Hybrid Sig - ML-DSA (4 algorithms)..."
  run_step "" pqc-bench run p256_mldsa44 rsa3072_mldsa44 p384_mldsa65 p521_mldsa87 --include-tls -f json -o "$RESULTS_DIR/12-hybrid-mldsa.json"
fi

# 13. Hybrid Sig - Falcon (6)
if [[ "$START_BATCH" -le 13 ]]; then
  echo "[13/17] Hybrid Sig - Falcon (6 algorithms)..."
  run_step "" pqc-bench run p256_falcon512 rsa3072_falcon512 p256_falconpadded512 rsa3072_falconpadded512 p521_falcon1024 p521_falconpadded1024 --include-tls -f json -o "$RESULTS_DIR/13-hybrid-falcon.json"
fi

# 14. Hybrid Sig - SPHINCS+ (7)
if [[ "$START_BATCH" -le 14 ]]; then
  echo "[14/17] Hybrid Sig - SPHINCS+ (7 algorithms)..."
  run_step "" pqc-bench run p256_sphincssha2128fsimple rsa3072_sphincssha2128fsimple p256_sphincssha2128ssimple rsa3072_sphincssha2128ssimple p384_sphincssha2192fsimple p256_sphincsshake128fsimple rsa3072_sphincsshake128fsimple --include-tls -f json -o "$RESULTS_DIR/14-hybrid-sphincs.json"
fi

# 15. Hybrid Sig - Mayo (4)
if [[ "$START_BATCH" -le 15 ]]; then
  echo "[15/17] Hybrid Sig - Mayo (4 algorithms)..."
  run_step "" pqc-bench run p256_mayo1 p256_mayo2 p384_mayo3 p521_mayo5 --include-tls -f json -o "$RESULTS_DIR/15-hybrid-mayo.json"
fi

# 16. Hybrid Sig - Experimental OV (4)
if [[ "$START_BATCH" -le 16 ]]; then
  echo "[16/17] Hybrid Sig - Experimental OV (4 algorithms)..."
  run_step "" pqc-bench run p256_OV_Is_pkc p256_OV_Ip_pkc p256_OV_Is_pkc_skc p256_OV_Ip_pkc_skc --include-tls -f json -o "$RESULTS_DIR/16-hybrid-ov.json"
fi

# 17. Hybrid Sig - Experimental SNOVA (5)
if [[ "$START_BATCH" -le 17 ]]; then
  echo "[17/17] Hybrid Sig - Experimental SNOVA (5 algorithms)..."
  run_step "" pqc-bench run p256_snova2454 p256_snova2454esk p256_snova37172 p384_snova2455 p521_snova2965 --include-tls -f json -o "$RESULTS_DIR/17-hybrid-snova.json"
fi

echo ""
HTTP_URL="${PQC_BENCH_HTTP_URL:-}"
HTTP_LOCAL="${PQC_BENCH_HTTP_LOCAL:-}"
if [[ "$HTTP_ONLY" -eq 1 && -z "$HTTP_URL" && -z "$HTTP_LOCAL" ]]; then
  HTTP_LOCAL="1"
fi

# Skip HTTP section entirely in packetization-only mode
if [[ "$PACKETIZATION_ONLY" == "1" ]]; then
  HTTP_URL=""
  HTTP_LOCAL=""
fi

HTTP_SAMPLES="${PQC_BENCH_HTTP_SAMPLES:-20}"
HTTP_WARMUP="${PQC_BENCH_HTTP_WARMUP:-2}"
HTTP_TIMEOUT="${PQC_BENCH_HTTP_TIMEOUT:-30}"
HTTP_GROUPS_HYBRID="${PQC_BENCH_HTTP_GROUPS_HYBRID:-X25519MLKEM768}"
HTTP_GROUPS_CLASSICAL="${PQC_BENCH_HTTP_GROUPS_CLASSICAL:-X25519}"
HTTP_BROWSER="${PQC_BENCH_HTTP_BROWSER:-chromium}"
HTTP_FULL_PQC="${PQC_BENCH_HTTP_FULL_PQC:-0}" # 0/1

# Optional: run OpenSSL HTTP benchmarks for all pure PQC KEM groups.
# (Playwright/browser mode cannot force PQC groups.)
HTTP_PQC_MODE="${PQC_BENCH_HTTP_PQC:-0}"             # 0/1 or "all"
HTTP_PQC_GROUPS_RAW="${PQC_BENCH_HTTP_PQC_GROUPS:-}" # optional override (space/comma/colon-separated)
HTTP_PQC_GROUPS=""
if [[ -n "$HTTP_PQC_GROUPS_RAW" ]]; then
  HTTP_PQC_GROUPS="${HTTP_PQC_GROUPS_RAW//,/ }"
  HTTP_PQC_GROUPS="${HTTP_PQC_GROUPS//:/ }"
elif [[ "$HTTP_PQC_MODE" == "1" || "$HTTP_PQC_MODE" == "all" ]]; then
  HTTP_PQC_GROUPS="$(
    pqc-bench -q list -t kem --pure-only -f json |
      python -c "import json,sys; data=json.load(sys.stdin); print(' '.join(a['name'] for a in data))"
  )"
fi

HTTP_LOCAL_DIR=""
HTTP_LOCAL_PID=""

cleanup_http_local() {
  if [[ -n "${HTTP_LOCAL_PID:-}" ]] && kill -0 "$HTTP_LOCAL_PID" 2>/dev/null; then
    kill "$HTTP_LOCAL_PID" 2>/dev/null || true
    wait "$HTTP_LOCAL_PID" 2>/dev/null || true
  fi
  if [[ -n "${HTTP_LOCAL_DIR:-}" ]] && [[ -d "$HTTP_LOCAL_DIR" ]]; then
    rm -rf "$HTTP_LOCAL_DIR" || true
  fi
}

if [[ -z "$HTTP_URL" && -n "$HTTP_LOCAL" ]]; then
  mkdir -p "$ROOT_DIR/.benchmarks"
  HTTP_LOCAL_DIR="$(mktemp -d "$ROOT_DIR/.benchmarks/http-local-XXXXXXXX")"
  trap cleanup_http_local EXIT

  OPENSSL_BIN="$OPENSSL_PATH"
  PROVIDER_PATH="${PQC_BENCH_PROVIDER_PATH:-}"
  PROVIDER_ARGS=(-provider oqsprovider -provider default)
  if [[ -n "$PROVIDER_PATH" ]]; then
    PROVIDER_ARGS=(-provider-path "$PROVIDER_PATH" "${PROVIDER_ARGS[@]}")
  fi

  CERT_FILE="$HTTP_LOCAL_DIR/cert.pem"
  KEY_FILE="$HTTP_LOCAL_DIR/key.pem"

  if ! openssl_req_with_conf_fallback "$OPENSSL_BIN" "$HTTP_LOCAL_DIR/cert.log" \
    "${PROVIDER_ARGS[@]}" \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" \
    -days 1; then
    echo "Warning: failed to generate local HTTPS certificate; skipping HTTP benchmarks." >&2
    tail -30 "$HTTP_LOCAL_DIR/cert.log" >&2 || true
    cleanup_http_local
  else
    HTTP_LOCAL_PORT="${PQC_BENCH_HTTP_LOCAL_PORT:-}"
    if [[ -z "$HTTP_LOCAL_PORT" ]]; then
      HTTP_LOCAL_PORT="$(
        python -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()"
      )"
    fi

    HTTP_GROUPS_HYBRID="${PQC_BENCH_HTTP_GROUPS_HYBRID:-X25519MLKEM768}"
    HTTP_GROUPS_CLASSICAL="${PQC_BENCH_HTTP_GROUPS_CLASSICAL:-X25519}"
    HTTP_SERVER_GROUPS="${PQC_BENCH_HTTP_LOCAL_GROUPS:-}"
    if [[ -z "$HTTP_SERVER_GROUPS" ]]; then
      HTTP_SERVER_GROUPS=""
      if [[ -n "$HTTP_PQC_GROUPS" ]]; then
        HTTP_SERVER_GROUPS="${HTTP_PQC_GROUPS// /:}"
      fi
      if [[ -n "$HTTP_GROUPS_HYBRID" ]]; then
        HTTP_SERVER_GROUPS="${HTTP_SERVER_GROUPS:+$HTTP_SERVER_GROUPS:}$HTTP_GROUPS_HYBRID"
      fi
      if [[ -n "$HTTP_GROUPS_CLASSICAL" ]]; then
        if [[ -z "$HTTP_GROUPS_HYBRID" || "$HTTP_GROUPS_CLASSICAL" != "$HTTP_GROUPS_HYBRID" ]]; then
          HTTP_SERVER_GROUPS="${HTTP_SERVER_GROUPS:+$HTTP_SERVER_GROUPS:}$HTTP_GROUPS_CLASSICAL"
        fi
      fi
    fi

    LD_LIBRARY_PATH="$LIBRARY_PATH" "$OPENSSL_BIN" s_server \
      "${PROVIDER_ARGS[@]}" \
      -accept "$HTTP_LOCAL_PORT" \
      -cert "$CERT_FILE" \
      -key "$KEY_FILE" \
      -tls1_3 \
      -groups "$HTTP_SERVER_GROUPS" \
      -www \
      >/dev/null 2>"$HTTP_LOCAL_DIR/server.log" &
    HTTP_LOCAL_PID=$!

    # Wait for TCP accept.
    for _ in $(seq 1 50); do
      if (echo >"/dev/tcp/127.0.0.1/$HTTP_LOCAL_PORT") >/dev/null 2>&1; then
        HTTP_URL="https://localhost:$HTTP_LOCAL_PORT/"
        break
      fi
      if ! kill -0 "$HTTP_LOCAL_PID" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done

    if [[ -z "$HTTP_URL" ]]; then
      echo "Warning: failed to start local HTTPS server; skipping HTTP benchmarks." >&2
      tail -30 "$HTTP_LOCAL_DIR/server.log" >&2 || true
      cleanup_http_local
    else
      echo "Local HTTP test server started: $HTTP_URL"
    fi
  fi
fi

if [[ -n "$HTTP_URL" ]]; then
  echo "=========================================="
  echo "HTTP benchmarks enabled"
  echo "Target URL: $HTTP_URL"
  echo "=========================================="
  HTTP_NEXT_INDEX=34

  run_step "[HTTP/1] OpenSSL (hybrid group $HTTP_GROUPS_HYBRID)..." \
    pqc-bench http --url "$HTTP_URL" --client openssl --groups "$HTTP_GROUPS_HYBRID" \
    -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" \
    -f json -o "$RESULTS_DIR/18-http-openssl-hybrid.json"

  run_step "[HTTP/2] OpenSSL (hybrid + session reuse)..." \
    pqc-bench http --url "$HTTP_URL" --client openssl --reuse session --groups "$HTTP_GROUPS_HYBRID" \
    -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" \
    -f json -o "$RESULTS_DIR/19-http-openssl-hybrid-session.json"

  run_step "[HTTP/3] OpenSSL (classical group $HTTP_GROUPS_CLASSICAL)..." \
    pqc-bench http --url "$HTTP_URL" --client openssl --groups "$HTTP_GROUPS_CLASSICAL" \
    -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" \
    -f json -o "$RESULTS_DIR/20-http-openssl-classical.json"

  if [[ -n "$HTTP_PQC_GROUPS" ]]; then
    echo ""
    echo "=========================================="
    echo "Pure-PQC HTTP benchmarks enabled (OpenSSL only)"
    echo "Groups: $HTTP_PQC_GROUPS"
    echo "=========================================="
    HTTP_PQC_INDEX=22
    for grp in $HTTP_PQC_GROUPS; do
      safe_grp="$(printf '%s' "$grp" | tr -c 'A-Za-z0-9._-' '_')"
      out_file="$(printf '%s/%02d-http-openssl-pqc-%s.json' "$RESULTS_DIR" "$HTTP_PQC_INDEX" "$safe_grp")"
      run_step "[HTTP/PQC] OpenSSL (group $grp)..." \
        pqc-bench http --url "$HTTP_URL" --client openssl --groups "$grp" \
        -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" \
        -f json -o "$out_file"
      HTTP_PQC_INDEX=$((HTTP_PQC_INDEX + 1))
    done
    if [[ "$HTTP_PQC_INDEX" -gt "$HTTP_NEXT_INDEX" ]]; then
      HTTP_NEXT_INDEX="$HTTP_PQC_INDEX"
    fi
  fi

  if python -c "import playwright" >/dev/null 2>&1; then
    PW_ARGS=(pqc-bench http --url "$HTTP_URL" --client playwright --browser "$HTTP_BROWSER" --reuse context
      -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" -f json
      -o "$RESULTS_DIR/21-http-playwright-${HTTP_BROWSER}.json")
    if [[ -n "${PQC_BENCH_BROWSER_EXECUTABLE:-}" ]]; then
      PW_ARGS+=(--browser-executable "${PQC_BENCH_BROWSER_EXECUTABLE}")
    fi
    PW_ENV=()
    if [[ -n "${SUDO_USER:-}" ]] && [[ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ]]; then
      SUDO_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
      if [[ -n "$SUDO_HOME" ]] && [[ -d "$SUDO_HOME/.cache/ms-playwright" ]]; then
        PW_ENV=(PLAYWRIGHT_BROWSERS_PATH="$SUDO_HOME/.cache/ms-playwright")
      fi
    fi
    run_step "[HTTP/4] Playwright (${HTTP_BROWSER}, reuse=context)..." env "${PW_ENV[@]}" "${PW_ARGS[@]}"
  else
    echo "Playwright not installed; skipping browser HTTP benchmark." >&2
    echo "Install: .venv/bin/pip install -e \".[web]\" (and optionally: playwright install)" >&2
  fi

  if [[ "$HTTP_FULL_PQC" == "1" ]]; then
    if [[ -z "${HTTP_LOCAL_DIR:-}" ]] || [[ ! -d "${HTTP_LOCAL_DIR:-}" ]]; then
      echo ""
      echo "Full-PQC HTTP benchmarks requested, but no local server is active; skipping." >&2
      echo "Hint: run with PQC_BENCH_HTTP_LOCAL=1 or ./run-benchmarks.sh --http-only" >&2
    else
      echo ""
      echo "=========================================="
      echo "Full-PQC HTTP benchmarks enabled (OpenSSL only)"
      echo "Scenarios: ML-KEM-512+ML-DSA-44, ML-KEM-768+ML-DSA-65, ML-KEM-1024+ML-DSA-87"
      echo "=========================================="

      OPENSSL_BIN="$OPENSSL_PATH"
      PROVIDER_PATH="${PQC_BENCH_PROVIDER_PATH:-}"
      PROVIDER_ARGS=(-provider oqsprovider -provider default)
      if [[ -n "$PROVIDER_PATH" ]]; then
        PROVIDER_ARGS=(-provider-path "$PROVIDER_PATH" "${PROVIDER_ARGS[@]}")
      fi

      FULL_PQC_SCENARIOS=("mlkem512:mldsa44" "mlkem768:mldsa65" "mlkem1024:mldsa87")

      for scenario in "${FULL_PQC_SCENARIOS[@]}"; do
        kem="${scenario%%:*}"
        sig="${scenario##*:}"
        safe_sig="$(printf '%s' "$sig" | tr -c 'A-Za-z0-9._-' '_')"
        safe_kem="$(printf '%s' "$kem" | tr -c 'A-Za-z0-9._-' '_')"

        cert_file="$HTTP_LOCAL_DIR/fullpqc-${safe_sig}-cert.pem"
        key_file="$HTTP_LOCAL_DIR/fullpqc-${safe_sig}-key.pem"
        cert_log="$HTTP_LOCAL_DIR/fullpqc-${safe_sig}-cert.log"
        server_log="$HTTP_LOCAL_DIR/fullpqc-${safe_sig}-server.log"

        if ! openssl_req_with_conf_fallback "$OPENSSL_BIN" "$cert_log" \
          "${PROVIDER_ARGS[@]}" \
          -x509 \
          -new \
          -newkey "$sig" \
          -nodes \
          -keyout "$key_file" \
          -out "$cert_file" \
          -subj "/CN=localhost" \
          -addext "subjectAltName=DNS:localhost" \
          -days 1; then
          echo "Warning: failed to generate $sig certificate; skipping scenario ($kem + $sig)." >&2
          tail -30 "$cert_log" >&2 || true
          continue
        fi

        full_port="$(
          python -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()"
        )"

        LD_LIBRARY_PATH="$LIBRARY_PATH" "$OPENSSL_BIN" s_server \
          "${PROVIDER_ARGS[@]}" \
          -accept "$full_port" \
          -cert "$cert_file" \
          -key "$key_file" \
          -tls1_3 \
          -groups "$kem" \
          -www \
          >/dev/null 2>"$server_log" &
        full_pid=$!

        full_url=""
        for _ in $(seq 1 50); do
          if (echo >"/dev/tcp/127.0.0.1/$full_port") >/dev/null 2>&1; then
            full_url="https://localhost:$full_port/"
            break
          fi
          if ! kill -0 "$full_pid" 2>/dev/null; then
            break
          fi
          sleep 0.1
        done

        if [[ -z "$full_url" ]]; then
          echo "Warning: failed to start full-PQC HTTPS server for $sig; skipping." >&2
          tail -30 "$server_log" >&2 || true
          kill "$full_pid" 2>/dev/null || true
          wait "$full_pid" 2>/dev/null || true
          continue
        fi

        out_file="$(printf '%s/%02d-http-openssl-fullpqc-%s-%s.json' "$RESULTS_DIR" "$HTTP_NEXT_INDEX" "$safe_kem" "$safe_sig")"
        run_step "[HTTP/FULL] OpenSSL (group $kem, cert $sig)..." \
          pqc-bench http --url "$full_url" --client openssl --groups "$kem" \
          -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" \
          -f json -o "$out_file"
        HTTP_NEXT_INDEX=$((HTTP_NEXT_INDEX + 1))

        kill "$full_pid" 2>/dev/null || true
        wait "$full_pid" 2>/dev/null || true
      done
    fi
  fi

  # Native HTTP benchmarks (if OpenSSL >= 3.5)
  if [[ "$NATIVE_PQC_AVAILABLE" -eq 1 ]] && [[ -n "${HTTP_LOCAL_DIR:-}" ]] && [[ -d "${HTTP_LOCAL_DIR:-}" ]]; then
    echo ""
    echo "=========================================="
    echo "Native PQC HTTP benchmarks (OpenSSL 3.5+)"
    echo "=========================================="

    # Kill the oqs-provider server
    if [[ -n "${HTTP_LOCAL_PID:-}" ]] && kill -0 "$HTTP_LOCAL_PID" 2>/dev/null; then
      kill "$HTTP_LOCAL_PID" 2>/dev/null || true
      wait "$HTTP_LOCAL_PID" 2>/dev/null || true
    fi

    # Start a native-only server (no oqs-provider needed for ML-KEM)
    NATIVE_CERT_FILE="$HTTP_LOCAL_DIR/native-cert.pem"
    NATIVE_KEY_FILE="$HTTP_LOCAL_DIR/native-key.pem"

    if openssl_req_with_conf_fallback "$OPENSSL_PATH" "$HTTP_LOCAL_DIR/native-cert.log" \
      -x509 \
      -newkey rsa:2048 \
      -nodes \
      -keyout "$NATIVE_KEY_FILE" \
      -out "$NATIVE_CERT_FILE" \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost" \
      -days 1; then

      NATIVE_HTTP_PORT="$(python -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()")"
      NATIVE_HTTP_GROUPS="X25519MLKEM768:SecP256r1MLKEM768:SecP384r1MLKEM1024:X25519"

      LD_LIBRARY_PATH="$LIBRARY_PATH" "$OPENSSL_PATH" s_server \
        -accept "$NATIVE_HTTP_PORT" \
        -cert "$NATIVE_CERT_FILE" \
        -key "$NATIVE_KEY_FILE" \
        -tls1_3 \
        -groups "$NATIVE_HTTP_GROUPS" \
        -www \
        >/dev/null 2>"$HTTP_LOCAL_DIR/native-server.log" &
      NATIVE_HTTP_PID=$!

      NATIVE_HTTP_URL=""
      for _ in $(seq 1 50); do
        if (echo >"/dev/tcp/127.0.0.1/$NATIVE_HTTP_PORT") >/dev/null 2>&1; then
          NATIVE_HTTP_URL="https://localhost:$NATIVE_HTTP_PORT/"
          break
        fi
        if ! kill -0 "$NATIVE_HTTP_PID" 2>/dev/null; then
          break
        fi
        sleep 0.1
      done

      if [[ -n "$NATIVE_HTTP_URL" ]]; then
        echo "Native HTTP test server started: $NATIVE_HTTP_URL"

        run_step "[HTTP/Native-1] OpenSSL 3.5 native (X25519MLKEM768)..." \
          pqc-bench http --url "$NATIVE_HTTP_URL" --client openssl --groups X25519MLKEM768 \
          -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" \
          -f json -o "$RESULTS_DIR/37-http-native-x25519mlkem768.json"

        run_step "[HTTP/Native-2] OpenSSL 3.5 native (X25519MLKEM768 + session)..." \
          pqc-bench http --url "$NATIVE_HTTP_URL" --client openssl --reuse session --groups X25519MLKEM768 \
          -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" \
          -f json -o "$RESULTS_DIR/38-http-native-x25519mlkem768-session.json"

        run_step "[HTTP/Native-3] OpenSSL 3.5 native (SecP256r1MLKEM768)..." \
          pqc-bench http --url "$NATIVE_HTTP_URL" --client openssl --groups SecP256r1MLKEM768 \
          -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" \
          -f json -o "$RESULTS_DIR/39-http-native-secp256r1mlkem768.json"

        run_step "[HTTP/Native-4] OpenSSL 3.5 native (SecP384r1MLKEM1024)..." \
          pqc-bench http --url "$NATIVE_HTTP_URL" --client openssl --groups SecP384r1MLKEM1024 \
          -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" \
          -f json -o "$RESULTS_DIR/40-http-native-secp384r1mlkem1024.json"

        run_step "[HTTP/Native-5] OpenSSL 3.5 native (X25519 baseline)..." \
          pqc-bench http --url "$NATIVE_HTTP_URL" --client openssl --groups X25519 \
          -n "$HTTP_SAMPLES" --warm-up "$HTTP_WARMUP" --timeout "$HTTP_TIMEOUT" \
          -f json -o "$RESULTS_DIR/41-http-native-x25519.json"
      else
        echo "Warning: failed to start native HTTPS server; skipping native HTTP benchmarks." >&2
      fi

      # Cleanup native server
      if [[ -n "${NATIVE_HTTP_PID:-}" ]] && kill -0 "$NATIVE_HTTP_PID" 2>/dev/null; then
        kill "$NATIVE_HTTP_PID" 2>/dev/null || true
        wait "$NATIVE_HTTP_PID" 2>/dev/null || true
      fi
    else
      echo "Warning: failed to generate native HTTPS certificate; skipping native HTTP benchmarks." >&2
    fi
  fi
else
  echo "HTTP benchmarks skipped (set PQC_BENCH_HTTP_URL or PQC_BENCH_HTTP_LOCAL=1 to enable)."
fi

# Capacity / Concurrency HTTP Suite (post-17, opt-in)
#
# Runs fixed-group OpenSSL HTTP benchmarks under increasing client concurrency
# to estimate capacity cost (throughput + tail latency under load).
#
# Enable with: PQC_BENCH_CAPACITY=1 ./run-benchmarks.sh --http-only
#
# Notes:
# - Uses local OpenSSL s_server instances (RSA and ML-DSA cert variants).
# - Output includes run duration + requests/sec in JSON metadata (see httpbench.py).

CAPACITY_ENABLED="${PQC_BENCH_CAPACITY:-0}"
CAPACITY_CONCURRENCY="${PQC_BENCH_CAPACITY_CONCURRENCY:-1 10 50 100 200}"
CAPACITY_SAMPLES="${PQC_BENCH_CAPACITY_SAMPLES:-1000}"
CAPACITY_WARMUP="${PQC_BENCH_CAPACITY_WARMUP:-100}"
CAPACITY_TIMEOUT="${PQC_BENCH_CAPACITY_TIMEOUT:-5}"
CAPACITY_INDEX_START="${PQC_BENCH_CAPACITY_INDEX_START:-60}"

if [[ "$CAPACITY_ENABLED" == "1" ]] && [[ "$PACKETIZATION_ONLY" != "1" ]]; then
  echo ""
  echo "=========================================="
  echo "Capacity / concurrency HTTP suite"
  echo "=========================================="

  mkdir -p "$ROOT_DIR/.benchmarks"
  CAPACITY_DIR="$(mktemp -d "$ROOT_DIR/.benchmarks/http-capacity-XXXXXXXX")"

  PROVIDER_PATH="${PQC_BENCH_PROVIDER_PATH:-}"
  PROVIDER_ARGS=(-provider oqsprovider -provider default)
  if [[ -n "$PROVIDER_PATH" ]]; then
    PROVIDER_ARGS=(-provider-path "$PROVIDER_PATH" "${PROVIDER_ARGS[@]}")
  fi

  # RSA server (classical + hybrid)
  CAP_RSA_CERT="$CAPACITY_DIR/rsa-cert.pem"
  CAP_RSA_KEY="$CAPACITY_DIR/rsa-key.pem"
  CAP_RSA_LOG="$CAPACITY_DIR/rsa-server.log"

  CAP_RSA_PORT="$(
    python -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()"
  )"
  CAP_RSA_URL="https://localhost:$CAP_RSA_PORT/"

  if ! openssl_req_with_conf_fallback "$OPENSSL_PATH" "$CAPACITY_DIR/rsa-cert.log" \
    "${PROVIDER_ARGS[@]}" \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -keyout "$CAP_RSA_KEY" \
    -out "$CAP_RSA_CERT" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" \
    -days 1; then
    echo "Warning: failed to generate RSA capacity certificate; skipping capacity suite." >&2
    rm -rf "$CAPACITY_DIR" || true
  else
    CAP_RSA_GROUPS="X25519:X25519MLKEM768:mlkem768"
    LD_LIBRARY_PATH="$LIBRARY_PATH" "$OPENSSL_PATH" s_server \
      "${PROVIDER_ARGS[@]}" \
      -accept "$CAP_RSA_PORT" \
      -cert "$CAP_RSA_CERT" \
      -key "$CAP_RSA_KEY" \
      -tls1_3 \
      -groups "$CAP_RSA_GROUPS" \
      -www \
      >/dev/null 2>"$CAP_RSA_LOG" &
    CAP_RSA_PID=$!

    # Full-PQC server (ML-DSA cert)
    CAP_FULL_CERT="$CAPACITY_DIR/mldsa-cert.pem"
    CAP_FULL_KEY="$CAPACITY_DIR/mldsa-key.pem"
    CAP_FULL_LOG="$CAPACITY_DIR/mldsa-server.log"
    CAP_FULL_PORT="$(
      python -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()"
    )"
    CAP_FULL_URL="https://localhost:$CAP_FULL_PORT/"

    CAP_FULL_OK="0"
    if openssl_req_with_conf_fallback "$OPENSSL_PATH" "$CAPACITY_DIR/mldsa-cert.log" \
      "${PROVIDER_ARGS[@]}" \
      -x509 \
      -new \
      -newkey mldsa65 \
      -nodes \
      -keyout "$CAP_FULL_KEY" \
      -out "$CAP_FULL_CERT" \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost" \
      -days 1; then
      LD_LIBRARY_PATH="$LIBRARY_PATH" "$OPENSSL_PATH" s_server \
        "${PROVIDER_ARGS[@]}" \
        -accept "$CAP_FULL_PORT" \
        -cert "$CAP_FULL_CERT" \
        -key "$CAP_FULL_KEY" \
        -tls1_3 \
        -groups "mlkem768" \
        -www \
        >/dev/null 2>"$CAP_FULL_LOG" &
      CAP_FULL_PID=$!
      CAP_FULL_OK="1"
    else
      echo "Warning: failed to generate ML-DSA cert; skipping full-PQC capacity runs." >&2
    fi

    # Wait for servers to accept TCP.
    for _ in $(seq 1 80); do
      (echo >"/dev/tcp/127.0.0.1/$CAP_RSA_PORT") >/dev/null 2>&1 && break
      sleep 0.1
    done
    if [[ "$CAP_FULL_OK" == "1" ]]; then
      for _ in $(seq 1 80); do
        (echo >"/dev/tcp/127.0.0.1/$CAP_FULL_PORT") >/dev/null 2>&1 && break
        sleep 0.1
      done
    fi

    CAPACITY_INDEX="$CAPACITY_INDEX_START"
    for c in $CAPACITY_CONCURRENCY; do
      echo "[CAP] concurrency=$c"

      meta_json="$(python -c "import json; print(json.dumps({'experiment':'capacity','concurrency':int('$c')}, separators=(',',':')))")"

      run_step "[CAP] classical (c=$c)..." \
        pqc-bench http --url "$CAP_RSA_URL" --client openssl --groups X25519 \
        -n "$CAPACITY_SAMPLES" --warm-up "$CAPACITY_WARMUP" --timeout "$CAPACITY_TIMEOUT" \
        --concurrency "$c" --meta-json "$meta_json" \
        -f json -o "$RESULTS_DIR/${CAPACITY_INDEX}-capacity-http-classical_c${c}.json"
      CAPACITY_INDEX=$((CAPACITY_INDEX + 1))

      run_step "[CAP] hybrid (c=$c)..." \
        pqc-bench http --url "$CAP_RSA_URL" --client openssl --groups X25519MLKEM768 \
        -n "$CAPACITY_SAMPLES" --warm-up "$CAPACITY_WARMUP" --timeout "$CAPACITY_TIMEOUT" \
        --concurrency "$c" --meta-json "$meta_json" \
        -f json -o "$RESULTS_DIR/${CAPACITY_INDEX}-capacity-http-hybrid_c${c}.json"
      CAPACITY_INDEX=$((CAPACITY_INDEX + 1))

      if [[ "$CAP_FULL_OK" == "1" ]]; then
        run_step "[CAP] fullpqc (c=$c)..." \
          pqc-bench http --url "$CAP_FULL_URL" --client openssl --groups mlkem768 \
          -n "$CAPACITY_SAMPLES" --warm-up "$CAPACITY_WARMUP" --timeout "$CAPACITY_TIMEOUT" \
          --concurrency "$c" --meta-json "$meta_json" \
          -f json -o "$RESULTS_DIR/${CAPACITY_INDEX}-capacity-http-fullpqc_c${c}.json"
      else
        echo "       Skipping fullpqc (missing ML-DSA cert support)"
      fi
      CAPACITY_INDEX=$((CAPACITY_INDEX + 1))
    done

    # Cleanup capacity servers
    kill "$CAP_RSA_PID" 2>/dev/null || true
    wait "$CAP_RSA_PID" 2>/dev/null || true
    if [[ "${CAP_FULL_OK:-0}" == "1" ]]; then
      kill "$CAP_FULL_PID" 2>/dev/null || true
      wait "$CAP_FULL_PID" 2>/dev/null || true
    fi
    rm -rf "$CAPACITY_DIR" || true
  fi
fi

# Packetization Experiment (Option B from PLAN.md)
#
# This is an opt-in experiment that creates network namespaces to capture
# TLS handshake packets and measure actual TCP segmentation vs the report's
# theoretical MSS-based estimates.
#
# Enable with: PQC_BENCH_PACKETIZATION=1 ./run-benchmarks.sh
# Or standalone: PQC_BENCH_PACKETIZATION_ONLY=1 ./run-benchmarks.sh
#
# Requires: root privileges, tcpdump, iproute2, ethtool

PACKETIZATION_ENABLED="${PQC_BENCH_PACKETIZATION:-0}"
# PACKETIZATION_ONLY is already set at the top of the script
PACKETIZATION_MTU="${PQC_BENCH_PACKETIZATION_MTU:-1500 1400 1280}"
PACKETIZATION_ITERATIONS="${PQC_BENCH_PACKETIZATION_ITERATIONS:-5}"
PACKETIZATION_KEEP_PCAP="${PQC_BENCH_PACKETIZATION_KEEP_PCAP:-0}"

# Define test cases: "label:kem:sig"
# These match the representative cases from PLAN.md Section 3
PACKETIZATION_CASES="${PQC_BENCH_PACKETIZATION_CASES:-}"
if [[ -z "$PACKETIZATION_CASES" ]]; then
  PACKETIZATION_CASES=(
    "baseline:X25519:rsa:2048"
    "hybrid-kem:X25519MLKEM768:rsa:2048"
    "pqc-kem:mlkem768:rsa:2048"
    "pqc-cert:X25519:mldsa65"
    "full-pqc:mlkem768:mldsa65"
  )
fi

if [[ "$PACKETIZATION_ENABLED" == "1" || "$PACKETIZATION_ONLY" == "1" ]]; then
  echo ""
  echo "=========================================="
  echo "Packetization Experiment"
  echo "=========================================="

  # Check for root
  if [[ $EUID -ne 0 ]]; then
    echo "Warning: Packetization experiment requires root privileges; skipping." >&2
    echo "Run with: sudo PQC_BENCH_PACKETIZATION=1 ./run-benchmarks.sh" >&2
  else
    # Detect original user for ownership fix (when running via sudo)
    ORIGINAL_USER="${SUDO_USER:-}"
    ORIGINAL_GROUP=""
    if [[ -n "$ORIGINAL_USER" ]]; then
      ORIGINAL_GROUP="$(id -gn "$ORIGINAL_USER" 2>/dev/null || echo "")"
    fi

    # Check for required tools
    PACKETIZATION_MISSING=""
    for cmd in ip tc tcpdump ethtool; do
      if ! command -v "$cmd" >/dev/null 2>&1; then
        PACKETIZATION_MISSING="$PACKETIZATION_MISSING $cmd"
      fi
    done

    if [[ -n "$PACKETIZATION_MISSING" ]]; then
      echo "Warning: Missing tools for packetization experiment:$PACKETIZATION_MISSING" >&2
      echo "Install with: apt install iproute2 tcpdump ethtool" >&2
    else
      # Create packetization results directory
      PACKETIZATION_DIR="$RESULTS_DIR/packetization"
      mkdir -p "$PACKETIZATION_DIR"

      CAPTURE_SCRIPT="$ROOT_DIR/src/scripts/packetization_capture.sh"

      if [[ ! -x "$CAPTURE_SCRIPT" ]]; then
        echo "Warning: Capture script not found or not executable: $CAPTURE_SCRIPT" >&2
      else
        echo "MTUs: $PACKETIZATION_MTU"
        echo "Iterations: $PACKETIZATION_ITERATIONS"
        echo "Cases: ${#PACKETIZATION_CASES[@]}"
        echo ""

        PACKETIZATION_INDEX=42
        PACKETIZATION_RESULTS=()

        for case_spec in "${PACKETIZATION_CASES[@]}"; do
          # Parse case specification
          IFS=':' read -r case_label kem_algo sig_algo <<<"$case_spec"

          for mtu in $PACKETIZATION_MTU; do
            case_dir="$PACKETIZATION_DIR/${case_label}_mtu${mtu}"
            mkdir -p "$case_dir"

            echo "[PKT] Case: $case_label, MTU: $mtu, KEM: $kem_algo, Sig: $sig_algo"

            # Build capture command
            capture_cmd=(
              "$CAPTURE_SCRIPT"
              -k "$kem_algo"
              -s "$sig_algo"
              -m "$mtu"
              -n "$PACKETIZATION_ITERATIONS"
              -o "$case_dir"
            )

            if [[ "$PACKETIZATION_KEEP_PCAP" == "1" ]]; then
              capture_cmd+=(--keep-pcap)
            fi

            # Run capture
            set +e
            capture_output=$("${capture_cmd[@]}" 2>&1)
            capture_rc=$?
            set -e

            if [[ $capture_rc -ne 0 ]]; then
              echo "       Capture failed (exit $capture_rc)" >&2
              echo "$capture_output" | tail -10 >&2
              continue
            fi

            # Extract pcap file path
            pcap_file=""
            metadata_file=""
            while IFS= read -r line; do
              if [[ "$line" == PCAP_FILE:* ]]; then
                pcap_file="${line#PCAP_FILE: }"
              elif [[ "$line" == METADATA_FILE:* ]]; then
                metadata_file="${line#METADATA_FILE: }"
              fi
            done <<<"$capture_output"

            # Run analysis
            if [[ -n "$pcap_file" ]] && [[ -f "$pcap_file" ]]; then
              analysis_file="$case_dir/analysis.json"

              set +e
              pqc-bench packetization "$pcap_file" -m "$metadata_file" -f json -o "$analysis_file" 2>/dev/null
              analysis_rc=$?
              set -e

              if [[ $analysis_rc -eq 0 ]]; then
                echo "       Analysis saved: $analysis_file"
                PACKETIZATION_RESULTS+=("$analysis_file")
              else
                echo "       Analysis failed (exit $analysis_rc)" >&2
              fi

              # Clean up pcap if not keeping
              if [[ "$PACKETIZATION_KEEP_PCAP" != "1" ]] && [[ -f "$pcap_file" ]]; then
                rm -f "$pcap_file"
              fi
            fi
          done
        done

        # Aggregate results into a single JSON file
        if [[ ${#PACKETIZATION_RESULTS[@]} -gt 0 ]]; then
          echo ""
          echo "Aggregating packetization results..."

          AGGREGATE_FILE="$RESULTS_DIR/${PACKETIZATION_INDEX}-packetization.json"

          # Create aggregate JSON using Python
          python3 <<EOF
import json
from datetime import datetime
from pathlib import Path

results = []
for path in [$(printf '"%s",' "${PACKETIZATION_RESULTS[@]}" | sed 's/,$//')]:
    try:
        with open(path) as f:
            data = json.load(f)
            # Add source file reference
            data["source_file"] = str(Path(path).name)
            results.append(data)
    except Exception as e:
        print(f"Warning: Failed to load {path}: {e}")

aggregate = {
    "metadata": {
        "generated_at": datetime.now().isoformat(),
        "version": "0.1.0",
        "experiment_type": "packetization",
        "case_count": len(results),
    },
    "environment": {
        "openssl_version": "$OPENSSL_VERSION",
    },
    "results": results,
}

with open("$AGGREGATE_FILE", "w") as f:
    json.dump(aggregate, f, indent=2)

print(f"Aggregate saved: $AGGREGATE_FILE")
EOF
        fi

        # Fix ownership of packetization files (when running via sudo)
        if [[ -n "$ORIGINAL_USER" ]] && [[ -n "$ORIGINAL_GROUP" ]]; then
          echo "Fixing ownership of packetization files..."
          chown -R "$ORIGINAL_USER:$ORIGINAL_GROUP" "$PACKETIZATION_DIR" 2>/dev/null || true
          if [[ -f "$AGGREGATE_FILE" ]]; then
            chown "$ORIGINAL_USER:$ORIGINAL_GROUP" "$AGGREGATE_FILE" 2>/dev/null || true
          fi
        fi

        echo ""
        echo "Packetization experiment complete."
      fi
    fi
  fi
fi

# Network Impairment / Breaking-Point Sweeps (post-17, opt-in)
#
# This is an opt-in experiment that runs HTTP benchmarks inside a netns/veth
# topology with tc netem to explore RTT/loss/MTU sensitivity and tail behavior.
#
# Enable with: sudo PQC_BENCH_NETEM_SWEEP=1 ./run-benchmarks.sh --http-only
#
# Requires: root privileges, iproute2 (ip, tc)

NETEM_SWEEP_ENABLED="${PQC_BENCH_NETEM_SWEEP:-0}"
NETEM_MTU="${PQC_BENCH_NETEM_MTU:-1500 1400 1280}"
NETEM_RTT_MS="${PQC_BENCH_NETEM_RTT_MS:-0 20 50 100}"
NETEM_LOSS_PCT="${PQC_BENCH_NETEM_LOSS_PCT:-0 0.1 0.5 1 2}"
NETEM_RATE="${PQC_BENCH_NETEM_RATE:-}"   # e.g., 1000mbit
NETEM_DIR="${PQC_BENCH_NETEM_DIR:-both}" # client|server|both
NETEM_SAMPLES="${PQC_BENCH_NETEM_SAMPLES:-1000}"
NETEM_WARMUP="${PQC_BENCH_NETEM_WARMUP:-100}"
NETEM_TIMEOUT="${PQC_BENCH_NETEM_TIMEOUT:-5}"
NETEM_CONCURRENCY="${PQC_BENCH_NETEM_CONCURRENCY:-1}"
NETEM_INDEX_START="${PQC_BENCH_NETEM_INDEX_START:-50}"
NETEM_SKIP_EXISTING="${PQC_BENCH_NETEM_SKIP_EXISTING:-0}"     # 0/1
NETEM_PCAP_ENABLED="${PQC_BENCH_NETEM_PCAP:-0}"               # 0/1
NETEM_PCAP_ITERATIONS="${PQC_BENCH_NETEM_PCAP_ITERATIONS:-5}" # handshakes per profile/config
NETEM_PCAP_KEEP_PCAP="${PQC_BENCH_NETEM_PCAP_KEEP_PCAP:-0}"   # 0/1

# Define configs: "label:groups:sig"
NETEM_CASES="${PQC_BENCH_NETEM_CASES:-}"
if [[ -z "$NETEM_CASES" ]]; then
  NETEM_CASES=(
    "classical:X25519:rsa:2048"
    "hybrid:X25519MLKEM768:rsa:2048"
    "fullpqc:mlkem768:mldsa65"
  )
fi

if [[ "$NETEM_SWEEP_ENABLED" == "1" ]] && [[ "$PACKETIZATION_ONLY" != "1" ]]; then
  echo ""
  echo "=========================================="
  echo "Network impairment sweeps (netem)"
  echo "=========================================="

  # Check for root
  if [[ $EUID -ne 0 ]]; then
    echo "Warning: netem sweeps require root privileges; skipping." >&2
    echo "Run with: sudo PQC_BENCH_NETEM_SWEEP=1 ./run-benchmarks.sh --http-only" >&2
  else
    # Detect original user for ownership fix (when running via sudo)
    NETEM_ORIGINAL_USER="${SUDO_USER:-}"
    NETEM_ORIGINAL_GROUP=""
    if [[ -n "$NETEM_ORIGINAL_USER" ]]; then
      NETEM_ORIGINAL_GROUP="$(id -gn "$NETEM_ORIGINAL_USER" 2>/dev/null || echo "")"
    fi

    NETEM_MISSING=""
    for cmd in ip tc; do
      if ! command -v "$cmd" >/dev/null 2>&1; then
        NETEM_MISSING="$NETEM_MISSING $cmd"
      fi
    done
    if [[ -n "$NETEM_MISSING" ]]; then
      echo "Warning: Missing tools for netem sweeps:$NETEM_MISSING" >&2
      echo "Install with: apt install iproute2" >&2
    else
      NETEM_SCRIPT="$ROOT_DIR/src/scripts/netem_http_run.sh"
      NETEM_PCAP_DIR="$RESULTS_DIR/netem-pcaps"
      NETEM_CAPTURE_SCRIPT="$ROOT_DIR/src/scripts/packetization_capture.sh"
      if [[ ! -x "$NETEM_SCRIPT" ]]; then
        echo "Warning: netem runner script not found or not executable: $NETEM_SCRIPT" >&2
      else
        if [[ "$NETEM_PCAP_ENABLED" == "1" ]]; then
          mkdir -p "$NETEM_PCAP_DIR"
          if [[ -n "$NETEM_ORIGINAL_USER" ]] && [[ -n "$NETEM_ORIGINAL_GROUP" ]]; then
            chown "${NETEM_ORIGINAL_USER}:${NETEM_ORIGINAL_GROUP}" "$NETEM_PCAP_DIR" 2>/dev/null || true
          fi
          if [[ ! -x "$NETEM_CAPTURE_SCRIPT" ]]; then
            echo "Warning: packetization capture script not found; disabling netem pcap capture." >&2
            NETEM_PCAP_ENABLED="0"
          fi
        fi

        echo "MTUs: $NETEM_MTU"
        echo "RTT (ms): $NETEM_RTT_MS"
        echo "Loss (%): $NETEM_LOSS_PCT"
        echo "Rate cap: ${NETEM_RATE:-none}"
        echo "Netem dir: $NETEM_DIR"
        echo "Samples: $NETEM_SAMPLES (warm-up: $NETEM_WARMUP)"
        echo "Timeout: ${NETEM_TIMEOUT}s"
        echo "Cases: ${#NETEM_CASES[@]}"
        if [[ "$NETEM_PCAP_ENABLED" == "1" ]]; then
          echo "PCAP: enabled (iterations=$NETEM_PCAP_ITERATIONS, keep_pcap=$NETEM_PCAP_KEEP_PCAP)"
        else
          echo "PCAP: disabled"
        fi
        echo ""

        NETEM_INDEX="$NETEM_INDEX_START"

        netem_result_is_valid() {
          local path="$1"
          python3 -c "import json,sys; json.load(open(sys.argv[1]));" "$path" >/dev/null 2>&1
        }

        netem_result_has_pcap_analysis() {
          local path="$1"
          python3 - "$path" <<'PY' >/dev/null 2>&1
import json
import os
import sys

path = sys.argv[1]
with open(path) as f:
    data = json.load(f)

pcap = data.get("pcap") or {}
analysis_file = pcap.get("analysis_file")
if not analysis_file:
    raise SystemExit(1)
if not os.path.exists(analysis_file):
    raise SystemExit(1)
PY
        }

        netem_capture_pcap_and_attach() {
          local case_label="$1"
          local case_groups="$2"
          local case_sig="$3"
          local mtu="$4"
          local rtt="$5"
          local loss="$6"
          local safe_loss="$7"
          local out_file="$8"

          local pcap_case_dir="$NETEM_PCAP_DIR/${case_label}_mtu${mtu}_rtt${rtt}_loss${safe_loss}"
          mkdir -p "$pcap_case_dir"

          # Build netem spec matching src/scripts/netem_http_run.sh.
          local netem_spec=""
          if [[ "$rtt" != "0" ]]; then
            local delay_ms=""
            if [[ "$NETEM_DIR" == "both" ]]; then
              delay_ms="$(python3 -c "print(float('$rtt')/2.0)")"
            else
              delay_ms="$rtt"
            fi
            netem_spec="delay ${delay_ms}ms"
          fi
          if [[ "$loss" != "0" ]]; then
            netem_spec="${netem_spec:+$netem_spec }loss ${loss}%"
          fi
          if [[ -n "$NETEM_RATE" ]]; then
            netem_spec="${netem_spec:+$netem_spec }rate ${NETEM_RATE}"
          fi

          local -a capture_cmd=(
            "$NETEM_CAPTURE_SCRIPT"
            -k "$case_groups"
            -s "$case_sig"
            -m "$mtu"
            -n "$NETEM_PCAP_ITERATIONS"
            -o "$pcap_case_dir"
          )
          if [[ -n "$netem_spec" ]]; then
            capture_cmd+=(--netem "$netem_spec" --netem-dir "$NETEM_DIR")
          fi

          set +e
          local capture_output
          capture_output=$("${capture_cmd[@]}" 2>&1)
          local capture_rc=$?
          set -e

          if [[ $capture_rc -ne 0 ]]; then
            echo "       PCAP capture failed (exit $capture_rc)" >&2
            echo "$capture_output" | tail -15 >&2
            return 0
          fi

          local pcap_file=""
          local metadata_file=""
          while IFS= read -r line; do
            if [[ "$line" == PCAP_FILE:* ]]; then
              pcap_file="${line#PCAP_FILE: }"
            elif [[ "$line" == METADATA_FILE:* ]]; then
              metadata_file="${line#METADATA_FILE: }"
            fi
          done <<<"$capture_output"

          if [[ -z "$pcap_file" ]] || [[ ! -f "$pcap_file" ]]; then
            return 0
          fi

          local analysis_file="$pcap_case_dir/analysis.json"
          set +e
          if [[ -n "$NETEM_ORIGINAL_USER" ]] && [[ -x "$ROOT_DIR/.venv/bin/pqc-bench" ]]; then
            sudo -u "$NETEM_ORIGINAL_USER" "$ROOT_DIR/.venv/bin/pqc-bench" packetization "$pcap_file" -m "$metadata_file" -f json -o "$analysis_file" 2>/dev/null
          else
            pqc-bench packetization "$pcap_file" -m "$metadata_file" -f json -o "$analysis_file" 2>/dev/null
          fi
          local analysis_rc=$?
          set -e

          if [[ $analysis_rc -ne 0 ]]; then
            echo "       PCAP analysis failed (exit $analysis_rc)" >&2
            return 0
          fi

          python3 <<EOF
import json
from pathlib import Path

http_path = Path("$out_file")
analysis_path = Path("$analysis_file")
pcap_path = Path("$pcap_file")

with http_path.open() as f:
    http = json.load(f)
with analysis_path.open() as f:
    analysis = json.load(f)

connections = analysis.get("connections") or []
if not isinstance(connections, list):
    connections = []

def _sum_int(key: str) -> int:
    total = 0
    for c in connections:
        if not isinstance(c, dict):
            continue
        value = c.get(key)
        if isinstance(value, int):
            total += value
    return total

http["pcap"] = {
    "pcap_file": str(pcap_path),
    "analysis_file": str(analysis_path),
    "aggregated": analysis.get("aggregated"),
    "retransmissions_total": _sum_int("retransmissions"),
    "out_of_order_total": _sum_int("out_of_order"),
}

with http_path.open("w") as f:
    json.dump(http, f, indent=2)
EOF
          echo "       PCAP analysis attached: $analysis_file"

          if [[ "$NETEM_PCAP_KEEP_PCAP" != "1" ]]; then
            rm -f "$pcap_file" 2>/dev/null || true
          fi
          return 0
        }

        for case_spec in "${NETEM_CASES[@]}"; do
          IFS=':' read -r case_label case_groups case_sig <<<"$case_spec"

          for mtu in $NETEM_MTU; do
            for rtt in $NETEM_RTT_MS; do
              for loss in $NETEM_LOSS_PCT; do
                safe_loss="$(printf '%s' "$loss" | tr '.' 'p')"
                out_file="$RESULTS_DIR/${NETEM_INDEX}-netem-http-${case_label}_mtu${mtu}_rtt${rtt}_loss${safe_loss}.json"

                echo "[NETEM] $NETEM_INDEX $case_label mtu=$mtu rtt=$rtt loss=$loss"
                if [[ "$NETEM_SKIP_EXISTING" == "1" ]] && [[ -f "$out_file" ]]; then
                  if netem_result_is_valid "$out_file"; then
                    if [[ "$NETEM_PCAP_ENABLED" != "1" ]] || netem_result_has_pcap_analysis "$out_file"; then
                      echo "       Skipping existing result: $out_file"
                      NETEM_INDEX=$((NETEM_INDEX + 1))
                      continue
                    fi

                    echo "       Skipping benchmark (exists), capturing PCAP only..."
                    netem_capture_pcap_and_attach "$case_label" "$case_groups" "$case_sig" "$mtu" "$rtt" "$loss" "$safe_loss" "$out_file"
                    NETEM_INDEX=$((NETEM_INDEX + 1))
                    continue
                  else
                    echo "       Existing result is invalid/incomplete; rerunning." >&2
                  fi
                fi
                netem_cmd=(
                  "$NETEM_SCRIPT"
                  --groups "$case_groups"
                  --sig "$case_sig"
                  --label "$case_label"
                  --mtu "$mtu"
                  --rtt-ms "$rtt"
                  --loss-pct "$loss"
                  --netem-dir "$NETEM_DIR"
                  --samples "$NETEM_SAMPLES"
                  --warm-up "$NETEM_WARMUP"
                  --timeout-s "$NETEM_TIMEOUT"
                  --concurrency "$NETEM_CONCURRENCY"
                  --output "$out_file"
                )
                if [[ -n "$NETEM_RATE" ]]; then
                  netem_cmd+=(--rate "$NETEM_RATE")
                fi

                set +e
                netem_output=$("${netem_cmd[@]}" 2>&1)
                netem_rc=$?
                set -e

                if [[ $netem_rc -ne 0 ]]; then
                  echo "       Netem run failed (exit $netem_rc)" >&2
                  echo "$netem_output" | tail -20 >&2
                  if [[ -n "$NETEM_ORIGINAL_USER" ]] && [[ -n "$NETEM_ORIGINAL_GROUP" ]] && [[ -f "$out_file" ]]; then
                    chown "${NETEM_ORIGINAL_USER}:${NETEM_ORIGINAL_GROUP}" "$out_file" 2>/dev/null || true
                  fi
                else
                  echo "       Saved: $out_file"
                  if [[ -n "$NETEM_ORIGINAL_USER" ]] && [[ -n "$NETEM_ORIGINAL_GROUP" ]] && [[ -f "$out_file" ]]; then
                    chown "${NETEM_ORIGINAL_USER}:${NETEM_ORIGINAL_GROUP}" "$out_file" 2>/dev/null || true
                  fi

                  # Optional: capture handshake pcaps under the same netem profile and attach a small summary.
                  if [[ "$NETEM_PCAP_ENABLED" == "1" ]]; then
                    netem_capture_pcap_and_attach "$case_label" "$case_groups" "$case_sig" "$mtu" "$rtt" "$loss" "$safe_loss" "$out_file"
                  fi
                fi

                NETEM_INDEX=$((NETEM_INDEX + 1))
              done
            done
          done
        done

        # Fix ownership of netem files (when running via sudo)
        if [[ -n "$NETEM_ORIGINAL_USER" ]] && [[ -n "$NETEM_ORIGINAL_GROUP" ]]; then
          echo "Fixing ownership of netem sweep files..."
          chown "${NETEM_ORIGINAL_USER}:${NETEM_ORIGINAL_GROUP}" "$RESULTS_DIR"/*-netem-http-*.json 2>/dev/null || true
          if [[ -d "$NETEM_PCAP_DIR" ]]; then
            chown -R "${NETEM_ORIGINAL_USER}:${NETEM_ORIGINAL_GROUP}" "$NETEM_PCAP_DIR" 2>/dev/null || true
          fi
        fi

        echo ""
        echo "Netem sweeps complete."
      fi
    fi
  fi
fi

echo ""
echo "=========================================="
echo "All benchmarks complete!"
echo "Finished at: $(date)"
echo "Results saved to: $RESULTS_DIR/"
echo "=========================================="
ls -la "$RESULTS_DIR"/*.json 2>/dev/null || echo "No result files found."
