#!/usr/bin/env bash
# perf HTTP profiling helper for PQC Bench.
#
# Runs `perf record` while executing `pqc-bench http` against a local OpenSSL
# `s_server`, to help explain "why OpenSSL X is faster" with call stacks.
#
# Notes:
# - `perf record` inherits into child processes by default, so spawned `openssl`
#   clients are included in the trace on typical systems.
# - You may need elevated privileges depending on kernel perf settings
#   (`/proc/sys/kernel/perf_event_paranoid`).
#
# Example:
#   ./src/scripts/perf_http_profile.sh --scenario hybrid --samples 2000
#
# Output:
#   <out_dir>/http.json
#   <out_dir>/perf.data
#   <out_dir>/perf.report.txt
#   <out_dir>/perf.script.txt

set -euo pipefail

OPENSSL="${PQC_BENCH_OPENSSL:-openssl}"
PROVIDER_PATH="${PQC_BENCH_PROVIDER_PATH:-}"
LIBRARY_PATH="${PQC_BENCH_LD_LIBRARY_PATH:-}"
PQC_BENCH_BIN="${PQC_BENCH_BIN:-pqc-bench}"

DEFAULT_SCENARIO="hybrid" # classical|hybrid|fullpqc
DEFAULT_SAMPLES="2000"
DEFAULT_WARMUP="200"
DEFAULT_TIMEOUT_S="5"
DEFAULT_FREQ="99"

usage() {
  cat >&2 <<EOF
Usage: $0 [OPTIONS]

Options:
  --scenario NAME          classical|hybrid|fullpqc (default: ${DEFAULT_SCENARIO})
  --samples N              measured requests (default: ${DEFAULT_SAMPLES})
  --warm-up N              warm-up requests discarded (default: ${DEFAULT_WARMUP})
  --timeout-s SECONDS      timeout per request (default: ${DEFAULT_TIMEOUT_S})
  --freq HZ                perf sampling frequency (default: ${DEFAULT_FREQ})
  --out-dir DIR            output directory (default: ./perf-http-YYYYmmdd-HHMMSS)
  -h, --help               show help

Environment:
  PQC_BENCH_OPENSSL         path to OpenSSL binary
  PQC_BENCH_PROVIDER_PATH   path to oqs-provider module (optional)
  PQC_BENCH_LD_LIBRARY_PATH LD_LIBRARY_PATH for OpenSSL
  PQC_BENCH_OPENSSL_CONF    OpenSSL config file path (sets OPENSSL_CONF)
  PQC_BENCH_BIN             pqc-bench executable (default: pqc-bench)
EOF
  exit 1
}

maybe_set_openssl_conf() {
  if [[ -n "${PQC_BENCH_OPENSSL_CONF:-}" ]]; then
    export OPENSSL_CONF="$PQC_BENCH_OPENSSL_CONF"
  fi
}

build_provider_args() {
  local args=(-provider oqsprovider -provider default)
  if [[ -n "$PROVIDER_PATH" ]]; then
    args=(-provider-path "$PROVIDER_PATH" "${args[@]}")
  fi
  printf '%s\n' "${args[@]}"
}

main() {
  local scenario="$DEFAULT_SCENARIO"
  local samples="$DEFAULT_SAMPLES"
  local warm_up="$DEFAULT_WARMUP"
  local timeout_s="$DEFAULT_TIMEOUT_S"
  local freq="$DEFAULT_FREQ"
  local out_dir=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --scenario)
        scenario="$2"
        shift 2
        ;;
      --samples)
        samples="$2"
        shift 2
        ;;
      --warm-up)
        warm_up="$2"
        shift 2
        ;;
      --timeout-s)
        timeout_s="$2"
        shift 2
        ;;
      --freq)
        freq="$2"
        shift 2
        ;;
      --out-dir)
        out_dir="$2"
        shift 2
        ;;
      -h | --help) usage ;;
      *)
        echo "[ERROR] Unknown option: $1" >&2
        usage
        ;;
    esac
  done

  if [[ -z "$out_dir" ]]; then
    out_dir="./perf-http-$(date +%Y%m%d-%H%M%S)"
  fi
  mkdir -p "$out_dir"

  if ! command -v perf >/dev/null 2>&1; then
    echo "[ERROR] perf not found. Install linux-tools/perf." >&2
    exit 3
  fi
  if ! command -v "$PQC_BENCH_BIN" >/dev/null 2>&1; then
    echo "[ERROR] pqc-bench not found in PATH: $PQC_BENCH_BIN" >&2
    exit 3
  fi
  if ! LD_LIBRARY_PATH="${LIBRARY_PATH:-}" "$OPENSSL" version >/dev/null 2>&1; then
    echo "[ERROR] OpenSSL not found or not runnable at: $OPENSSL" >&2
    exit 3
  fi
  maybe_set_openssl_conf

  local groups sig
  case "$scenario" in
    classical)
      groups="X25519"
      sig="rsa:2048"
      ;;
    hybrid)
      groups="X25519MLKEM768"
      sig="rsa:2048"
      ;;
    fullpqc)
      groups="mlkem768"
      sig="mldsa65"
      ;;
    *)
      echo "[ERROR] --scenario must be one of: classical|hybrid|fullpqc" >&2
      exit 2
      ;;
  esac

  local provider_args=()
  mapfile -t provider_args < <(build_provider_args)

  local temp_dir
  temp_dir="$(mktemp -d)"
  local cert_file="$temp_dir/cert.pem"
  local key_file="$temp_dir/key.pem"

  # Generate a short-lived self-signed certificate.
  if ! LD_LIBRARY_PATH="${LIBRARY_PATH:-}" "$OPENSSL" req \
    "${provider_args[@]}" \
    -x509 \
    -new \
    -newkey "$sig" \
    -nodes \
    -keyout "$key_file" \
    -out "$cert_file" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" \
    -days 1 \
    >/dev/null 2>"$out_dir/cert.log"; then
    if [[ -z "${OPENSSL_CONF:-}" ]] && grep -Eq "process_include:No such file or directory|calling stat\\(" "$out_dir/cert.log"; then
      export OPENSSL_CONF="/dev/null"
      export PQC_BENCH_OPENSSL_CONF="$OPENSSL_CONF"
      echo "[INFO] Retrying openssl req with OPENSSL_CONF=/dev/null" >&2
      if ! LD_LIBRARY_PATH="${LIBRARY_PATH:-}" OPENSSL_CONF="$OPENSSL_CONF" "$OPENSSL" req \
        "${provider_args[@]}" \
        -x509 \
        -new \
        -newkey "$sig" \
        -nodes \
        -keyout "$key_file" \
        -out "$cert_file" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost" \
        -days 1 \
        >/dev/null 2>>"$out_dir/cert.log"; then
        echo "[ERROR] Failed to generate certificate ($sig). See: $out_dir/cert.log" >&2
        rm -rf "$temp_dir"
        exit 2
      fi
    else
      echo "[ERROR] Failed to generate certificate ($sig). See: $out_dir/cert.log" >&2
      rm -rf "$temp_dir"
      exit 2
    fi
  fi

  local port
  port="$(
    python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()"
  )"
  local url="https://localhost:${port}/"

  LD_LIBRARY_PATH="$LIBRARY_PATH" "$OPENSSL" s_server \
    "${provider_args[@]}" \
    -accept "$port" \
    -cert "$cert_file" \
    -key "$key_file" \
    -tls1_3 \
    -groups "$groups" \
    -www \
    >/dev/null 2>"$out_dir/server.log" &
  local server_pid=$!

  # Wait for TCP accept.
  local ready=0
  for _ in $(seq 1 80); do
    if (echo >"/dev/tcp/127.0.0.1/$port") >/dev/null 2>&1; then
      ready=1
      break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  if [[ "$ready" != "1" ]]; then
    echo "[ERROR] Server failed to start. See: $out_dir/server.log" >&2
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    rm -rf "$temp_dir"
    exit 2
  fi

  meta_json="$(python3 -c "import json; print(json.dumps({'experiment':'perf','scenario':'$scenario','groups':'$groups','sig':'$sig'}, separators=(',',':')))")"

  echo "[INFO] Profiling scenario=$scenario url=$url samples=$samples warm_up=$warm_up freq=$freq"
  echo "[INFO] Writing to: $out_dir"

  set +e
  perf record -F "$freq" -g -o "$out_dir/perf.data" -- \
    "$PQC_BENCH_BIN" http --url "$url" --client openssl --groups "$groups" \
    -n "$samples" --warm-up "$warm_up" --timeout "$timeout_s" \
    --no-sample-details --meta-json "$meta_json" \
    -f json -o "$out_dir/http.json"
  local rc=$?
  set -e

  # Stop server
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  rm -rf "$temp_dir"

  if [[ $rc -ne 0 ]]; then
    echo "[ERROR] perf record or benchmark failed (exit $rc)." >&2
    echo "Hint: try sudo, or lower perf restrictions (perf_event_paranoid)." >&2
    exit "$rc"
  fi

  perf report --stdio -i "$out_dir/perf.data" >"$out_dir/perf.report.txt" 2>/dev/null || true
  perf script -i "$out_dir/perf.data" >"$out_dir/perf.script.txt" 2>/dev/null || true

  echo "[INFO] Done:"
  echo "  - $out_dir/perf.data"
  echo "  - $out_dir/perf.report.txt"
  echo "  - $out_dir/perf.script.txt"
  echo "  - $out_dir/http.json"
}

main "$@"
