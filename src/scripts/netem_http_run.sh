#!/usr/bin/env bash
# Netem HTTP Run Script for PQC Benchmarking Suite
#
# Creates a network namespace topology with veth pair, applies MTU + tc netem,
# starts an OpenSSL TLS 1.3 server, and runs `pqc-bench http` inside the client
# namespace to capture HTTP-level timings (TTFB/total) under network impairment.
#
# Requirements:
#   - Root privileges (for netns/veth/tc)
#   - iproute2 (ip, tc)
#   - OpenSSL with PQC support (oqs-provider or native 3.5+)
#   - pqc-bench available in PATH (typically via .venv/bin/activate)
#
# This script is intended to be called by run-benchmarks.sh (post-17 suites).

set -euo pipefail

# Configuration via environment
OPENSSL="${PQC_BENCH_OPENSSL:-openssl}"
PROVIDER_PATH="${PQC_BENCH_PROVIDER_PATH:-}"
LIBRARY_PATH="${PQC_BENCH_LD_LIBRARY_PATH:-}"
PQC_BENCH_BIN="${PQC_BENCH_BIN:-pqc-bench}"

maybe_set_openssl_conf() {
  if [[ -n "${PQC_BENCH_OPENSSL_CONF:-}" ]]; then
    export OPENSSL_CONF="$PQC_BENCH_OPENSSL_CONF"
  fi
}

DEFAULT_GROUPS="X25519"
DEFAULT_SIG="rsa:2048"
DEFAULT_LABEL=""
DEFAULT_MTU="1500"
DEFAULT_PORT="44333"
DEFAULT_RTT_MS="0"
DEFAULT_LOSS_PCT="0"
DEFAULT_NETEM_DIR="both" # client|server|both
DEFAULT_RATE=""          # e.g., 1000mbit

DEFAULT_HTTP_SAMPLES="200"
DEFAULT_HTTP_WARMUP="50"
DEFAULT_HTTP_TIMEOUT_S="5"
DEFAULT_HTTP_CONCURRENCY="1"
DEFAULT_HTTP_ALPN="http/1.1"

# Network namespace names (unique to avoid conflicts).
# Linux limits interface names to 15 chars, so use short prefix + truncated PID.
NS_PREFIX="pqc$(printf '%05d' $(($$ % 100000)))"
NS_SRV="${NS_PREFIX}s"
NS_CLI="${NS_PREFIX}c"
VETH_SRV="${NS_PREFIX}vs"
VETH_CLI="${NS_PREFIX}vc"

# IP addresses for the veth pair
IP_SRV="10.200.1.1"
IP_CLI="10.200.1.2"
NETMASK="24"

TEMP_DIR=""
CLEANUP_DONE=0

usage() {
  cat >&2 <<EOF
Usage: $0 [OPTIONS]

Run pqc-bench HTTP benchmark inside a netns/veth topology with tc netem.

Options:
  --groups GROUPS          TLS groups for key exchange (default: ${DEFAULT_GROUPS})
  --sig ALGORITHM          Certificate signature algorithm (default: ${DEFAULT_SIG})
  --label LABEL            Logical config label (stored in JSON metadata)
  --mtu MTU                MTU value (default: ${DEFAULT_MTU})
  --port PORT              Server port (default: ${DEFAULT_PORT})
  --rtt-ms MS              Approx RTT in ms (default: ${DEFAULT_RTT_MS})
  --loss-pct PCT           Packet loss percentage (default: ${DEFAULT_LOSS_PCT})
  --rate RATE              Netem rate cap (e.g., 1000mbit) (default: unset)
  --netem-dir DIR          Apply netem on: client|server|both (default: ${DEFAULT_NETEM_DIR})
  --samples N              Measured HTTP requests (default: ${DEFAULT_HTTP_SAMPLES})
  --warm-up N              Warm-up requests (discarded) (default: ${DEFAULT_HTTP_WARMUP})
  --timeout-s SECONDS      Timeout per request (default: ${DEFAULT_HTTP_TIMEOUT_S})
  --concurrency N          Parallel requests (OpenSSL only) (default: ${DEFAULT_HTTP_CONCURRENCY})
  --alpn ALPN              ALPN string (default: ${DEFAULT_HTTP_ALPN})
  --output FILE            Output JSON file (required)
  -h, --help               Show this help

Environment variables:
  PQC_BENCH_OPENSSL         Path to OpenSSL binary (default: openssl)
  PQC_BENCH_PROVIDER_PATH   Path to oqs-provider module
  PQC_BENCH_LD_LIBRARY_PATH LD_LIBRARY_PATH for custom OpenSSL builds
  PQC_BENCH_OPENSSL_CONF    OpenSSL config file path (sets OPENSSL_CONF)
  PQC_BENCH_BIN             pqc-bench executable (default: pqc-bench)
EOF
  exit 1
}

log_info() { echo "[INFO] $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

check_dependencies() {
  local missing=()
  for cmd in ip tc; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    log_error "Missing required tools: ${missing[*]}"
    log_error "Install with: apt install iproute2"
    exit 3
  fi

  if [[ $EUID -ne 0 ]]; then
    log_error "This script requires root privileges for network namespace operations"
    exit 3
  fi

  if ! command -v "$PQC_BENCH_BIN" >/dev/null 2>&1; then
    log_error "pqc-bench not found in PATH: $PQC_BENCH_BIN"
    exit 3
  fi

  if ! LD_LIBRARY_PATH="${LIBRARY_PATH:-}" "$OPENSSL" version >/dev/null 2>&1; then
    log_error "OpenSSL not found or not runnable at: $OPENSSL"
    exit 3
  fi

  maybe_set_openssl_conf
}

cleanup() {
  if [[ "$CLEANUP_DONE" == "1" ]]; then
    return 0
  fi
  CLEANUP_DONE=1

  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi

  ip netns del "$NS_SRV" 2>/dev/null || true
  ip netns del "$NS_CLI" 2>/dev/null || true

  if [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]]; then
    rm -rf "$TEMP_DIR"
  fi
}

trap cleanup EXIT

setup_network() {
  local mtu="$1"

  ip netns add "$NS_SRV"
  ip netns add "$NS_CLI"

  ip link add "$VETH_SRV" type veth peer name "$VETH_CLI"
  ip link set "$VETH_SRV" netns "$NS_SRV"
  ip link set "$VETH_CLI" netns "$NS_CLI"

  ip netns exec "$NS_SRV" ip addr add "${IP_SRV}/${NETMASK}" dev "$VETH_SRV"
  ip netns exec "$NS_SRV" ip link set "$VETH_SRV" mtu "$mtu"
  ip netns exec "$NS_SRV" ip link set "$VETH_SRV" up
  ip netns exec "$NS_SRV" ip link set lo up

  ip netns exec "$NS_CLI" ip addr add "${IP_CLI}/${NETMASK}" dev "$VETH_CLI"
  ip netns exec "$NS_CLI" ip link set "$VETH_CLI" mtu "$mtu"
  ip netns exec "$NS_CLI" ip link set "$VETH_CLI" up
  ip netns exec "$NS_CLI" ip link set lo up

  # Best-effort: disable offloads (avoids surprises in packet sizing).
  if command -v ethtool >/dev/null 2>&1; then
    ip netns exec "$NS_SRV" ethtool -K "$VETH_SRV" tso off gso off gro off 2>/dev/null || true
    ip netns exec "$NS_CLI" ethtool -K "$VETH_CLI" tso off gso off gro off 2>/dev/null || true
  fi

  if ! ip netns exec "$NS_CLI" ping -c 1 -W 1 "$IP_SRV" >/dev/null 2>&1; then
    log_error "Failed to establish connectivity between namespaces"
    return 1
  fi
}

apply_netem() {
  local mtu="$1"
  local rtt_ms="$2"
  local loss_pct="$3"
  local rate="$4"
  local netem_dir="$5"

  # Build netem spec.
  local spec=()
  local delay_ms="0"

  # RTT model:
  # - both: apply rtt/2 on each direction (closest to symmetric RTT)
  # - client/server: apply full rtt on the chosen direction only (egress-only shaping)
  if [[ "$rtt_ms" != "0" ]]; then
    if [[ "$netem_dir" == "both" ]]; then
      delay_ms="$(python3 -c "print(float('$rtt_ms')/2.0)")"
    else
      delay_ms="$rtt_ms"
    fi
    spec+=(delay "${delay_ms}ms")
  fi

  if [[ "$loss_pct" != "0" ]]; then
    spec+=(loss "${loss_pct}%")
  fi

  if [[ -n "$rate" ]]; then
    spec+=(rate "$rate")
  fi

  if [[ ${#spec[@]} -eq 0 ]]; then
    return 0
  fi

  # Apply MTU (explicit, in case caller changes MTU between runs).
  ip netns exec "$NS_SRV" ip link set dev "$VETH_SRV" mtu "$mtu"
  ip netns exec "$NS_CLI" ip link set dev "$VETH_CLI" mtu "$mtu"

  # Apply netem using "replace" so re-running is idempotent.
  if [[ "$netem_dir" == "client" || "$netem_dir" == "both" ]]; then
    ip netns exec "$NS_CLI" tc qdisc replace dev "$VETH_CLI" root netem "${spec[@]}"
  fi
  if [[ "$netem_dir" == "server" || "$netem_dir" == "both" ]]; then
    ip netns exec "$NS_SRV" tc qdisc replace dev "$VETH_SRV" root netem "${spec[@]}"
  fi
}

build_provider_args() {
  local args=(-provider oqsprovider -provider default)
  if [[ -n "$PROVIDER_PATH" ]]; then
    args=(-provider-path "$PROVIDER_PATH" "${args[@]}")
  fi
  printf '%s\n' "${args[@]}"
}

generate_certificate() {
  local sig_algo="$1"
  local cert_file="$2"
  local key_file="$3"
  local cert_log="$4"

  local provider_args=()
  mapfile -t provider_args < <(build_provider_args)

  local openssl_cmd=("$OPENSSL" req -x509 -new -nodes)
  if [[ ${#provider_args[@]} -gt 0 ]]; then
    openssl_cmd+=("${provider_args[@]}")
  fi

  openssl_cmd+=(
    -newkey "$sig_algo"
    -keyout "$key_file"
    -out "$cert_file"
    -subj "/CN=${IP_SRV}"
    -addext "subjectAltName=IP:${IP_SRV}"
    -days 1
  )

  if LD_LIBRARY_PATH="${LIBRARY_PATH:-}" "${openssl_cmd[@]}" >/dev/null 2>"$cert_log"; then
    return 0
  fi

  if [[ -z "${OPENSSL_CONF:-}" ]] && grep -Eq "process_include:No such file or directory|calling stat\\(" "$cert_log"; then
    export OPENSSL_CONF="/dev/null"
    export PQC_BENCH_OPENSSL_CONF="$OPENSSL_CONF"
    log_info "Retrying openssl req with OPENSSL_CONF=/dev/null"
    if LD_LIBRARY_PATH="${LIBRARY_PATH:-}" OPENSSL_CONF="$OPENSSL_CONF" "${openssl_cmd[@]}" >/dev/null 2>>"$cert_log"; then
      return 0
    fi
  fi

  log_error "Failed to generate certificate with $sig_algo"
  tail -30 "$cert_log" >&2 || true
  return 1
}

start_server() {
  local server_groups="$1"
  local cert_file="$2"
  local key_file="$3"
  local port="$4"
  local server_log="$5"

  local provider_args=()
  mapfile -t provider_args < <(build_provider_args)

  local server_cmd=("$OPENSSL" s_server)
  if [[ ${#provider_args[@]} -gt 0 ]]; then
    server_cmd+=("${provider_args[@]}")
  fi
  server_cmd+=(
    -accept "$port"
    -cert "$cert_file"
    -key "$key_file"
    -tls1_3
    -groups "$server_groups"
    -www
    -quiet
  )

  ip netns exec "$NS_SRV" env LD_LIBRARY_PATH="${LIBRARY_PATH:-}" \
    "${server_cmd[@]}" >"$server_log" 2>&1 &
  SERVER_PID=$!

  # Wait for TCP accept.
  for _ in $(seq 1 80); do
    if ip netns exec "$NS_CLI" bash -c "echo > /dev/tcp/${IP_SRV}/${port}" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  log_error "Server failed to become ready"
  tail -30 "$server_log" >&2 || true
  return 1
}

main() {
  local groups="$DEFAULT_GROUPS"
  local sig_algo="$DEFAULT_SIG"
  local label="$DEFAULT_LABEL"
  local mtu="$DEFAULT_MTU"
  local port="$DEFAULT_PORT"
  local rtt_ms="$DEFAULT_RTT_MS"
  local loss_pct="$DEFAULT_LOSS_PCT"
  local rate="$DEFAULT_RATE"
  local netem_dir="$DEFAULT_NETEM_DIR"

  local samples="$DEFAULT_HTTP_SAMPLES"
  local warm_up="$DEFAULT_HTTP_WARMUP"
  local timeout_s="$DEFAULT_HTTP_TIMEOUT_S"
  local concurrency="$DEFAULT_HTTP_CONCURRENCY"
  local alpn="$DEFAULT_HTTP_ALPN"
  local output_file=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --groups)
        groups="$2"
        shift 2
        ;;
      --sig)
        sig_algo="$2"
        shift 2
        ;;
      --label)
        label="$2"
        shift 2
        ;;
      --mtu)
        mtu="$2"
        shift 2
        ;;
      --port)
        port="$2"
        shift 2
        ;;
      --rtt-ms)
        rtt_ms="$2"
        shift 2
        ;;
      --loss-pct)
        loss_pct="$2"
        shift 2
        ;;
      --rate)
        rate="$2"
        shift 2
        ;;
      --netem-dir)
        netem_dir="$2"
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
      --concurrency)
        concurrency="$2"
        shift 2
        ;;
      --alpn)
        alpn="$2"
        shift 2
        ;;
      --output)
        output_file="$2"
        shift 2
        ;;
      -h | --help) usage ;;
      *)
        log_error "Unknown option: $1"
        usage
        ;;
    esac
  done

  if [[ -z "$output_file" ]]; then
    log_error "--output is required"
    usage
  fi

  check_dependencies

  TEMP_DIR="$(mktemp -d)"
  local cert_file="$TEMP_DIR/cert.pem"
  local key_file="$TEMP_DIR/key.pem"
  local cert_log="$TEMP_DIR/cert.log"
  local server_log="$TEMP_DIR/server.log"

  log_info "=== Netem HTTP Run ==="
  log_info "groups=$groups sig=$sig_algo mtu=$mtu rtt_ms=$rtt_ms loss_pct=$loss_pct rate=${rate:-none} dir=$netem_dir"
  log_info "samples=$samples warm_up=$warm_up timeout_s=$timeout_s concurrency=$concurrency"

  generate_certificate "$sig_algo" "$cert_file" "$key_file" "$cert_log"
  setup_network "$mtu"
  apply_netem "$mtu" "$rtt_ms" "$loss_pct" "$rate" "$netem_dir"
  start_server "$groups" "$cert_file" "$key_file" "$port" "$server_log"

  local url="https://${IP_SRV}:${port}/"
  meta_json="$(python3 -c "import json; meta={'experiment':'netem','netem':{'mtu':int('$mtu'),'rtt_ms':float('$rtt_ms'),'loss_pct':float('$loss_pct'),'netem_dir':'$netem_dir'}}; meta['netem'].update({'rate':'$rate'} if '$rate' else {}); meta.update({'label':'$label'} if '$label' else {}); print(json.dumps(meta, separators=(',',':')))")"
  set +e
  ip netns exec "$NS_CLI" "$PQC_BENCH_BIN" http \
    --url "$url" \
    --client openssl \
    --groups "$groups" \
    --alpn "$alpn" \
    --meta-json "$meta_json" \
    -n "$samples" \
    --warm-up "$warm_up" \
    --timeout "$timeout_s" \
    --concurrency "$concurrency" \
    -f json \
    -o "$output_file"
  rc=$?
  set -e

  # If invoked via sudo, make output user-owned even when the run fails/aborts.
  if [[ -n "${SUDO_USER:-}" ]] && [[ -f "$output_file" ]]; then
    sudo_group="$(id -gn "$SUDO_USER" 2>/dev/null || true)"
    if [[ -n "$sudo_group" ]]; then
      chown "$SUDO_USER:$sudo_group" "$output_file" 2>/dev/null || true
    else
      chown "$SUDO_USER" "$output_file" 2>/dev/null || true
    fi
  fi

  echo "RESULT_FILE: $output_file"
  exit "$rc"
}

main "$@"
