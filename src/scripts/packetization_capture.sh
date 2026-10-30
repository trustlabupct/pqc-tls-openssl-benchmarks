#!/bin/bash
# Packetization Capture Script for PQC Benchmarking Suite
#
# Creates a network namespace topology with veth pair, runs TLS handshakes
# with specified KEM/signature algorithms, and captures packets for analysis.
#
# This script implements Option B from PLAN.md: a standalone packetization
# experiment harness that produces pcap files for post-hoc analysis.
#
# Requirements:
#   - Root privileges (for netns/veth creation and tcpdump)
#   - iproute2 (ip, tc), tcpdump, ethtool
#   - OpenSSL with PQC support (oqs-provider or native 3.5+)
#
# Output:
#   - Writes pcap and metadata to specified output directory
#   - Exits 0 on success, 1 on failure, 3 on missing dependencies

set -euo pipefail

# Configuration via environment
OPENSSL="${PQC_BENCH_OPENSSL:-openssl}"
PROVIDER_PATH="${PQC_BENCH_PROVIDER_PATH:-}"
USE_NATIVE="${PQC_BENCH_USE_NATIVE:-0}"
LIBRARY_PATH="${PQC_BENCH_LD_LIBRARY_PATH:-}"

# If invoked via sudo, keep outputs user-owned.
ORIGINAL_USER="${SUDO_USER:-}"
ORIGINAL_GROUP=""
if [[ -n "$ORIGINAL_USER" ]]; then
  ORIGINAL_GROUP="$(id -gn "$ORIGINAL_USER" 2>/dev/null || true)"
fi

OUTPUT_DIR=""

# Default test parameters
DEFAULT_MTU="1500"
DEFAULT_ITERATIONS="5"
DEFAULT_PORT="44333"

# Network namespace names (unique to avoid conflicts)
# Linux limits interface names to 15 chars, so use short prefix + truncated PID
NS_PREFIX="pqc$(printf '%05d' $(($$ % 100000)))"
NS_SRV="${NS_PREFIX}s"
NS_CLI="${NS_PREFIX}c"
VETH_SRV="${NS_PREFIX}vs"
VETH_CLI="${NS_PREFIX}vc"

# IP addresses for the veth pair
IP_SRV="10.200.1.1"
IP_CLI="10.200.1.2"
NETMASK="24"

# Temporary directory for certificates and logs
TEMP_DIR=""
CLEANUP_DONE=0

# Algorithms natively supported in OpenSSL 3.5+
NATIVE_KEMS="mlkem512 mlkem768 mlkem1024 ML-KEM-512 ML-KEM-768 ML-KEM-1024 MLKEM512 MLKEM768 MLKEM1024 X25519MLKEM768 X448MLKEM1024 SecP256r1MLKEM768 SecP384r1MLKEM1024"
NATIVE_MLDSA="mldsa44 mldsa65 mldsa87 ML-DSA-44 ML-DSA-65 ML-DSA-87 MLDSA44 MLDSA65 MLDSA87"
NATIVE_SIGS="$NATIVE_MLDSA"

# Utility functions

usage() {
  cat >&2 <<EOF
Usage: $0 [OPTIONS]

Capture TLS handshake packets for MTU/packetization analysis.

Options:
  -k, --kem ALGORITHM       KEM algorithm (default: X25519)
  -s, --sig ALGORITHM       Signature algorithm (default: rsa:2048)
  -m, --mtu MTU             MTU value (default: $DEFAULT_MTU)
  -n, --iterations N        Number of handshakes (default: $DEFAULT_ITERATIONS)
  -o, --output-dir DIR      Output directory for pcap/metadata (required)
  -p, --port PORT           TLS server port (default: $DEFAULT_PORT)
      --netem SPEC          Apply tc netem (e.g., "delay 20ms loss 0.1%")
      --netem-dir DIR       Apply netem on: client|server|both (default: client)
      --keep-pcap           Keep pcap file (default: delete after analysis)
  -h, --help                Show this help

Environment variables:
  PQC_BENCH_OPENSSL         Path to OpenSSL binary (default: openssl)
  PQC_BENCH_PROVIDER_PATH   Path to oqs-provider module
  PQC_BENCH_USE_NATIVE      Use native OpenSSL 3.5+ PQC (1=yes, 0=no)
  PQC_BENCH_LD_LIBRARY_PATH LD_LIBRARY_PATH for custom OpenSSL builds
  PQC_BENCH_OPENSSL_CONF    OpenSSL config file path (sets OPENSSL_CONF)

Examples:
  # Baseline: X25519 + RSA certificate
  sudo $0 -k X25519 -s rsa:2048 -m 1500 -n 5 -o ./captures

  # Hybrid KEM + RSA certificate
  sudo $0 -k X25519MLKEM768 -s rsa:2048 -m 1500 -n 5 -o ./captures

  # Pure PQC: ML-KEM + ML-DSA certificate
  sudo $0 -k mlkem768 -s mldsa65 -m 1400 -n 5 -o ./captures
EOF
  exit 1
}

log_info() {
  echo "[INFO] $*" >&2
}

log_error() {
  echo "[ERROR] $*" >&2
}

log_debug() {
  if [[ "${VERBOSE:-0}" == "1" ]]; then
    echo "[DEBUG] $*" >&2
  fi
}

maybe_set_openssl_conf() {
  if [[ -n "${PQC_BENCH_OPENSSL_CONF:-}" ]]; then
    export OPENSSL_CONF="$PQC_BENCH_OPENSSL_CONF"
  fi
}

# Check if algorithm is natively supported (KEM)
is_native_kem() {
  local algo="$1"
  local algo_lower="${algo,,}"
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
  local algo_lower="${algo,,}"
  # RSA is always native
  if [[ "$algo_lower" == rsa* ]]; then
    return 0
  fi
  for native in $NATIVE_SIGS; do
    if [[ "${native,,}" == "$algo_lower" ]]; then
      return 0
    fi
  done
  return 1
}

# Check required tools
check_dependencies() {
  local missing=()

  for cmd in ip tc tcpdump ethtool; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    log_error "Missing required tools: ${missing[*]}"
    log_error "Install with: apt install iproute2 tcpdump ethtool"
    exit 3
  fi

  # Check for root/CAP_NET_ADMIN
  if [[ $EUID -ne 0 ]]; then
    log_error "This script requires root privileges for network namespace operations"
    exit 3
  fi

  # Check OpenSSL
  if ! LD_LIBRARY_PATH="${LIBRARY_PATH:-}" "$OPENSSL" version >/dev/null 2>&1; then
    log_error "OpenSSL not found at: $OPENSSL"
    exit 3
  fi

  maybe_set_openssl_conf
}

# Network namespace setup/teardown

cleanup() {
  if [[ "$CLEANUP_DONE" == "1" ]]; then
    return 0
  fi
  CLEANUP_DONE=1

  log_debug "Cleaning up network namespaces and processes..."

  # Kill any server process
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi

  # Kill tcpdump
  if [[ -n "${TCPDUMP_PID:-}" ]] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
  fi

  # Delete network namespaces (this also removes veth pairs)
  ip netns del "$NS_SRV" 2>/dev/null || true
  ip netns del "$NS_CLI" 2>/dev/null || true

  # Cleanup temp directory
  if [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]]; then
    rm -rf "$TEMP_DIR"
  fi

  # Best-effort: fix ownership of capture outputs.
  if [[ -n "$ORIGINAL_USER" ]] && [[ -n "$OUTPUT_DIR" ]] && [[ -d "$OUTPUT_DIR" ]]; then
    if [[ -n "$ORIGINAL_GROUP" ]]; then
      chown -R "$ORIGINAL_USER:$ORIGINAL_GROUP" "$OUTPUT_DIR" 2>/dev/null || true
    else
      chown -R "$ORIGINAL_USER" "$OUTPUT_DIR" 2>/dev/null || true
    fi
  fi
}

trap cleanup EXIT

setup_network() {
  local mtu="$1"
  local netem_spec="${2:-}"
  local netem_dir="${3:-client}"

  log_info "Creating network namespaces with MTU=$mtu..."

  # Create namespaces
  ip netns add "$NS_SRV"
  ip netns add "$NS_CLI"

  # Create veth pair
  ip link add "$VETH_SRV" type veth peer name "$VETH_CLI"

  # Move each end to its namespace
  ip link set "$VETH_SRV" netns "$NS_SRV"
  ip link set "$VETH_CLI" netns "$NS_CLI"

  # Configure server side
  ip netns exec "$NS_SRV" ip addr add "${IP_SRV}/${NETMASK}" dev "$VETH_SRV"
  ip netns exec "$NS_SRV" ip link set "$VETH_SRV" mtu "$mtu"
  ip netns exec "$NS_SRV" ip link set "$VETH_SRV" up
  ip netns exec "$NS_SRV" ip link set lo up

  # Configure client side
  ip netns exec "$NS_CLI" ip addr add "${IP_CLI}/${NETMASK}" dev "$VETH_CLI"
  ip netns exec "$NS_CLI" ip link set "$VETH_CLI" mtu "$mtu"
  ip netns exec "$NS_CLI" ip link set "$VETH_CLI" up
  ip netns exec "$NS_CLI" ip link set lo up

  # Disable offloads to get accurate packet sizes in captures
  for ns in "$NS_SRV" "$NS_CLI"; do
    local iface
    if [[ "$ns" == "$NS_SRV" ]]; then
      iface="$VETH_SRV"
    else
      iface="$VETH_CLI"
    fi
    ip netns exec "$ns" ethtool -K "$iface" tso off gso off gro off 2>/dev/null || true
    ip netns exec "$ns" ethtool -K "$iface" tx off rx off 2>/dev/null || true
  done

  # Apply netem if specified (egress shaping via tc netem)
  if [[ -n "$netem_spec" ]]; then
    log_info "Applying netem (${netem_dir}): $netem_spec"
    # shellcheck disable=SC2086
    if [[ "$netem_dir" == "client" || "$netem_dir" == "both" ]]; then
      ip netns exec "$NS_CLI" tc qdisc replace dev "$VETH_CLI" root netem $netem_spec || true
    fi
    # shellcheck disable=SC2086
    if [[ "$netem_dir" == "server" || "$netem_dir" == "both" ]]; then
      ip netns exec "$NS_SRV" tc qdisc replace dev "$VETH_SRV" root netem $netem_spec || true
    fi
  fi

  # Verify connectivity (best-effort under loss/jitter). Retry a few times to
  # avoid false negatives when netem loss drops the single probe.
  local ping_ok=0
  for _ in 1 2 3 4 5; do
    if ip netns exec "$NS_CLI" ping -c 1 -W 1 "$IP_SRV" >/dev/null 2>&1; then
      ping_ok=1
      break
    fi
    sleep 0.1
  done
  if [[ "$ping_ok" != "1" ]]; then
    log_error "Failed to establish connectivity between namespaces"
    return 1
  fi

  log_debug "Network namespaces configured successfully"
}

# Certificate generation

generate_certificate() {
  local sig_algo="$1"
  local cert_file="$2"
  local key_file="$3"
  local cert_log="$4"

  log_info "Generating certificate with $sig_algo..."

  # Select native or provider mode.
  # RSA is ALWAYS native - never use oqs-provider for RSA certificates
  local use_provider=1
  if [[ "$sig_algo" == rsa:* ]]; then
    use_provider=0 # RSA is always native, never needs provider
  elif [[ "$USE_NATIVE" == "1" ]] && is_native_sig "$sig_algo"; then
    use_provider=0
  fi

  # Build provider arguments
  local provider_args=()
  if [[ "$use_provider" == "1" ]] && [[ -n "$PROVIDER_PATH" ]]; then
    provider_args=(-provider-path "$PROVIDER_PATH" -provider oqsprovider -provider default)
  elif [[ "$use_provider" == "1" ]]; then
    provider_args=(-provider oqsprovider -provider default)
  fi

  # Handle RSA specially
  local newkey_arg="$sig_algo"
  if [[ "$sig_algo" == rsa:* ]]; then
    newkey_arg="$sig_algo"
  fi

  # Generate certificate
  local openssl_cmd=("$OPENSSL" req)
  if [[ ${#provider_args[@]} -gt 0 ]]; then
    openssl_cmd+=("${provider_args[@]}")
  fi
  openssl_cmd+=(
    -x509
    -new
    -newkey "$newkey_arg"
    -keyout "$key_file"
    -out "$cert_file"
    -nodes
    -days 1
    -subj "/CN=packetization-test"
  )

  if ! LD_LIBRARY_PATH="${LIBRARY_PATH:-}" "${openssl_cmd[@]}" 2>"$cert_log"; then
    if [[ -z "${OPENSSL_CONF:-}" ]] && grep -Eq "process_include:No such file or directory|calling stat\\(" "$cert_log"; then
      export OPENSSL_CONF="/dev/null"
      export PQC_BENCH_OPENSSL_CONF="$OPENSSL_CONF"
      log_info "Retrying openssl req with OPENSSL_CONF=/dev/null"
      if ! LD_LIBRARY_PATH="${LIBRARY_PATH:-}" OPENSSL_CONF="$OPENSSL_CONF" "${openssl_cmd[@]}" 2>>"$cert_log"; then
        log_error "Failed to generate certificate with $sig_algo"
        log_error "--- Certificate generation error (last 30 lines) ---"
        tail -30 "$cert_log" >&2
        return 1
      fi
    else
      log_error "Failed to generate certificate with $sig_algo"
      log_error "--- Certificate generation error (last 30 lines) ---"
      tail -30 "$cert_log" >&2
      return 1
    fi
  fi

  # Get certificate DER size for verification
  local cert_der_size
  cert_der_size=$(LD_LIBRARY_PATH="${LIBRARY_PATH:-}" "$OPENSSL" x509 -in "$cert_file" -outform DER 2>/dev/null | wc -c)
  log_info "Certificate DER size: $cert_der_size bytes"

  echo "$cert_der_size"
}

# TLS server/client operations

start_server() {
  local kem_algo="$1"
  local cert_file="$2"
  local key_file="$3"
  local port="$4"
  local server_log="$5"

  log_info "Starting TLS server in namespace $NS_SRV..."

  # Determine provider mode
  local use_provider=1
  if [[ "$USE_NATIVE" == "1" ]] && is_native_kem "$kem_algo"; then
    use_provider=0
  fi

  # Build provider arguments
  local provider_args=()
  if [[ "$use_provider" == "1" ]] && [[ -n "$PROVIDER_PATH" ]]; then
    provider_args=(-provider-path "$PROVIDER_PATH" -provider oqsprovider -provider default)
  elif [[ "$use_provider" == "1" ]]; then
    provider_args=(-provider oqsprovider -provider default)
  fi

  # Build server command
  local server_cmd=("$OPENSSL" s_server)
  if [[ ${#provider_args[@]} -gt 0 ]]; then
    server_cmd+=("${provider_args[@]}")
  fi
  server_cmd+=(
    -accept "$port"
    -cert "$cert_file"
    -key "$key_file"
    -tls1_3
    -groups "$kem_algo"
    -www
  )

  # Start server in namespace
  ip netns exec "$NS_SRV" env LD_LIBRARY_PATH="${LIBRARY_PATH:-}" \
    "${server_cmd[@]}" >"$server_log" 2>&1 &
  SERVER_PID=$!

  # Wait for server to be ready
  local max_attempts=50
  local attempt=0
  while [[ $attempt -lt $max_attempts ]]; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      log_error "Server died unexpectedly"
      tail -30 "$server_log" >&2
      return 1
    fi
    if ip netns exec "$NS_CLI" nc -z "$IP_SRV" "$port" 2>/dev/null; then
      log_debug "Server is ready on port $port"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done

  log_error "Server failed to become ready"
  tail -30 "$server_log" >&2
  return 1
}

run_client_handshakes() {
  local kem_algo="$1"
  local iterations="$2"
  local port="$3"
  local client_log="$4"

  log_info "Running $iterations TLS handshakes..."

  # Determine provider mode
  local use_provider=1
  if [[ "$USE_NATIVE" == "1" ]] && is_native_kem "$kem_algo"; then
    use_provider=0
  fi

  # Build provider arguments
  local provider_args=()
  if [[ "$use_provider" == "1" ]] && [[ -n "$PROVIDER_PATH" ]]; then
    provider_args=(-provider-path "$PROVIDER_PATH" -provider oqsprovider -provider default)
  elif [[ "$use_provider" == "1" ]]; then
    provider_args=(-provider oqsprovider -provider default)
  fi

  local success_count=0
  local fail_count=0
  local first_connection_info=""

  for i in $(seq 1 "$iterations"); do
    local client_cmd=("$OPENSSL" s_client)
    if [[ ${#provider_args[@]} -gt 0 ]]; then
      client_cmd+=("${provider_args[@]}")
    fi
    client_cmd+=(
      -connect "${IP_SRV}:${port}"
      -tls1_3
      -groups "$kem_algo"
    )

    if [[ $i -eq 1 ]]; then
      # Capture first connection info
      local output
      if output=$(ip netns exec "$NS_CLI" env LD_LIBRARY_PATH="${LIBRARY_PATH:-}" \
        "${client_cmd[@]}" </dev/null 2>&1); then
        success_count=$((success_count + 1))
        # Extract connection info
        local protocol cipher temp_key peer_sig
        protocol=$(echo "$output" | grep -oP 'Protocol\s*:\s*\K\S+' | head -1 || true)
        cipher=$(echo "$output" | grep -oP 'Cipher\s*(:|is)\s*\K\S+' | head -1 || true)
        # Extract just the algorithm name (before comma or space with bits)
        temp_key=$(echo "$output" | grep -oP 'Server Temp Key:\s*\K[^,\s]+' | head -1 || true)
        peer_sig=$(echo "$output" | grep -oP 'Peer signature type:\s*\K\S+' | head -1 || true)
        first_connection_info="protocol=${protocol:-unknown} cipher=${cipher:-unknown} group=${temp_key:-unknown} sig=${peer_sig:-unknown}"
        echo "$first_connection_info"
      else
        fail_count=$((fail_count + 1))
        log_debug "Handshake $i failed"
      fi
    else
      # Quick handshake without capturing output
      client_cmd+=(-brief)
      if ip netns exec "$NS_CLI" env LD_LIBRARY_PATH="${LIBRARY_PATH:-}" \
        "${client_cmd[@]}" </dev/null >/dev/null 2>&1; then
        success_count=$((success_count + 1))
      else
        fail_count=$((fail_count + 1))
        log_debug "Handshake $i failed"
      fi
    fi
  done

  log_info "Completed: $success_count/$iterations successful handshakes"
  echo "success=$success_count fail=$fail_count total=$iterations" >>"$client_log"

  if [[ $success_count -eq 0 ]]; then
    return 1
  fi
  return 0
}

# Packet capture

start_capture() {
  local pcap_file="$1"
  local port="$2"

  log_info "Starting packet capture..."

  # Capture on client side (sees both directions)
  ip netns exec "$NS_CLI" tcpdump \
    -i "$VETH_CLI" \
    -w "$pcap_file" \
    -s 0 \
    "tcp port $port" \
    2>/dev/null &
  TCPDUMP_PID=$!

  # Give tcpdump time to start
  sleep 0.5

  if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    log_error "Failed to start tcpdump"
    return 1
  fi

  log_debug "Packet capture started (PID: $TCPDUMP_PID)"
}

stop_capture() {
  if [[ -n "${TCPDUMP_PID:-}" ]] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    # Send SIGTERM to tcpdump
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    log_debug "Packet capture stopped"
  fi
}

# Metadata output

write_metadata() {
  local output_dir="$1"
  local kem_algo="$2"
  local sig_algo="$3"
  local mtu="$4"
  local iterations="$5"
  local cert_der_size="$6"
  local connection_info="$7"
  local pcap_file="$8"

  local metadata_file="$output_dir/metadata.json"

  # Get OpenSSL version
  local openssl_version
  openssl_version=$(LD_LIBRARY_PATH="${LIBRARY_PATH:-}" "$OPENSSL" version 2>/dev/null || echo "unknown")

  # Get kernel version
  local kernel_version
  kernel_version=$(uname -r)

  # Get capture timestamp
  local timestamp
  timestamp=$(date -Iseconds)

  # Parse connection_info (format: "key1=value1 key2=value2 ...")
  # Extract each field safely
  local conn_protocol="" conn_cipher="" conn_group="" conn_sig=""
  local field value
  for pair in $connection_info; do
    field="${pair%%=*}"
    value="${pair#*=}"
    case "$field" in
      protocol) conn_protocol="$value" ;;
      cipher) conn_cipher="$value" ;;
      group) conn_group="$value" ;;
      sig) conn_sig="$value" ;;
    esac
  done

  # Write metadata JSON
  cat >"$metadata_file" <<EOF
{
  "capture_info": {
    "timestamp": "$timestamp",
    "kem_algorithm": "$kem_algo",
    "sig_algorithm": "$sig_algo",
    "mtu": $mtu,
    "iterations": $iterations,
    "cert_der_size_bytes": $cert_der_size,
    "pcap_file": "$(basename "$pcap_file")"
  },
  "connection_info": {
    "protocol": "${conn_protocol:-unknown}",
    "cipher": "${conn_cipher:-unknown}",
    "group": "${conn_group:-unknown}",
    "signature_type": "${conn_sig:-unknown}"
  },
  "environment": {
    "openssl_version": "$openssl_version",
    "kernel_version": "$kernel_version",
    "use_native": $USE_NATIVE,
    "server_ip": "$IP_SRV",
    "client_ip": "$IP_CLI"
  },
  "network_config": {
    "mtu": $mtu,
    "expected_mss_ipv4": $((mtu - 40)),
    "namespace_server": "$NS_SRV",
    "namespace_client": "$NS_CLI"
  }
}
EOF

  log_info "Metadata written to $metadata_file"
}

# Main

main() {
  local kem_algo="X25519"
  local sig_algo="rsa:2048"
  local mtu="$DEFAULT_MTU"
  local iterations="$DEFAULT_ITERATIONS"
  local output_dir=""
  local port="$DEFAULT_PORT"
  local netem_spec=""
  local netem_dir="client"
  local keep_pcap=0

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -k | --kem)
        kem_algo="$2"
        shift 2
        ;;
      -s | --sig)
        sig_algo="$2"
        shift 2
        ;;
      -m | --mtu)
        mtu="$2"
        shift 2
        ;;
      -n | --iterations)
        iterations="$2"
        shift 2
        ;;
      -o | --output-dir)
        output_dir="$2"
        shift 2
        ;;
      -p | --port)
        port="$2"
        shift 2
        ;;
      --netem)
        netem_spec="$2"
        shift 2
        ;;
      --netem-dir)
        netem_dir="$2"
        shift 2
        ;;
      --keep-pcap)
        keep_pcap=1
        shift
        ;;
      -v | --verbose)
        VERBOSE=1
        shift
        ;;
      -h | --help)
        usage
        ;;
      *)
        log_error "Unknown option: $1"
        usage
        ;;
    esac
  done

  # Validate required arguments
  if [[ -z "$output_dir" ]]; then
    log_error "Output directory (-o) is required"
    usage
  fi

  # Check dependencies
  check_dependencies

  # Create output directory
  mkdir -p "$output_dir"
  OUTPUT_DIR="$output_dir"
  if [[ -n "$ORIGINAL_USER" ]] && [[ -d "$output_dir" ]]; then
    if [[ -n "$ORIGINAL_GROUP" ]]; then
      chown "$ORIGINAL_USER:$ORIGINAL_GROUP" "$output_dir" 2>/dev/null || true
    else
      chown "$ORIGINAL_USER" "$output_dir" 2>/dev/null || true
    fi
  fi

  # Create temporary directory
  TEMP_DIR=$(mktemp -d)

  # Define file paths
  local cert_file="$TEMP_DIR/cert.pem"
  local key_file="$TEMP_DIR/key.pem"
  local cert_log="$TEMP_DIR/cert.log"
  local server_log="$TEMP_DIR/server.log"
  local client_log="$TEMP_DIR/client.log"
  local pcap_file="$output_dir/capture_${kem_algo}_${sig_algo//:/}_mtu${mtu}.pcap"

  log_info "=== Packetization Capture ==="
  log_info "KEM: $kem_algo, Sig: $sig_algo, MTU: $mtu, Iterations: $iterations"

  # Generate certificate
  local cert_der_size
  cert_der_size=$(generate_certificate "$sig_algo" "$cert_file" "$key_file" "$cert_log")
  if [[ -z "$cert_der_size" ]]; then
    log_error "Certificate generation failed"
    exit 1
  fi

  # Setup network namespaces
  if [[ "$netem_dir" != "client" && "$netem_dir" != "server" && "$netem_dir" != "both" ]]; then
    log_error "--netem-dir must be one of: client|server|both"
    exit 1
  fi

  if ! setup_network "$mtu" "$netem_spec" "$netem_dir"; then
    log_error "Network setup failed"
    exit 1
  fi

  # Start packet capture
  if ! start_capture "$pcap_file" "$port"; then
    log_error "Packet capture setup failed"
    exit 1
  fi

  # Start TLS server
  if ! start_server "$kem_algo" "$cert_file" "$key_file" "$port" "$server_log"; then
    log_error "TLS server failed to start"
    exit 1
  fi

  # Give a small delay for capture to be fully ready
  sleep 0.2

  # Run client handshakes
  local connection_info
  connection_info=$(run_client_handshakes "$kem_algo" "$iterations" "$port" "$client_log")
  local client_rc=$?

  # Stop capture (give time for last packets)
  sleep 0.5
  stop_capture

  # Stop server
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi

  if [[ $client_rc -ne 0 ]]; then
    log_error "All handshakes failed"
    exit 1
  fi

  # Write metadata
  write_metadata "$output_dir" "$kem_algo" "$sig_algo" "$mtu" "$iterations" \
    "$cert_der_size" "$connection_info" "$pcap_file"

  # Report pcap size
  if [[ -f "$pcap_file" ]]; then
    local pcap_size
    pcap_size=$(stat -c%s "$pcap_file" 2>/dev/null || stat -f%z "$pcap_file" 2>/dev/null || echo "unknown")
    log_info "Capture saved: $pcap_file ($pcap_size bytes)"

    # Output for parsing
    echo "PCAP_FILE: $pcap_file"
    echo "METADATA_FILE: $output_dir/metadata.json"
  else
    log_error "No capture file produced"
    exit 1
  fi

  # Optionally delete pcap after analysis
  if [[ "$keep_pcap" != "1" ]]; then
    log_debug "Pcap will be kept (use analyzer to process, then delete if desired)"
  fi

  log_info "=== Capture complete ==="
  exit 0
}

main "$@"
