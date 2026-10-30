# PQC Benchmarks

Benchmark Post-Quantum Cryptography algorithms with OpenSSL 3.x and oqs-provider.

**Version**: 0.1.2

This suite includes:

- **Crypto microbenchmarks** (`pqc-bench run`): `openssl speed` sampling with median/p95/p99
- **TLS handshake microbenchmarks** (`pqc-bench run --include-tls`): `s_server/s_client` handshakes
- **HTTP/web benchmarks** (`pqc-bench http`): end-to-end TTFB/total request timings (OpenSSL or browser)

## Platform Support

**Linux only**. Reproducibility checks and CPU pinning use these Linux interfaces:
- `/proc/cpuinfo`, `/sys/devices/system/cpu/` for CPU info
- `taskset` for CPU pinning
- `perf stat` for hardware performance counters
- `systemd-detect-virt` for VM detection

Core OpenSSL speed benchmarks work on any platform with OpenSSL 3.x and oqs-provider. Reproducibility warnings and `--pin-cpu` require Linux.

## Requirements

- **Linux** (see above)
- OpenSSL 3.x (3.4+ recommended, 3.5+ for native PQC comparison)
- oqs-provider (version auto-detected, tested with >= 0.6.0)
- Python 3.11+
- Bash 4.0+

### Optional: OpenSSL 3.5+ for Native PQC

OpenSSL 3.5+ includes native ML-KEM and ML-DSA implementations (FIPS 203/204). Install it alongside system OpenSSL to compare the native implementation with oqs-provider:

```bash
# Check if you have OpenSSL 3.5 available
/opt/openssl-3.5/bin/openssl version
# OpenSSL 3.5.0 8 Apr 2025

# Run comparison benchmarks
./run-benchmarks.sh --compare
```

**Native algorithms in OpenSSL 3.5+** (no oqs-provider needed):
- **KEMs**: mlkem512, mlkem768, mlkem1024, X25519MLKEM768, X448MLKEM1024, SecP256r1MLKEM768, SecP384r1MLKEM1024
- **Signatures**: mldsa44, mldsa65, mldsa87, SLH-DSA-SHA2-*, SLH-DSA-SHAKE-*

In OpenSSL 3.5.0, `openssl speed` supports native ML-KEM algorithms. Native ML-DSA and SLH-DSA support key generation and signing, but `speed` returns "operation not supported". Native benchmarks are limited to KEMs.

## Install

```bash
pip install -e .
```

## Verify Setup

```bash
pqc-bench check
```

Example output:
```
Checking system dependencies...

Dependency Check Results
========================================
OpenSSL version:      3.4.1 ✓
oqs-provider version: 0.10.1-dev ✓
perf available:       yes (optional)

All required dependencies satisfied.
```

## Benchmark Methodology

Statistics are computed from **multiple independent samples**:

1. **Warm-up runs** (default 2) - discarded to stabilize CPU caches
2. **Sample runs** (default 10) - each runs `openssl speed` for a fixed duration
3. **Percentiles computed** across samples using `stats.py`

Median, p95, and p99 use the independent samples.

### Reproducibility Controls

The tool warns about conditions that may affect benchmark reproducibility:

```
Reproducibility warnings:
  [cpu_governor] CPU governor is 'powersave', not 'performance'
  [cpu_frequency] CPU frequency scaling enabled (800-4500 MHz)
  [virtualization] Running in virtualized environment (kvm)
```

Use `--no-warnings` to suppress these messages, or `--pin-cpu N` to pin benchmarks to a specific CPU core.

## Usage

### List Algorithms

```bash
pqc-bench list                    # all 90 algorithms
pqc-bench list -t kem             # KEMs only
pqc-bench list -t sig             # signatures only
pqc-bench list --hybrids-only     # hybrid algorithms
pqc-bench list --include-experimental
```

### Run Benchmarks

```bash
# specific algorithms (case-insensitive, aliases supported)
pqc-bench run mlkem768 mldsa65
pqc-bench run ML-KEM-768 ML-DSA-65  # also works

# all KEMs
pqc-bench run -t kem

# all signatures
pqc-bench run -t sig

# with options
pqc-bench run mlkem768 -n 20 --warm-up 3 --seconds 5

# include TLS handshake timing
pqc-bench run mlkem768 --include-tls

# output formats
pqc-bench run mlkem768 -f json -o results.json
pqc-bench run mlkem768 -f csv -o results.csv

# reproducibility options
pqc-bench run mlkem768 --pin-cpu 0       # pin to CPU 0
pqc-bench run mlkem768 --no-warnings     # suppress warnings
```

#### Native OpenSSL 3.5+ Mode

Compare oqs-provider against native OpenSSL 3.5+ implementations:

```bash
# Run with native OpenSSL 3.5 (requires 3.5+ installed)
pqc-bench run mlkem768 mldsa65 --use-native \
  --openssl-path /opt/openssl-3.5/bin/openssl \
  --library-path /opt/openssl-3.5/lib64

# Or set environment variables
export PQC_BENCH_OPENSSL=/opt/openssl-3.5/bin/openssl
export PQC_BENCH_LD_LIBRARY_PATH=/opt/openssl-3.5/lib64
pqc-bench run mlkem768 --use-native
```

### HTTP / Web Benchmarks

Measure end-to-end HTTPS request timings (TTFB and total time).

```bash
# OpenSSL client (controlled, reproducible)
pqc-bench http --url https://host/small --client openssl --groups X25519MLKEM768 -n 50 --warm-up 5

# TLS resumption across new TCP connections (OpenSSL only)
pqc-bench http --url https://host/small --client openssl --reuse session -n 50

# Attach extra experiment metadata (embedded in JSON under `metadata.context`)
pqc-bench http --url https://host/small --client openssl --groups X25519MLKEM768 \
  --meta label=netem --meta-json '{"netem":{"mtu":1500,"rtt_ms":50,"loss_pct":0.5}}' -n 1000 --warm-up 100

# Browser client (Playwright)
pip install -e \".[web]\"
pqc-bench http --url https://host/page --client playwright --browser chromium --reuse context -n 20

# Use a system-installed Chromium/Chrome binary (avoids `playwright install`)
pqc-bench http --url https://host/page --client playwright \\
  --browser chromium --browser-executable /usr/bin/google-chrome --reuse context -n 20
```

Notes:

- `pqc-bench http` currently supports **`https://` URLs only**.
- OpenSSL mode uses `openssl s_client` and sends a minimal HTTP/1.1 `GET` with `Connection: close`.
- Playwright mode derives timings from the browser's Navigation Timing API. In JSON output, `ttfb_us`/`total_us` start at `requestStart` (excludes DNS/TCP/TLS); use `ttfb_e2e_us`/`total_e2e_us` for end-to-end timings (start=`fetchStart`).
- Negotiated TLS parameters are best-effort; for browsers, prefer server-side logging for cipher/group.

### Full Suite Script

`run-benchmarks.sh` runs the full 17-batch suite and writes JSON outputs to `./results/` by default.

```bash
# crypto + TLS (17 batches)
./run-benchmarks.sh

# compare oqs-provider vs native OpenSSL 3.5 for ML-KEM/ML-DSA
# (requires OpenSSL 3.5+ at /opt/openssl-3.5 or set PQC_BENCH_NATIVE_OPENSSL)
./run-benchmarks.sh --compare

# also run HTTP benchmarks (OpenSSL + optional Playwright)
PQC_BENCH_HTTP_URL=https://host/small ./run-benchmarks.sh

# quick local smoke test for the HTTP layer (auto-starts a local `openssl s_server`)
PQC_BENCH_HTTP_LOCAL=1 ./run-benchmarks.sh

# Network impairment sweeps (post-17, opt-in; requires root + iproute2)
# Produces `50-netem-http-*.json` files in the results directory.
sudo PQC_BENCH_NETEM_SWEEP=1 PQC_BENCH_NETEM_MTU="1500" PQC_BENCH_NETEM_RTT_MS="0 50" \
  PQC_BENCH_NETEM_LOSS_PCT="0 0.5 1" PQC_BENCH_NETEM_SAMPLES=1000 PQC_BENCH_NETEM_WARMUP=100 \
  ./run-benchmarks.sh --http-only

# Optional: capture handshake PCAPs + attach packetization summary to each netem JSON
# (requires tcpdump + ethtool, and writes `results/*/netem-pcaps/*/analysis.json`)
sudo PQC_BENCH_NETEM_SWEEP=1 PQC_BENCH_NETEM_PCAP=1 PQC_BENCH_NETEM_PCAP_ITERATIONS=10 \
  ./run-benchmarks.sh --http-only

# Capacity / concurrency sweeps (post-17, opt-in)
# Produces `60-capacity-http-*.json` files (uses local OpenSSL s_server).
PQC_BENCH_CAPACITY=1 PQC_BENCH_CAPACITY_CONCURRENCY="1 10 50 100" ./run-benchmarks.sh --http-only

# perf profiling helper (client-side)
# Produces `perf.data` + `perf.report.txt` + the HTTP JSON for a chosen scenario.
./src/scripts/perf_http_profile.sh --scenario hybrid --samples 2000 --out-dir ./perf-hybrid

# customize output directory
PQC_BENCH_RESULTS_DIR=results-$(date +%F) ./run-benchmarks.sh
```

The `--compare` mode runs ML-KEM algorithms twice:

1. First with oqs-provider (saves to `01-mlkem.json`)
2. Then with native OpenSSL 3.5 (saves to `01-mlkem-native.json`)

Compare these files to measure implementation performance. ML-DSA comparison is unavailable because OpenSSL 3.5's `speed` command does not support signature benchmarks.

### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --samples` | 10 | Number of repeated benchmark runs for statistics |
| `--warm-up` | 2 | Number of warm-up runs (discarded) |
| `--seconds` | 3 | Duration of each openssl speed run |
| `--timeout` | 300 | Timeout per algorithm in seconds |
| `--include-tls` | off | Include TLS handshake benchmarks |
| `--include-perf` | off | Include CPU cycle counts (requires perf) |
| `--pin-cpu` | none | Pin benchmark to specific CPU core (requires taskset) |
| `--no-warnings` | off | Suppress reproducibility warnings |
| `--openssl-path` | env/default | Path to OpenSSL binary |
| `--library-path` | env/default | LD_LIBRARY_PATH for OpenSSL |
| `--use-native` | off | Use native OpenSSL 3.5+ PQC (skip oqs-provider) |
| `-f, --format` | text | Output format: text, json, csv |
| `-o, --output` | stdout | Output file path |

### Reports

```bash
pqc-bench report results.json --summary
pqc-bench report new.json --compare baseline.json
```

PDF report (Alcázar template):

```bash
python3 report/generate_pqc_report.py --build
```

## Output

All benchmarks report:

- **Latency**: median, p95, p99, stdev (microseconds) - computed across samples
- **Throughput**: ops/sec (derived from median)
- **Sizes**: public key, secret key, ciphertext/signature (bytes)
- **Sample count**: number of benchmark runs used for statistics
- **Raw timings**: individual sample timings for reproducibility (JSON only)

Example text output:
```
PQC Benchmark Results
============================================================
Environment: OpenSSL 3.4.1, oqs-provider 0.10.1-dev, Linux x86_64
CPU: Intel(R) Core(TM) i5-10300H CPU @ 2.50GHz
Samples per algorithm: 10

Algorithm: mlkem768 (KEM)
  keygen         15.4 us (median),     15.6 us (p95),     15.6 us (p99), stdev=0.2
  encaps         13.9 us (median),     14.1 us (p95),     14.1 us (p99), stdev=0.2
  decaps         16.5 us (median),     16.6 us (p95),     16.6 us (p99), stdev=0.2
  Sizes: pk=1184B, sk=2400B, ct=1088B

Algorithm: mldsa65 (Signature)
  keygen         49.5 us (median),     50.1 us (p95),     50.1 us (p99), stdev=0.9
  sign          117.2 us (median),    118.0 us (p95),    118.0 us (p99), stdev=1.2
  verify         44.4 us (median),     44.6 us (p95),     44.7 us (p99), stdev=0.4
  Sizes: pk=1952B, sk=4032B, sig=3309B

Summary: 2 algorithms benchmarked, 0 failed
```

### JSON Output Features

```json
{
  "results": [{
    "algorithm": "mlkem768",
    "operations": {
      "keygen": {
        "median_us": 15.4,
        "p95_us": 15.6,
        "p99_us": 15.6,
        "stdev_us": 0.2,
        "timings_us": [15.2, 15.3, 15.4, 15.5, 15.6]
      }
    },
    "sizes": {
      "public_key_bytes": 1184,
      "secret_key_bytes": 2400,
      "ciphertext_bytes": 1088,
      "source": "fallback"
    }
  }]
}
```

- `timings_us`: Raw sample timings for auditing/reproducibility
- `sizes.source`: Indicates if sizes are `"fallback"` (hardcoded) or `"measured"`

## Algorithms

| Type | Pure PQC | Hybrid | Total |
|------|----------|--------|-------|
| KEM | 12 | 23 | 35 |
| Signature | 15 | 40 | 55 |

**KEMs**: ML-KEM (512/768/1024), FrodoKEM, BIKE + X25519/P256/P384/P521 hybrids

**Signatures**: ML-DSA, Falcon, SPHINCS+, Mayo + P256/P384/P521/RSA3072 hybrids

**Experimental**: CROSS, OV, SNOVA (use `--include-experimental`)

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PQC_BENCH_OPENSSL` | Path to OpenSSL binary |
| `PQC_BENCH_PROVIDER_PATH` | Path to oqs-provider module |
| `PQC_BENCH_LD_LIBRARY_PATH` | LD_LIBRARY_PATH for OpenSSL (for custom builds) |
| `PQC_BENCH_USE_NATIVE` | Set to `1` to use native OpenSSL 3.5+ PQC |
| `PQC_BENCH_NATIVE_OPENSSL` | Path to OpenSSL 3.5+ binary for `--compare` mode |
| `PQC_BENCH_NATIVE_LD_LIBRARY_PATH` | LD_LIBRARY_PATH for OpenSSL 3.5+ |
| `PQC_BENCH_BROWSER_EXECUTABLE` | Playwright browser executable path (optional) |

These affect both dependency checking and benchmark execution consistently.

## Examples

```bash
# quick benchmark with 5 samples
pqc-bench run mlkem768 mldsa65 -n 5

# high-precision: 20 samples, 5s each, with CPU metrics
pqc-bench run mlkem768 -n 20 --seconds 5 --include-perf

# compare pure vs hybrid
pqc-bench run mlkem768 X25519MLKEM768 -f json -o comparison.json

# full KEM suite to CSV
pqc-bench run -t kem -f csv -o kem_results.csv

# use custom OpenSSL build
PQC_BENCH_OPENSSL=/opt/openssl/bin/openssl pqc-bench run mlkem768

# reproducible benchmark pinned to CPU 0
pqc-bench run mlkem768 --pin-cpu 0 -n 20 --no-warnings
```

## Exit Codes

- 0: success
- 1: partial failure (some algorithms failed)
- 2: complete failure (no algorithms completed)
- 3: dependency error (OpenSSL/oqs-provider missing)

For `pqc-bench http`:

- 0: all samples succeeded
- 1: one or more samples failed

## Parser Support

The parser supports these OpenSSL output formats:

1. **Machine-readable** (`-mr` flag): `+DTP`/`+R` lines from oqs-provider
2. **Detailed output**: "N algorithm operation ops in X.XXs"
3. **Summary table**: Fallback for older outputs

Algorithm names are normalized to lowercase snake_case internally, with aliases for common variations (e.g., `ML-KEM-768` → `mlkem768`).
