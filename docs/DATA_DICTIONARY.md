# Data dictionary

## Directory layout

| Directory | Host | OpenSSL |
|---|---|---|
| `data/raw/openssl-3.4.1/` | laptop (Intel Core i5-10300H) | 3.4.1 + oqs-provider 0.11.0-rc1 |
| `data/raw/openssl-3.5.0/` | laptop | 3.5.0 |
| `data/raw/lab-server/openssl-3.4.1/` | lab server (Intel Core Ultra 9 285) | 3.4.1 + oqs-provider 0.11.0-rc1 |
| `data/raw/lab-server/openssl-3.5.0/` | lab server | 3.5.0 |
| `data/raw/unsupported*/` | both | records of groups that produced no successful request (not used) |

File names start with the run ID assigned by `run-benchmarks.sh`.

| File pattern | Content | Used in the article |
|---|---|---|
| `01`–`17-*.json` | `openssl speed` micro-benchmarks (KEMs, signatures, hybrids; `*-native.json` variants in 3.5.0) and TLS handshake summaries (`tls_details`) | `04-hybrid-mlkem.json` (Table 4) |
| `18-http-openssl-hybrid.json` | HTTP, X25519MLKEM768 + RSA-PSS (Run A) | Tables 2–5 |
| `19-http-openssl-hybrid-session.json` | same, with session reuse | session-reuse comparison |
| `20-http-openssl-classical.json` | HTTP, X25519 + RSA-PSS | Tables 2, 5 |
| `21-http-playwright-chromium.json` | browser client (not comparable) | no |
| `22`–`33-http-openssl-pqc-*.json` | HTTP, pure PQC KEM + RSA-PSS | `23-…mlkem768.json` (Table 5) |
| `34`–`36-http-openssl-fullpqc-*.json` | HTTP, ML-KEM + ML-DSA | `35-…mlkem768-mldsa65.json` (Tables 2, 5) |
| `37`–`41-http-native-*.json` (3.5.0 only) | HTTP, natively labelled runs | `37-…x25519mlkem768.json` (Run B, Table 3), `38-…-session.json` |
| `42-packetization.json`, `packetization/<scenario>_mtu<M>/` | packetization summaries (OpenSSL 3.5.0) | Figure 2, Table 6 |
| `50`–`229-netem-http-<cfg>_mtu<M>_rtt<R>_loss<L>.json` | network-impairment HTTP runs; `loss0p5` = 0.5 % | Figure 1; Tables S1–S2 |
| second `netem-http-classical_…` record of a profile (lab server, 3.4.1; run IDs 184–236) | 47 later records repeating a nominal profile; the lower run ID is canonical | Table S3 |
| `netem-pcaps/` | per-condition capture summaries of separate 5-connection runs | no |
| `60`–`74-capacity-http-<cfg>_c<C>.json` (laptop) | concurrency runs | Figures 3–4 |
| `netem-run*.log`, `netem-exit-code.txt` | run logs | no |

Configuration labels: `classical` = X25519 + RSA-PSS; `hybrid` = X25519MLKEM768 + RSA-PSS; `fullpqc` = ML-KEM-768 + ML-DSA-65. Packetization scenarios: `baseline` (X25519 + RSA), `hybrid-kem` (X25519MLKEM768 + RSA), `pqc-kem` (ML-KEM-768 + RSA), `pqc-cert` (X25519 + ML-DSA-65), `full-pqc` (ML-KEM-768 + ML-DSA-65).

## HTTP record fields

| Field | Meaning |
|---|---|
| `metadata.samples`, `warm_up`, `timeout_s` | measured requests, discarded warm-ups, per-request timeout (s) |
| `metadata.success_count`, `fail_count` | successful requests (HTTP 2xx/3xx) and failures (timeout or error) |
| `metadata.reuse` | `none` or `session` (`-sess_in`/`-sess_out`) |
| `metadata.concurrency` | maximum worker count c |
| `metadata.groups` | TLS group requested with `-groups` |
| `metadata.context.netem` | `mtu`, `rtt_ms`, `loss_pct`, `netem_dir` (always `both`) |
| `metadata.measured_duration_s`, `measured_requests_per_sec` | wall-clock duration of the measured batch, and successes divided by it |
| `environment.*` | OpenSSL and oqs-provider versions, CPU model, kernel |
| `tls.*` | protocol, cipher, key exchange, signature type from one probe connection (see `MEASUREMENT_DEFINITIONS.md`) |
| `metrics.ttfb_us`, `metrics.total_us` | summary statistics (µs) over successful requests: median, p95, p99, p999, min, max, mean, stdev, count, timings |
| `samples[]` | per request: `ok`, `status`, `ttfb_us`, `total_us`, `error`; `dns_us`/`tcp_us`/`tls_us` are null for the OpenSSL client |

## Packetization fields (`analysis.json`)

`connections[]` → `client_to_server` / `server_to_client`: `segment_count`, `segments_with_payload`, `total_payload_bytes`, `mss`, `tls_records[]` (`content_type`, `length` without the 5-byte header, `segments_spanned`). `retransmissions` and `out_of_order` are placeholders (always 0). `metadata.json` holds the KEM, signature algorithm, MTU, certificate DER size and OpenSSL version.
