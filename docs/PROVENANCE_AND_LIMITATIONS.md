# Provenance and limitations

## Origin of the data

The measurements were recorded between 15 and 23 December 2025 on two Linux x86-64 hosts (kernel 6.14.0-37-generic): a laptop (Intel Core i5-10300H) and a lab server (Intel Core Ultra 9 285), with OpenSSL 3.4.1 + oqs-provider and OpenSSL 3.5.0. Each record stores its generation time, tool version (`pqc-bench` 0.1.2), OpenSSL version, oqs-provider version, CPU model and kernel.

`data/raw/` reproduces the original results archive file for file (2,424 files, SHA-256 of the archive `69c0b2c5f7c4f39ca687ce1de5d16bdfb95f7b98e295125f6251aadc55d83728`). Backup copies of partial lab-server runs were excluded. `data/SHA256SUMS` lists every file; `analysis/run_all.py` verifies it before any computation.

The benchmark source in `src/` is version 0.1.2, the version written into every record. The exact source commit, compiler options and build configuration of the OpenSSL and liboqs installations used for the original runs were not recorded, and the original hosts are no longer available.

## Known issues in the archive and how the analysis handles them

| Issue | Handling |
|---|---|
| The records identify the requested group and the loaded provider, but not which provider implemented the algorithm. With OpenSSL ≥ 3.5, oqs-provider does not register algorithms that OpenSSL provides natively, including X25519MLKEM768. | The two OpenSSL 3.5.0 X25519MLKEM768 runs (`18-…hybrid.json`, `37-http-native-x25519mlkem768.json`) are treated as two runs of the same nominal configuration. See `POST_HOC_PROVIDER_CHECK.md`. |
| `tls.key_exchange` falls back to the requested group when the probe connection does not print it. | Not used as evidence of negotiation. |
| Packetization summaries exist in four directories. Those under `lab-server/` are byte-identical copies of the laptop-directory files; those under `openssl-3.4.1/` are a second capture session that was also run with the OpenSSL 3.5.0 binary (64 files declare 3.5.0 in a 3.4.1 directory). | Only `openssl-3.5.0/packetization/` is analysed; the second session gives identical qualifying segment counts and TLS records (`results/packetization_copies.csv`). Packetization results are reported for OpenSSL 3.5.0 only. |
| Seven connections per packetization capture include one empty and one alert-only connection. | The five test connections are used. |
| `retransmissions` / `out_of_order` are always 0 (not populated by the parser). The binary `.pcap` files were not retained. | Not interpreted. Retransmission behaviour is inferred only indirectly, from the timing of delayed requests (`04_tail_events.py`). |
| `netem-pcaps/` contains per-condition capture summaries of separate 5-iteration runs, not of the measured HTTP requests. | Not used. |
| 47 netem records for lab server / OpenSSL 3.4.1 / classical repeat a nominal profile with a later run ID. | The lowest run ID is canonical. The later records are compared with the canonical ones in Table S3 as evidence of run-to-run variability. |
| Additional records (other KEMs and signatures, a browser client, `unsupported*/` directories) are not used in the article. | Kept for completeness. |

## Limits of what the data can show

* Most experimental conditions were recorded once. The confidence intervals in `results/` are within-run intervals and do not cover between-run variability. Table S3 shows that this variability can be large for p99 under loss.
* TTFB is an end-to-end metric of a CLI-based workload (new client process and TLS connection per request). Process start-up, TCP, TLS and response phases were not time-stamped.
* Cross-release comparisons change the OpenSSL release and the PQC integration mechanism together and cannot attribute differences to either.
* Concurrency results describe a co-located client–server workload, not server capacity.
