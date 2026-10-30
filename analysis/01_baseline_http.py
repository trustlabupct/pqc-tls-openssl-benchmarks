#!/usr/bin/env python3
"""Baseline (loopback) HTTP TTFB: manuscript Tables 2-3, matched configurations,
session-reuse runs, and within-run bootstrap confidence intervals.

Each archived run contains 20 measured requests (2 warm-ups discarded).
Confidence intervals are percentile bootstrap intervals over the requests of
each run (10,000 resamples, fixed seed). They describe within-run sampling
uncertainty only; they are not between-run (replication) intervals.
"""
from common import (HOSTS, VERSIONS, bootstrap_ci, http_file, load, median,
                    rel, ttfb_ms, write_csv)

CONFIGS = {
    # name: (file stem, key establishment, authentication)
    "classical": ("http-openssl-classical", "X25519", "RSA-PSS (RSA-2048)"),
    "hybrid": ("http-openssl-hybrid", "X25519MLKEM768", "RSA-PSS (RSA-2048)"),
    "mlkem768_rsa": ("http-openssl-pqc-mlkem768", "ML-KEM-768", "RSA-PSS (RSA-2048)"),
    "fullpqc": ("http-openssl-fullpqc-mlkem768-mldsa65", "ML-KEM-768", "ML-DSA-65"),
}


def run(host, version, stem):
    path = http_file(host, version, stem)
    doc = load(path)
    t = ttfb_ms(doc)
    m = doc["metadata"]
    assert len(t) == m["samples"] == m["success_count"] == 20 and m["fail_count"] == 0
    assert abs(median(t) - doc["metrics"]["ttfb_us"]["median_us"] / 1000) < 1e-9
    return path, doc, t


def pct_diff(a, b):
    return 100 * (median(b) / median(a) - 1)


def main():
    rows_cfg, rows_t2, rows_eff, rows_t3, rows_sess = [], [], [], [], []
    for host in HOSTS:
        for version in VERSIONS:
            data = {}
            for name, (stem, kex, auth) in CONFIGS.items():
                path, doc, t = run(host, version, stem)
                lo, hi = bootstrap_ci(median, [t])
                tls = doc.get("tls") or {}
                rows_cfg.append([host, version, name, kex, auth, rel(path), len(t), median(t), lo, hi,
                                 tls.get("key_exchange"), tls.get("signature_type"), tls.get("cipher"),
                                 doc["metadata"].get("reuse")])
                data[name] = t
            c, h = data["classical"], data["hybrid"]
            lo, hi = bootstrap_ci(pct_diff, [c, h])
            rows_t2.append([host, version, median(c), median(h), pct_diff(c, h), lo, hi, median(data["fullpqc"])])
            # Matched comparisons available in the archive.
            for label, a, b in [
                ("key establishment X25519 -> X25519MLKEM768 (RSA-PSS fixed)", "classical", "hybrid"),
                ("key establishment X25519 -> ML-KEM-768 (RSA-PSS fixed)", "classical", "mlkem768_rsa"),
                ("authentication RSA-PSS -> ML-DSA-65 (ML-KEM-768 fixed)", "mlkem768_rsa", "fullpqc"),
                ("both changed: classical -> full PQC", "classical", "fullpqc"),
            ]:
                ta, tb = data[a], data[b]
                d = median(tb) - median(ta)
                lo, hi = bootstrap_ci(lambda x, y: median(y) - median(x), [ta, tb])
                rows_eff.append([host, version, label, median(ta), median(tb), d, lo, hi, pct_diff(ta, tb)])
            # Session-reuse runs (-sess_out / -sess_in). Resumption per request is not recorded.
            pairs = [("http-openssl-hybrid", "http-openssl-hybrid-session")]
            if version == "3.5.0":
                pairs.append(("http-native-x25519mlkem768", "http-native-x25519mlkem768-session"))
            for a_stem, b_stem in pairs:
                pa, _, ta = run(host, version, a_stem)
                pb, db, tb = run(host, version, b_stem)
                assert db["metadata"]["reuse"] == "session"
                lo, hi = bootstrap_ci(lambda x, y: median(y) - median(x), [ta, tb])
                rows_sess.append([host, version, rel(pa), rel(pb), median(ta), median(tb),
                                  median(tb) - median(ta), lo, hi, pct_diff(ta, tb)])
        # Table 3: the two OpenSSL 3.5.0 X25519MLKEM768 runs.
        pa, _, ta = run(host, "3.5.0", "http-openssl-hybrid")
        pb, _, tb = run(host, "3.5.0", "http-native-x25519mlkem768")
        lo, hi = bootstrap_ci(lambda x, y: median(y) - median(x), [ta, tb])
        plo, phi = bootstrap_ci(pct_diff, [ta, tb])
        rows_t3.append([host, rel(pa), rel(pb), median(ta), median(tb), median(tb) - median(ta), lo, hi,
                        pct_diff(ta, tb), plo, phi])

    write_csv("baseline_http_runs.csv",
              ["host", "openssl", "config", "key_establishment", "authentication", "file", "n",
               "median_ttfb_ms", "ci95_low_ms", "ci95_high_ms", "recorded_key_exchange",
               "recorded_signature_type", "recorded_cipher", "reuse"], rows_cfg)
    write_csv("table2_cross_version.csv",
              ["host", "openssl", "classical_median_ms", "hybrid_median_ms", "hybrid_overhead_pct",
               "overhead_ci95_low_pct", "overhead_ci95_high_pct", "fullpqc_median_ms"], rows_t2)
    write_csv("table5_matched_configurations.csv",
              ["host", "openssl", "comparison", "median_a_ms", "median_b_ms", "diff_ms",
               "diff_ci95_low_ms", "diff_ci95_high_ms", "diff_pct"], rows_eff)
    write_csv("table3_runA_runB.csv",
              ["host", "run_a", "run_b", "run_a_median_ms", "run_b_median_ms", "diff_ms",
               "diff_ci95_low_ms", "diff_ci95_high_ms", "diff_pct", "diff_ci95_low_pct",
               "diff_ci95_high_pct"], rows_t3)
    write_csv("session_reuse_runs.csv",
              ["host", "openssl", "no_reuse_file", "session_reuse_file", "no_reuse_median_ms",
               "session_reuse_median_ms", "diff_ms", "diff_ci95_low_ms", "diff_ci95_high_ms",
               "diff_pct"], rows_sess)

    print("Table 2 (median TTFB, ms; hybrid overhead with within-run 95% bootstrap CI)")
    for r in rows_t2:
        print(f"  {r[0]:10} {r[1]}  classical {r[2]:7.3f}  hybrid {r[3]:7.3f}  "
              f"overhead {r[4]:+6.2f}% [{r[5]:+6.2f}, {r[6]:+6.2f}]  full PQC {r[7]:7.3f}")
    print("Table 3 (Run A vs Run B)")
    for r in rows_t3:
        print(f"  {r[0]:10} A {r[3]:.3f}  B {r[4]:.3f}  diff {r[5]:+.3f} ms [{r[6]:+.3f}, {r[7]:+.3f}]  "
              f"{r[8]:+.2f}% [{r[9]:+.2f}, {r[10]:+.2f}]")
    print("Matched-configuration differences (ms, within-run 95% bootstrap CI)")
    for r in rows_eff:
        print(f"  {r[0]:10} {r[1]}  {r[2]:62} {r[3]:7.3f} -> {r[4]:7.3f}  {r[5]:+7.3f} [{r[6]:+7.3f}, {r[7]:+7.3f}]  {r[8]:+6.1f}%")
    print("Session-reuse runs")
    for r in rows_sess:
        print(f"  {r[0]:10} {r[1]}  {r[4]:7.3f} -> {r[5]:7.3f}  {r[6]:+.3f} ms [{r[7]:+.3f}, {r[8]:+.3f}]  {r[9]:+.1f}%")


if __name__ == "__main__":
    main()
