#!/usr/bin/env python3
"""Concurrency experiments (laptop): manuscript Figures 3 and 4.

30 records: 2 releases x 3 TLS configurations x c in {1, 10, 50, 100, 200}.
Each: 100 sequential warm-ups, then 1,000 measured requests submitted to a
ThreadPoolExecutor(max_workers=c); one new s_client process and TLS connection
per request. RPS = successful measured requests / wall-clock duration of the
measured batch. p99 over successful requests; within-run order-statistic CI.
"""
from common import BRANCHES, load, quantile, quantile_ci, rel, ttfb_ms, write_csv

MODES = {"classical": "X25519", "hybrid": "X25519MLKEM768", "fullpqc": "mlkem768"}


def main():
    rows, data = [], {}
    for v in ("3.4.1", "3.5.0"):
        for c in (1, 10, 50, 100, 200):
            for mode, group in MODES.items():
                [p] = list(BRANCHES[("laptop", v)].glob(f"*-capacity-http-{mode}_c{c}.json"))
                doc = load(p)
                m = doc["metadata"]
                assert m["samples"] == 1000 and m["warm_up"] == 100 and m["concurrency"] == c
                assert m["success_count"] == 1000 and m["fail_count"] == 0 and m["groups"] == group
                t = ttfb_ms(doc)
                lo, hi, _ = quantile_ci(t, 0.99)
                rps = m["measured_requests_per_sec"]
                assert abs(rps - m["success_count"] / m["measured_duration_s"]) < 1e-8
                data[(v, c, mode)] = (rps, quantile(t, 0.99))
                rows.append([v, c, mode, rps, m["measured_duration_s"], quantile(t, 0.5), quantile(t, 0.99), lo, hi,
                             (doc.get("tls") or {}).get("signature_type"), rel(p)])
    write_csv("capacity_concurrency.csv",
              ["openssl", "concurrency", "tls_config", "rps", "measured_duration_s", "p50_ms", "p99_ms",
               "p99_ci95_low_ms", "p99_ci95_high_ms", "recorded_signature_type", "file"], rows)
    gains = [100 * (data[("3.5.0", c, k)][0] / data[("3.4.1", c, k)][0] - 1) for c in (50, 100, 200) for k in MODES]
    tails = [100 * (data[("3.5.0", c, k)][1] / data[("3.4.1", c, k)][1] - 1) for c in (50, 100, 200) for k in MODES]
    print(f"c=50-200: RPS change {min(gains):+.1f}% to {max(gains):+.1f}%; p99 change {min(tails):+.1f}% to {max(tails):+.1f}%")
    for k in MODES:
        a, b = data[("3.4.1", 50, k)], data[("3.5.0", 50, k)]
        print(f"c=50 {k:9} RPS {a[0]:.1f} -> {b[0]:.1f}; p99 {a[1]:.1f} -> {b[1]:.1f} ms")
    durs = [r[4] for r in rows if r[1] == 200]
    print(f"c=200 measured batch duration: {min(durs):.1f}-{max(durs):.1f} s")


if __name__ == "__main__":
    main()
