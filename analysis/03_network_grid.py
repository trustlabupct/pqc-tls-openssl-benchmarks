#!/usr/bin/env python3
"""Complete network-impairment grid (Supplementary Table S1) and Figure 1 data.

720 canonical profiles = 2 hosts x 2 OpenSSL releases x 3 TLS configurations
x 3 MTUs x 4 RTTs x 5 loss rates; 1,000 measured requests each (100 warm-ups).
Percentiles are computed over successful requests only; timeouts (5 s) are
counted as failures. p99 confidence intervals are within-run, distribution-free
order-statistic intervals (ranks 983 and 997 of 1,000; coverage 97.6%).

Also compares the 47 later records that repeat a canonical nominal profile
(lab server, OpenSSL 3.4.1, classical) with their canonical counterparts.
"""
from common import (load, median, n_failed, netem_profiles, quantile, rel,
                    quantile_ci, ttfb_ms, write_csv)


def p99(x):
    return quantile(x, 0.99)


def main():
    prof = netem_profiles()
    assert len(prof) == 720, len(prof)
    rows, fig1 = [], []
    total_req = total_fail = 0
    max_fail = 0
    for key in sorted(prof):
        host, version, cfg, mtu, rtt, loss = key
        path = prof[key]["canonical"]
        doc = load(path)
        m = doc["metadata"]
        net = m["context"]["netem"]
        assert (net["mtu"], net["rtt_ms"], net["loss_pct"], net["netem_dir"]) == (mtu, rtt, loss, "both")
        assert m["samples"] == 1000 and m["warm_up"] == 100 and m["timeout_s"] == 5
        assert doc["environment"]["openssl_version"] == version
        t = ttfb_ms(doc)
        f = n_failed(doc)
        assert len(t) + f == 1000 and f == m["fail_count"]
        rec = doc["metrics"]["ttfb_us"]
        assert abs(quantile(t, 0.99) - rec["p99_us"] / 1000) < 1e-6
        lo, hi, _ = quantile_ci(t, 0.99)
        tls = doc.get("tls") or {}
        rows.append([host, version, cfg, mtu, rtt, loss, len(t), f, median(t), quantile(t, 0.95),
                     quantile(t, 0.99), lo, hi, tls.get("key_exchange"), tls.get("signature_type"),
                     rel(path)])
        total_req += 1000
        total_fail += f
        max_fail = max(max_fail, f)
        if rtt == 50 and mtu == 1500:
            fig1.append(rows[-1])
    write_csv("S1_network_grid_720_profiles.csv",
              ["host", "openssl", "tls_config", "mtu", "rtt_ms", "loss_pct", "successes", "failures",
               "p50_ms", "p95_ms", "p99_ms", "p99_ci95_low_ms", "p99_ci95_high_ms",
               "recorded_key_exchange", "recorded_signature_type", "file"], rows)
    write_csv("figure1_rtt50_mtu1500_all_loss_levels.csv",
              ["host", "openssl", "tls_config", "mtu", "rtt_ms", "loss_pct", "successes", "failures",
               "p50_ms", "p95_ms", "p99_ms", "p99_ci95_low_ms", "p99_ci95_high_ms",
               "recorded_key_exchange", "recorded_signature_type", "file"], fig1)
    print(f"profiles={len(rows)} requests={total_req} failures={total_fail} max_failures_per_profile={max_fail}")
    # Ratios used in the text (RTT 50 ms, MTU 1500).
    base = {(r[0], r[1], r[2]): r[10] for r in fig1 if r[5] == 0.0}
    for loss in (0.5, 1.0):
        ratios = [r[10] / base[(r[0], r[1], r[2])] for r in fig1 if r[5] == loss]
        print(f"RTT50/MTU1500 p99 ratio at {loss}% loss: {min(ratios):.2f}x - {max(ratios):.2f}x "
              f"(>=2x: {sum(x >= 2 for x in ratios)}/12, >=5x: {sum(x >= 5 for x in ratios)}/12)")
    print("p99 at 0% / 1% loss range (ms):",
          round(min(base.values()), 1), round(max(base.values()), 1), "/",
          round(min(r[10] for r in fig1 if r[5] == 1.0), 1), round(max(r[10] for r in fig1 if r[5] == 1.0), 1))
    # Failures by loss level.
    for loss in (0.0, 0.1, 0.5, 1.0, 2.0):
        fs = [r[7] for r in rows if r[5] == loss]
        print(f"loss {loss}%: failures {sum(fs)} in {len(fs)} profiles, max {max(fs)}")
    # Repeated records.
    rep_rows = []
    for key in sorted(prof):
        for rp in prof[key]["repeats"]:
            a = ttfb_ms(load(prof[key]["canonical"]))
            b = ttfb_ms(load(rp))
            rep_rows.append([*key, rel(prof[key]["canonical"]), rel(rp), median(a), median(b),
                             100 * (median(b) / median(a) - 1), p99(a), p99(b), p99(b) / p99(a)])
    write_csv("S3_repeated_netem_records.csv",
              ["host", "openssl", "tls_config", "mtu", "rtt_ms", "loss_pct", "canonical_file", "repeat_file",
               "canonical_p50_ms", "repeat_p50_ms", "p50_diff_pct", "canonical_p99_ms", "repeat_p99_ms",
               "p99_ratio"], rep_rows)
    if rep_rows:
        lossy = [r for r in rep_rows if r[5] > 0]
        print(f"repeated records: {len(rep_rows)} (lossy {len(lossy)}); "
              f"max |p50 diff| {max(abs(r[10]) for r in rep_rows):.2f}%; "
              f"p99 ratio range {min(r[13] for r in rep_rows):.2f}-{max(r[13] for r in rep_rows):.2f}; "
              f"|p99 change|>20%: {sum(abs(r[13]-1) > 0.2 for r in rep_rows)}")
        z = [r for r in rep_rows if r[5] == 0]
        if z:
            print(f"  zero-loss repeats: {len(z)}; max |p50 diff| {max(abs(r[10]) for r in z):.2f}%, "
                  f"p99 ratio {min(r[13] for r in z):.2f}-{max(r[13] for r in z):.2f}")


if __name__ == "__main__":
    main()
