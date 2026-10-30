#!/usr/bin/env python3
"""Decomposition of tail latency into delay classes (Supplementary Table S2).

For every canonical netem profile, each successful request's excess delay is
its TTFB minus the profile median TTFB. Requests are classified as
  - sub-second delay:  100 ms <= excess < 900 ms
  - ~1 s delay:        900 ms <= excess < 1600 ms
  - longer delay:      excess >= 1600 ms
  - failure:           5 s timeout (no TTFB)
The 900 ms boundary lies in the empty region of the pooled excess-delay
histogram between the sub-second cluster and the cluster near +1 s
(see results/excess_delay_histogram.csv).

The ~1 s class is compared with the probability that at least one of the two
TCP connection-establishment segments (SYN, SYN-ACK) is dropped when the
configured loss rate p is applied independently on each direction:
1 - (1 - p)^2. Linux retransmits an unanswered SYN after its 1 s initial
retransmission timeout (RFC 6298). This comparison is a consistency check; the
archive contains no packet-level retransmission records.

Configuration differences use matched profiles (same host, release, MTU, RTT,
loss) and a cluster bootstrap over the 48 matched profile groups per loss rate
(10,000 resamples, fixed seed).
"""
import collections
import math
import random

from common import (BOOTSTRAP_RESAMPLES, LOSSES, SEED, load, median, n_failed,
                    netem_profiles, quantile, ttfb_ms, write_csv)

CLASSES = ("sub_second", "one_second", "longer", "failed")


def classify(doc):
    t = ttfb_ms(doc)
    med = median(t)
    c = dict.fromkeys(CLASSES, 0)
    hist = collections.Counter()
    for x in t:
        e = x - med
        if e >= 100:
            hist[int(e // 100) * 100] += 1
        if 100 <= e < 900:
            c["sub_second"] += 1
        elif 900 <= e < 1600:
            c["one_second"] += 1
        elif e >= 1600:
            c["longer"] += 1
    c["failed"] = n_failed(doc)
    p99_excess = quantile(t, 0.99) - med
    return c, len(t) + c["failed"], hist, med, p99_excess


def binom_sf(k, n, p):
    """P(X >= k) for X ~ Binomial(n, p)."""
    return sum(math.comb(n, j) * p ** j * (1 - p) ** (n - j) for j in range(k, n + 1))


def main():
    prof = netem_profiles()
    per = {}
    hist_by_loss = collections.defaultdict(collections.Counter)
    rows = []
    for key in sorted(prof):
        c, n, hist, med, p99x = classify(load(prof[key]["canonical"]))
        per[key] = (c, n, p99x)
        hist_by_loss[key[5]].update(hist)
        rows.append([*key, n, med, *(c[k] for k in CLASSES), p99x])
    write_csv("S2_tail_classes_by_profile.csv",
              ["host", "openssl", "tls_config", "mtu", "rtt_ms", "loss_pct", "requests", "p50_ms",
               "sub_second_delay", "one_second_delay", "longer_delay", "failed", "p99_minus_p50_ms"], rows)
    hrows = []
    for loss in sorted(hist_by_loss):
        for b in sorted(hist_by_loss[loss]):
            hrows.append([loss, b, b + 100, hist_by_loss[loss][b]])
    write_csv("excess_delay_histogram.csv", ["loss_pct", "excess_from_ms", "excess_to_ms", "requests"], hrows)

    rng = random.Random(SEED)
    groups_by_loss = collections.defaultdict(list)
    for (host, ver, cfg, mtu, rtt, loss) in per:
        if cfg == "classical":
            groups_by_loss[loss].append((host, ver, mtu, rtt))

    def frac(cfg, loss, cls, groups):
        num = sum(per[(h, v, cfg, m, r, loss)][0][cls] for (h, v, m, r) in groups)
        den = sum(per[(h, v, cfg, m, r, loss)][1] for (h, v, m, r) in groups)
        return 100 * num / den

    summary, diffs = [], []
    for loss in LOSSES:
        g = groups_by_loss[loss]
        assert len(g) == 48
        boots = []
        for _ in range(BOOTSTRAP_RESAMPLES):
            boots.append([g[rng.randrange(48)] for _ in range(48)])
        for cfg in ("classical", "hybrid", "fullpqc"):
            for cls in CLASSES:
                est = frac(cfg, loss, cls, g)
                reps = sorted(frac(cfg, loss, cls, b) for b in boots)
                summary.append([cfg, loss, cls, est, quantile(reps, .025), quantile(reps, .975),
                                100 * (1 - (1 - loss / 100) ** 2) if cls == "one_second" else ""])
        for cfg in ("hybrid", "fullpqc"):
            for cls in ("sub_second", "one_second"):
                est = frac(cfg, loss, cls, g) - frac("classical", loss, cls, g)
                reps = sorted(frac(cfg, loss, cls, b) - frac("classical", loss, cls, b) for b in boots)
                diffs.append([f"{cfg} - classical", loss, cls, est, quantile(reps, .025), quantile(reps, .975)])
    write_csv("tail_classes_by_config_and_loss.csv",
              ["tls_config", "loss_pct", "delay_class", "percent_of_requests", "ci95_low", "ci95_high",
               "expected_percent_if_syn_or_synack_lost"], summary)
    write_csv("tail_class_differences_vs_classical.csv",
              ["comparison", "loss_pct", "delay_class", "difference_pct_points", "ci95_low", "ci95_high"], diffs)

    print("Delay classes (% of requests, cluster-bootstrap 95% CI); expected ~1 s share = 1-(1-p)^2")
    for r in summary:
        if r[2] in ("sub_second", "one_second") and r[1] > 0:
            exp = f"  expected {r[6]:.2f}" if r[6] != "" else ""
            print(f"  {r[0]:9} loss {r[1]:3}%  {r[2]:10} {r[3]:6.2f} [{r[4]:5.2f}, {r[5]:5.2f}]{exp}")
    print("Differences vs classical (percentage points)")
    for r in diffs:
        if r[1] > 0:
            print(f"  {r[0]:20} loss {r[1]:3}%  {r[2]:10} {r[3]:+5.2f} [{r[4]:+5.2f}, {r[5]:+5.2f}]")
    # Where does p99 fall at 0.5% loss?
    for loss in (0.5, 1.0, 2.0):
        keys = [k for k in per if k[5] == loss]
        in1s = sum(1 for k in keys if per[k][2] >= 900)
        print(f"loss {loss}%: p99 lies in the >=900 ms excess region for {in1s}/{len(keys)} profiles")
    # Binomial expectation at 0.5%: p99 (rank ~990 of 1000) falls in the >=900 ms region when
    # at least 11 of 1000 requests are in the ~1 s or longer classes.
    p = 1 - (1 - 0.005) ** 2
    print(f"P(at least 11 of 1000 requests with lost SYN/SYN-ACK | p=0.5%) = {binom_sf(11, 1000, p):.2f}")


if __name__ == "__main__":
    main()
