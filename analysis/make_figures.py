#!/usr/bin/env python3
"""Draw the revised manuscript figures from the CSV files in results/.

Requires matplotlib (the analysis scripts themselves use the standard library only).
Run the numbered scripts first. Output: results/figures/*.png (300 dpi).
Figure 1 combines the p99 sweep (a, b) and the delay-class shares (c, d).
"""
import csv
from collections import defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from common import RESULTS  # noqa: E402

OUT = RESULTS / "figures"
COLORS = {"classical": "#2a78d6", "hybrid": "#eb6834", "fullpqc": "#1baf7a"}
MARKERS = {"classical": "o", "hybrid": "s", "fullpqc": "^"}
NAMES = {"classical": "Classical (X25519 + RSA-PSS)", "hybrid": "Hybrid (X25519MLKEM768 + RSA-PSS)",
         "fullpqc": "Full PQC (ML-KEM-768 + ML-DSA-65)"}
INK, MUTED, GRID = "#1f1f1e", "#5f5e5a", "#e6e5e0"
plt.rcParams.update({"font.size": 9, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED,
                     "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
                     "font.family": "DejaVu Sans"})


def read(name):
    with (RESULTS / name).open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def fig_loss_and_tail():
    """Figure 1: (a, b) p99 vs loss, OpenSSL 3.5.0, RTT 50 ms, MTU 1500;
    (c, d) share of requests per delay class, all 720 profiles pooled."""
    rows = [r for r in read("figure1_rtt50_mtu1500_all_loss_levels.csv") if r["openssl"] == "3.5.0"]
    cls_rows = read("tail_classes_by_config_and_loss.csv")
    losses = [0.0, 0.1, 0.5, 1.0, 2.0]
    fig, axes = plt.subplots(2, 2, figsize=(7.2, 5.8))
    for ax, host, title in zip(axes[0], ("laptop", "lab-server"), ("(a) Laptop, OpenSSL 3.5.0", "(b) Lab server, OpenSSL 3.5.0")):
        for k, cfg in enumerate(("classical", "hybrid", "fullpqc")):
            sel = {float(r["loss_pct"]): r for r in rows if r["host"] == host and r["tls_config"] == cfg}
            x = [i + (k - 1) * 0.12 for i in range(len(losses))]
            y = [float(sel[l]["p99_ms"]) for l in losses]
            lo = [y[i] - float(sel[l]["p99_ci95_low_ms"]) for i, l in enumerate(losses)]
            hi = [float(sel[l]["p99_ci95_high_ms"]) - y[i] for i, l in enumerate(losses)]
            ax.errorbar(x, y, yerr=[lo, hi], color=COLORS[cfg], marker=MARKERS[cfg], ms=5, lw=1.6,
                        capsize=2, elinewidth=1, label=NAMES[cfg])
        ax.set_xticks(range(len(losses)), [f"{l:g}" for l in losses])
        ax.set_xlabel("Configured packet loss per direction (%)")
        ax.set_ylabel("p99 TTFB (ms)")
        ax.set_ylim(0, 2400)
        ax.set_title(title, color=INK, fontsize=9, loc="left")
        ax.grid(axis="y", color=GRID, lw=0.8)
        ax.set_axisbelow(True)
    axes[0][0].legend(frameon=False, fontsize=7, loc="upper left")
    closs = [0.1, 0.5, 1.0, 2.0]
    for ax, cls, title in zip(axes[1], ("one_second", "sub_second"),
                              ("(c) Requests delayed by 900–1600 ms (≈1 s)", "(d) Requests delayed by 100–900 ms")):
        for k, cfg in enumerate(("classical", "hybrid", "fullpqc")):
            sel = {float(r["loss_pct"]): r for r in cls_rows if r["tls_config"] == cfg and r["delay_class"] == cls}
            x = [i + (k - 1) * 0.1 for i in range(len(closs))]
            y = [float(sel[l]["percent_of_requests"]) for l in closs]
            lo = [y[i] - float(sel[l]["ci95_low"]) for i, l in enumerate(closs)]
            hi = [float(sel[l]["ci95_high"]) - y[i] for i, l in enumerate(closs)]
            ax.errorbar(x, y, yerr=[lo, hi], color=COLORS[cfg], marker=MARKERS[cfg], ms=5, lw=0,
                        elinewidth=1.2, capsize=2, label=NAMES[cfg])
        if cls == "one_second":
            exp = [100 * (1 - (1 - l / 100) ** 2) for l in closs]
            (exp_line,) = ax.plot(range(len(closs)), exp, color=MUTED, lw=1.2, ls="--",
                                  label="Expected: SYN or SYN-ACK lost, 1−(1−p)²")
            ax.legend(frameon=False, fontsize=7, loc="upper left", handles=[exp_line])
        ax.set_xticks(range(len(closs)), [f"{l:g}" for l in closs])
        ax.set_xlabel("Configured packet loss per direction (%)")
        ax.set_ylabel("Share of requests (%)")
        ax.set_title(title, color=INK, fontsize=9, loc="left")
        ax.grid(axis="y", color=GRID, lw=0.8)
        ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(OUT / "figure1_loss_and_tail_classes.png", dpi=300)
    plt.close(fig)


def fig_packetization():
    rows = read("figure2_packetization_segments.csv")
    recs = read("table6_tls_record_bytes_mtu1500.csv")
    order = ["baseline", "hybrid-kem", "pqc-kem", "pqc-cert", "full-pqc"]
    labels = ["X25519\nRSA", "X25519-\nMLKEM768\nRSA", "ML-KEM-768\nRSA", "X25519\nML-DSA-65",
              "ML-KEM-768\nML-DSA-65"]
    mtus = ["1500", "1400", "1280"]
    shades = {"1500": "#184f95", "1400": "#3987e5", "1280": "#9ec5f4"}
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.4, 3.4))
    w = 0.26
    for j, mtu in enumerate(mtus):
        vals = [float(next(r for r in rows if r["scenario"] == s and r["mtu"] == mtu)["mean_s2c_payload_segments"])
                for s in order]
        xs = [i + (j - 1) * w for i in range(len(order))]
        a1.bar(xs, vals, width=w - 0.03, color=shades[mtu], label=f"MTU {mtu}")
        for x, v in zip(xs, vals):
            a1.text(x, v + 0.2, f"{v:g}", ha="center", va="bottom", fontsize=6.5, color=INK)
    a1.set_xticks(range(len(order)), labels, fontsize=6.5)
    a1.set_ylabel("Server-to-client payload segments\nper qualifying connection")
    a1.legend(frameon=False, fontsize=7)
    a1.grid(axis="y", color=GRID, lw=0.8)
    a1.set_axisbelow(True)
    parts = [("ServerHello", "#eb6834"), ("Certificate", "#2a78d6"), ("CertificateVerify", "#1baf7a"),
             ("Other", "#b4b2a9")]
    bottoms = [0] * len(order)
    for name, col in parts:
        vals = []
        for s in order:
            srv = [r for r in recs if r["scenario"] == s and r["direction"] == "server->client"]
            if name == "Other":
                v = sum(int(r["record_length_bytes"]) + 5 for r in srv
                        if r["message_inferred"] not in ("ServerHello", "Certificate", "CertificateVerify"))
            else:
                v = sum(int(r["record_length_bytes"]) + 5 for r in srv if r["message_inferred"] == name)
            vals.append(v / 1000)
        a2.bar(range(len(order)), vals, bottom=bottoms, color=col, width=0.6, label=name,
               edgecolor="white", linewidth=1)
        bottoms = [b + v for b, v in zip(bottoms, vals)]
    for i, b in enumerate(bottoms):
        a2.text(i, b + 0.15, f"{b:.1f}", ha="center", va="bottom", fontsize=6.5, color=INK)
    a2.set_xticks(range(len(order)), labels, fontsize=6.5)
    a2.set_ylabel("Server-to-client TLS bytes (kB)")
    a2.legend(frameon=False, fontsize=7, loc="upper left")
    a2.grid(axis="y", color=GRID, lw=0.8)
    a2.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(OUT / "figure2_packetization_and_bytes.png", dpi=300)
    plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    fig_loss_and_tail()
    fig_packetization()
    print("figures written to", OUT)
