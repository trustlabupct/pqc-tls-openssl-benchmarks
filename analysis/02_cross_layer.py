#!/usr/bin/env python3
"""Manuscript Table 4: X25519MLKEM768 primitive, handshake and HTTP medians (laptop).

Primitive timings: 10 `openssl speed` samples per operation (04-hybrid-mlkem.json).
Handshake: archived summary of 10 s_client connections with an ML-DSA-65 server
certificate (per-handshake timings are not stored, so only the recorded median is shown).
HTTP: Run A (18-http-openssl-hybrid.json) in both releases, RSA-PSS authentication.
"""
from common import BRANCHES, load, median, rel, ttfb_ms, write_csv


def kem_row(doc):
    return next(r for r in doc["results"] if r["algorithm"] == "X25519MLKEM768")


def main():
    rows = []
    docs = {v: load(BRANCHES[("laptop", v)] / "04-hybrid-mlkem.json") for v in ("3.4.1", "3.5.0")}
    for op in ("keygen", "encaps", "decaps"):
        vals = []
        for v in ("3.4.1", "3.5.0"):
            o = kem_row(docs[v])["operations"][op]
            assert len(o["timings_us"]) == o["sample_count"] == 10
            vals.append(median(o["timings_us"]))
        rows.append(["primitive", op, "us", vals[0], vals[1], 100 * (vals[1] / vals[0] - 1)])
    hs = []
    for v in ("3.4.1", "3.5.0"):
        d = next(r for r in docs[v]["tls_details"]
                 if r["kem_algorithm"] == "X25519MLKEM768" and r["sig_algorithm"].lower() == "mldsa65")
        assert d["success_count"] == d["total_count"] == 10
        hs.append(d["stats"]["median_us"] / 1000)
    rows.append(["tls_handshake", "X25519MLKEM768 + ML-DSA-65 (summary median)", "ms", hs[0], hs[1],
                 100 * (hs[1] / hs[0] - 1)])
    http = []
    for v in ("3.4.1", "3.5.0"):
        p = BRANCHES[("laptop", v)] / "18-http-openssl-hybrid.json"
        http.append(median(ttfb_ms(load(p))))
    rows.append(["http_ttfb", "X25519MLKEM768 + RSA-PSS, Run A", "ms", http[0], http[1],
                 100 * (http[1] / http[0] - 1)])
    write_csv("table4_cross_layer_laptop.csv",
              ["layer", "metric", "unit", "openssl_3.4.1", "openssl_3.5.0", "relative_change_pct"], rows)
    for r in rows:
        print(f"{r[0]:14} {r[1]:45} {r[3]:9.3f} {r[4]:9.3f} {r[2]:3} {r[5]:+6.1f}%")


if __name__ == "__main__":
    main()
