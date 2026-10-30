"""Shared helpers for the read-only analysis scripts.

Standard library only. Nothing in data/raw/ is modified.
"""
from __future__ import annotations

import csv
import json
import math
import random
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
RESULTS = ROOT / "results"

# Directory of each host / OpenSSL release in the archive.
BRANCHES = {
    ("laptop", "3.4.1"): RAW / "openssl-3.4.1",
    ("laptop", "3.5.0"): RAW / "openssl-3.5.0",
    ("lab-server", "3.4.1"): RAW / "lab-server" / "openssl-3.4.1",
    ("lab-server", "3.5.0"): RAW / "lab-server" / "openssl-3.5.0",
}
HOSTS = ("laptop", "lab-server")
VERSIONS = ("3.4.1", "3.5.0")
TLS_CONFIGS = ("classical", "hybrid", "fullpqc")
MTUS = (1500, 1400, 1280)
RTTS = (0, 20, 50, 100)
LOSSES = (0.0, 0.1, 0.5, 1.0, 2.0)

BOOTSTRAP_RESAMPLES = 10_000
SEED = 20261029


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def quantile(values, p: float) -> float:
    """Linear interpolation at (n-1)*p; same rule as src/pqc_bench/stats.py."""
    s = sorted(values)
    if not s:
        raise ValueError("empty sample")
    idx = (len(s) - 1) * p
    lo, hi = math.floor(idx), math.ceil(idx)
    return s[lo] + (s[hi] - s[lo]) * (idx - lo)


def median(values) -> float:
    return quantile(values, 0.5)


def ttfb_ms(doc: dict) -> list[float]:
    """Successful-request TTFB samples in milliseconds."""
    return [s["ttfb_us"] / 1000 for s in doc["samples"] if s.get("ok") and s.get("ttfb_us") is not None]


def n_failed(doc: dict) -> int:
    return sum(1 for s in doc["samples"] if not s.get("ok"))


def bootstrap_ci(stat, samples: list[list[float]], level: float = 0.95,
                 resamples: int = BOOTSTRAP_RESAMPLES, seed: int = SEED):
    """Percentile bootstrap CI of stat(*resampled_groups); groups resampled independently."""
    rng = random.Random(seed)
    reps = []
    for _ in range(resamples):
        groups = [[g[rng.randrange(len(g))] for _ in range(len(g))] for g in samples]
        reps.append(stat(*groups))
    reps.sort()
    a = (1 - level) / 2
    return quantile(reps, a), quantile(reps, 1 - a)


def quantile_ci(values, p: float, level: float = 0.95):
    """Distribution-free CI for a population quantile from order statistics.

    Uses the binomial distribution of the number of observations below the
    quantile (e.g. Conover, Practical Nonparametric Statistics, 3rd ed., §3.2).
    Returns (low, high, achieved_coverage). Within-run interval only.
    """
    s = sorted(values)
    n = len(s)
    # Binomial(n, p) pmf computed in log space for stability.
    logp, logq = math.log(p), math.log1p(-p)
    pmf = [math.exp(math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1) + k * logp + (n - k) * logq)
           for k in range(n + 1)]
    cdf = []
    acc = 0.0
    for v in pmf:
        acc += v
        cdf.append(acc)
    a = (1 - level) / 2
    # 1-based ranks: largest l with P(B <= l-1) <= a, smallest u with P(B >= u) <= a,
    # where B ~ Binomial(n, p) counts observations below the population quantile.
    below = [k for k in range(n + 1) if cdf[k] <= a]
    l = max(1, below[-1] + 1) if below else 1
    above = [k for k in range(1, n + 1) if 1 - cdf[k - 1] <= a]
    u = min(n, above[0]) if above else n
    coverage = cdf[u - 1] - (cdf[l - 1] if l > 0 else 0)
    return s[l - 1], s[u - 1], coverage


def http_file(host: str, version: str, name: str) -> Path:
    matches = sorted(BRANCHES[(host, version)].glob(f"*-{name}.json"))
    if len(matches) != 1:
        raise FileNotFoundError((host, version, name, matches))
    return matches[0]


NETEM_RE = re.compile(r"^(\d+)-netem-http-(\w+?)_mtu(\d+)_rtt(\d+)_loss([\dp]+)\.json$")


def netem_profiles():
    """Return {(host, version, cfg, mtu, rtt, loss): {'canonical': path, 'repeats': [paths]}}.

    The canonical record of each nominal profile is the one with the lowest run ID.
    Later records with identical nominal parameters (present only for
    lab-server / OpenSSL 3.4.1 / classical) are kept separately as repeats.
    """
    out: dict = {}
    for (host, version), base in BRANCHES.items():
        for path in base.glob("*-netem-http-*.json"):
            m = NETEM_RE.match(path.name)
            if not m:
                continue
            rid, cfg, mtu, rtt, loss = m.groups()
            key = (host, version, cfg, int(mtu), int(rtt), float(loss.replace("p", ".")))
            out.setdefault(key, []).append((int(rid), path))
    result = {}
    for key, items in out.items():
        items.sort()
        result[key] = {"canonical": items[0][1], "repeats": [p for _, p in items[1:]]}
    return result


def write_csv(name: str, header: list[str], rows: list[list]) -> Path:
    RESULTS.mkdir(exist_ok=True)
    path = RESULTS / name
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for r in rows:
            w.writerow([f"{x:.6g}" if isinstance(x, float) else x for x in r])
    return path


def rel(path: Path) -> str:
    return str(Path(path).relative_to(ROOT))
