#!/usr/bin/env python3
"""Generate an Alcazar-based PDF report from pqc-bench result JSON files.

This script reads the JSON files under ./results/ and generates:
  - LaTeX tables under ./report/alcazar/text/chapters/generated/
  - Optional PDF figures under ./report/alcazar/figures/pqc/

It can also run latexmk to build the final PDF.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


_CURVE_PREFIX_DISPLAY: dict[str, str] = {
    # NIST curves
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
    "p256": "P-256",
    "p384": "P-384",
    "p521": "P-521",
    # X25519 / X448
    "x25519": "X25519",
    "x448": "X448",
    # Brainpool
    "bp256": "brainpoolP256r1",
    "bp384": "brainpoolP384r1",
    "bp512": "brainpoolP512r1",
    # Classical signature prefixes used in hybrid signature benchmarks
    "rsa3072": "RSA3072",
}


@dataclass(frozen=True)
class OpStats:
    median_us: float | None
    p95_us: float | None
    p99_us: float | None
    sample_count: int | None


@dataclass(frozen=True)
class AlgoRow:
    algorithm: str
    type: str | None
    is_hybrid: bool
    is_experimental: bool
    is_tls: bool
    operations: dict[str, OpStats]
    sizes: dict[str, int | None]
    tls_kem: str | None
    tls_sig: str | None


@dataclass(frozen=True)
class Dataset:
    label: str
    title: str
    results_dir: Path
    slug: str


@dataclass(frozen=True)
class PacketizationObservation:
    host: str
    mtu: int
    kem_algorithm: str
    sig_algorithm: str
    cert_der_size_bytes: int | None
    avg_client_segments_with_payload: float | None
    avg_server_segments_with_payload: float | None
    iterations: int | None
    connection_count: int | None


@dataclass(frozen=True)
class NetemEntry:
    label: str
    mtu: int
    rtt_ms: float
    loss_pct: float
    p99_ms: float
    fail_rate: float | None


@dataclass(frozen=True)
class CapacityEntry:
    label: str
    concurrency: int
    rps: float | None
    p99_ms: float | None


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _latex_escape(text: str) -> str:
    # Conservative escape for common LaTeX special chars in regular text mode.
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(ch, ch) for ch in text)


def _latex_escape_code(text: str) -> str:
    escaped = _latex_escape(text)
    # Improve line breaking for code-like identifiers (algorithm names, filenames, etc.).
    escaped = escaped.replace(r"\_", r"\_\allowbreak{}")
    escaped = escaped.replace("+", r"+\allowbreak{}")
    escaped = escaped.replace("-", r"-\allowbreak{}")
    return escaped


def _canonical_prefix(name: str) -> str | None:
    key = name.strip().lower()
    return _CURVE_PREFIX_DISPLAY.get(key)


def _format_algo_display(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""

    if "+" in text:
        return "+".join(_format_algo_display(part) for part in text.split("+") if part)

    # snake_case hybrids: <prefix>_<scheme...>
    if "_" in text:
        prefix, rest = text.split("_", 1)
        prefix_disp = _canonical_prefix(prefix)
        if prefix_disp:
            return f"{prefix_disp}+{_format_algo_display(rest)}"

    # CamelCase hybrids: <Curve><Scheme>
    for curve_prefix in ("SecP256r1", "SecP384r1", "SecP521r1", "X25519", "X448"):
        if text.lower().startswith(curve_prefix.lower()):
            curve_disp = _canonical_prefix(curve_prefix) or curve_prefix
            remainder = text[len(curve_prefix) :]
            if remainder:
                return f"{curve_disp}+{_format_algo_display(remainder)}"
            return curve_disp

    prefix_disp = _canonical_prefix(text)
    if prefix_disp:
        return prefix_disp

    if match := re.fullmatch(r"(?i)mlkem(\d+)", text):
        return f"ML-KEM-{match.group(1)}"
    if match := re.fullmatch(r"(?i)mldsa(\d+)", text):
        return f"ML-DSA-{match.group(1)}"
    if match := re.fullmatch(r"(?i)bikel(\d+)", text):
        return f"BIKE-L{match.group(1)}"
    if match := re.fullmatch(r"(?i)frodo(\d+)(aes|shake)", text):
        param, variant = match.groups()
        return f"FrodoKEM-{param}-{variant.upper()}"
    if match := re.fullmatch(r"(?i)falconpadded(\d+)", text):
        return f"FalconPadded-{match.group(1)}"
    if match := re.fullmatch(r"(?i)falcon(\d+)", text):
        return f"Falcon-{match.group(1)}"
    if match := re.fullmatch(r"(?i)mayo(\d+)", text):
        return f"MAYO-{match.group(1)}"
    if match := re.fullmatch(r"(?i)sphincs(sha2|shake)(\d+)([fs])simple", text):
        family, level, variant = match.groups()
        return f"SPHINCS+-{family.upper()}-{level}{variant}-simple"

    return text


def _fmt_us(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value:.1f}"


def _fmt_bool(value: bool) -> str:
    return "yes" if value else "no"


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _coerce_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _coerce_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _normalize_float(value: float, *, digits: int = 3) -> float:
    return round(float(value), digits)


def _is_microbench_json(data: dict[str, Any]) -> bool:
    results = data.get("results")
    if not isinstance(results, list) or not results:
        return False
    first = results[0]
    return isinstance(first, dict) and "algorithm" in first


def _is_packetization_json(data: dict[str, Any]) -> bool:
    meta = data.get("metadata")
    return isinstance(meta, dict) and meta.get("experiment_type") == "packetization"


def _parse_iso_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _parse_leading_int(filename: str) -> int | None:
    match = re.match(r"(\\d+)-", filename)
    if not match:
        return None
    return int(match.group(1))


def _parse_packetization_observations(
    data: dict[str, Any],
    *,
    host: str,
) -> list[PacketizationObservation]:
    observations: list[PacketizationObservation] = []

    for raw in data.get("results") or []:
        if not isinstance(raw, dict):
            continue
        test_parameters = raw.get("test_parameters")
        aggregated = raw.get("aggregated")
        if not isinstance(test_parameters, dict) or not isinstance(aggregated, dict):
            continue

        mtu = _coerce_int(test_parameters.get("mtu"))
        kem_algorithm = str(test_parameters.get("kem_algorithm") or "").strip()
        sig_algorithm = str(test_parameters.get("sig_algorithm") or "").strip()
        if mtu is None or not kem_algorithm or not sig_algorithm:
            continue

        cert_der_size_bytes = _coerce_int(test_parameters.get("cert_der_size_bytes"))
        iterations = _coerce_int(test_parameters.get("iterations"))

        client_avg = aggregated.get("avg_client_segments_with_payload")
        server_avg = aggregated.get("avg_server_segments_with_payload")
        avg_client = float(client_avg) if isinstance(client_avg, (int, float)) else None
        avg_server = float(server_avg) if isinstance(server_avg, (int, float)) else None

        connection_count = _coerce_int(aggregated.get("connection_count"))

        observations.append(
            PacketizationObservation(
                host=host,
                mtu=mtu,
                kem_algorithm=kem_algorithm,
                sig_algorithm=sig_algorithm,
                cert_der_size_bytes=cert_der_size_bytes,
                avg_client_segments_with_payload=avg_client,
                avg_server_segments_with_payload=avg_server,
                iterations=iterations,
                connection_count=connection_count,
            )
        )

    return observations


def _label_from_filename(filename: str, tag: str) -> str | None:
    match = re.search(rf"{re.escape(tag)}([a-z0-9]+)", filename.lower())
    if match:
        return match.group(1)
    return None


def _concurrency_from_filename(filename: str) -> int | None:
    match = re.search(r"_c(\d+)", filename.lower())
    if match:
        return int(match.group(1))
    return None


def _parse_netem_entries(http_runs: list[tuple[str, dict[str, Any]]]) -> list[NetemEntry]:
    entries_by_key: dict[
        tuple[str, int, float, float],
        tuple[NetemEntry, datetime | None, int | None, str],
    ] = {}

    for filename, data in http_runs:
        meta = data.get("metadata") or {}
        context = meta.get("context") or {}
        if not isinstance(context, dict) or context.get("experiment") != "netem":
            continue

        netem = context.get("netem") or {}
        if not isinstance(netem, dict):
            continue

        mtu = _coerce_int(netem.get("mtu"))
        rtt_ms = _coerce_float(netem.get("rtt_ms"))
        loss_pct = _coerce_float(netem.get("loss_pct"))
        label = str(context.get("label") or "").strip().lower()
        if not label:
            label = _label_from_filename(filename, "netem-http-") or ""

        metrics = data.get("metrics") or {}
        ttfb = metrics.get("ttfb_us") or {}
        p99_us = _coerce_float(ttfb.get("p99_us"))
        fail_rate = _coerce_float(meta.get("fail_rate"))

        if not label or mtu is None or rtt_ms is None or loss_pct is None or p99_us is None:
            continue

        entry = NetemEntry(
            label=label,
            mtu=mtu,
            rtt_ms=_normalize_float(rtt_ms),
            loss_pct=_normalize_float(loss_pct),
            p99_ms=float(p99_us) / 1000.0,
            fail_rate=fail_rate,
        )
        key = (entry.label, entry.mtu, entry.rtt_ms, entry.loss_pct)
        timestamp = _parse_iso_timestamp(meta.get("run_finished_at") or meta.get("run_started_at"))
        sequence = _parse_leading_int(filename)

        existing = entries_by_key.get(key)
        if existing is None:
            entries_by_key[key] = (entry, timestamp, sequence, filename)
            continue

        _, prev_ts, prev_seq, prev_name = existing
        replace = False
        if timestamp and prev_ts:
            replace = timestamp > prev_ts
        elif timestamp and not prev_ts:
            replace = True
        elif not timestamp and not prev_ts:
            if sequence is not None and prev_seq is not None:
                replace = sequence > prev_seq
            elif sequence is not None and prev_seq is None:
                replace = True
            elif sequence is None and prev_seq is None:
                replace = filename > prev_name

        if replace:
            entries_by_key[key] = (entry, timestamp, sequence, filename)

    return [entry for entry, _, _, _ in entries_by_key.values()]


def _parse_capacity_entries(http_runs: list[tuple[str, dict[str, Any]]]) -> list[CapacityEntry]:
    entries: list[CapacityEntry] = []

    for filename, data in http_runs:
        meta = data.get("metadata") or {}
        context = meta.get("context") or {}
        if not isinstance(context, dict) or context.get("experiment") != "capacity":
            continue

        label = _label_from_filename(filename, "capacity-http-") or ""
        label = label.strip().lower()
        concurrency = _coerce_int(context.get("concurrency")) or _concurrency_from_filename(
            filename
        )

        metrics = data.get("metrics") or {}
        ttfb = metrics.get("ttfb_us") or {}
        p99_us = _coerce_float(ttfb.get("p99_us"))
        p99_ms = float(p99_us) / 1000.0 if p99_us is not None else None

        rps = _coerce_float(meta.get("measured_requests_per_sec"))
        if rps is None:
            rps = _coerce_float(meta.get("requests_per_sec"))

        if not label or concurrency is None:
            continue

        entries.append(
            CapacityEntry(
                label=label,
                concurrency=concurrency,
                rps=rps,
                p99_ms=p99_ms,
            )
        )

    return entries


def _render_packetization_appendix(observations: list[PacketizationObservation]) -> str:
    by_host: dict[str, list[PacketizationObservation]] = defaultdict(list)
    for obs in observations:
        by_host[obs.host].append(obs)

    def host_sort_key(host: str) -> tuple[int, str]:
        if host == "Laptop":
            return (0, host.lower())
        if host == "Lab server":
            return (1, host.lower())
        return (2, host.lower())

    unique_iterations = sorted(
        {obs.iterations for obs in observations if isinstance(obs.iterations, int)}
    )
    unique_connections = sorted(
        {obs.connection_count for obs in observations if isinstance(obs.connection_count, int)}
    )

    if len(unique_iterations) == 1 and len(unique_connections) == 1:
        averaging_note = f"averaged over {unique_iterations[0]} iterations ({unique_connections[0]} connections per case)."
    else:
        averaging_note = "averaged over the available iterations (multiple connections per case)."

    sig_order = {"rsa:2048": 0, "mldsa65": 1}
    kem_order = {"X25519": 0, "X25519MLKEM768": 1, "mlkem768": 2}

    def sort_key(key: tuple[int, str, str]) -> tuple[int, int, int, str, str]:
        mtu, kem, sig = key
        return (-mtu, sig_order.get(sig, 99), kem_order.get(kem, 99), kem.lower(), sig.lower())

    def fmt_range_int(values: list[int]) -> str:
        if not values:
            return "N/A"
        low, high = min(values), max(values)
        return str(low) if low == high else f"{low}--{high}"

    def fmt_range_float(values: list[float]) -> str:
        if not values:
            return "N/A"
        low, high = min(values), max(values)
        if abs(low - high) < 1e-9:
            return f"{low:.2f}"
        return f"{low:.2f}--{high:.2f}"

    lines: list[str] = []
    lines.append("% Auto-generated by report/generate_pqc_report.py. Do not edit by hand.")
    lines.append(r"\chapter{Packetization Data}")
    lines.append(r"\label{appendix:packetization}")
    lines.append("")
    lines.append(r"\noindent This appendix provides the full packetization dataset used in")
    lines.append(
        r"Section~\ref{sec:pqc:mtu}. The benchmark harness captures TLS 1.3 connection setups in isolated"
    )
    lines.append(
        r"network namespaces with a configured MTU, then analyzes the resulting PCAP to count TCP"
    )
    lines.append(
        r"segments carrying payload in each direction (pure ACKs excluded). Each row reports the mean"
    )
    lines.append(rf"number of payload-carrying segments, {averaging_note}")
    lines.append("")
    lines.append(
        r"\noindent Tables are separated by host. Within each host, ranges indicate min--max"
    )
    lines.append(r"across the OpenSSL datasets included in the input results directory.")
    lines.append("")

    for host in sorted(by_host, key=host_sort_key):
        host_obs = by_host[host]

        groups: dict[tuple[int, str, str], dict[str, Any]] = defaultdict(
            lambda: {
                "cert_sizes": [],
                "client_avgs": [],
                "server_avgs": [],
            }
        )
        for obs in host_obs:
            key = (obs.mtu, obs.kem_algorithm, obs.sig_algorithm)
            group = groups[key]
            if obs.cert_der_size_bytes is not None:
                group["cert_sizes"].append(obs.cert_der_size_bytes)
            if obs.avg_client_segments_with_payload is not None:
                group["client_avgs"].append(obs.avg_client_segments_with_payload)
            if obs.avg_server_segments_with_payload is not None:
                group["server_avgs"].append(obs.avg_server_segments_with_payload)

        host_slug = _slugify(host)
        lines.append(rf"\section{{{_latex_escape(host)}}}")
        lines.append("")
        lines.append(r"\begingroup")
        lines.append(r"\sf")
        lines.append(r"\small")
        lines.append(r"\setlength{\tabcolsep}{3.2pt}")
        lines.append(r"\renewcommand{\arraystretch}{1.2}")
        lines.append(r"\begin{longtable}{|r|l|l|r|r|r|}")
        lines.append(r"\hline")
        lines.append(
            r"\rowcolor{lightgray}\textbf{MTU} & \textbf{KEM} & \textbf{Cert sig} & \textbf{Cert DER (B)} & "
            r"\shortstack{\textbf{Client segs}\\\textbf{(avg)}} & \shortstack{\textbf{Server segs}\\\textbf{(avg)}} \\ \hline"
        )
        lines.append(r"\endfirsthead")
        lines.append(r"\hline")
        lines.append(
            r"\rowcolor{lightgray}\textbf{MTU} & \textbf{KEM} & \textbf{Cert sig} & \textbf{Cert DER (B)} & "
            r"\shortstack{\textbf{Client segs}\\\textbf{(avg)}} & \shortstack{\textbf{Server segs}\\\textbf{(avg)}} \\ \hline"
        )
        lines.append(r"\endhead")

        for mtu, kem, sig in sorted(groups, key=sort_key):
            group = groups[(mtu, kem, sig)]
            cert_range = fmt_range_int(group["cert_sizes"])
            client_range = fmt_range_float(group["client_avgs"])
            server_range = fmt_range_float(group["server_avgs"])
            lines.append(
                f"{mtu} & "
                + r"\texttt{"
                + _latex_escape_code(kem)
                + "} & "
                + r"\texttt{"
                + _latex_escape_code(sig)
                + "} & "
                + cert_range
                + " & "
                + client_range
                + " & "
                + server_range
                + r" \\ \hline"
            )

        lines.append(
            rf"\caption[Packetization dataset ({_latex_escape(host)})]{{Packetization dataset for {_latex_escape(host)} derived from \texttt{{results/*/42-packetization.json}}. Values are mean TCP segments carrying payload per connection setup (client / server directions), {averaging_note} Ranges indicate min--max across OpenSSL datasets for this host.}}"
        )
        lines.append(rf"\label{{tab:pqc:packetization-raw:{host_slug}}}")
        lines.append(r"\end{longtable}")
        lines.append(r"\endgroup")
        lines.append("")

    return "\n".join(lines)


def _normalize_http_sig(sig: str | None) -> str:
    s = (sig or "").strip()
    if not s:
        return ""
    low = s.lower()
    if low.startswith("mldsa"):
        match = re.search(r"mldsa(\d+)", low)
        if match:
            return f"ML-DSA{match.group(1)}"
        return "ML-DSA"
    if "rsa" in low:
        return "RSA-PSS"
    return s


def _pick_http_median(
    http_runs: list[tuple[str, dict[str, Any]]],
    *,
    groups: str,
    sig_label: str | None = None,
    sig_prefix: str | None = None,
) -> float | None:
    for filename, data in http_runs:
        if "playwright" in filename.lower():
            continue
        meta = data.get("metadata") or {}
        if str(meta.get("client") or "") != "openssl":
            continue
        if str(meta.get("reuse") or "") not in ("", "none"):
            continue
        # Prefer the canonical openssl scenarios (avoid duplicate native runs).
        if "http-openssl" not in filename.lower():
            continue
        if str(meta.get("groups") or "") != groups:
            continue

        tls_info = data.get("tls") or {}
        sig_norm = _normalize_http_sig(str(tls_info.get("signature_type") or ""))
        if sig_label is not None and sig_norm != sig_label:
            continue
        if sig_prefix is not None and not sig_norm.startswith(sig_prefix):
            continue

        metrics = data.get("metrics") or {}
        ttfb = metrics.get("ttfb_us", {})
        if not isinstance(ttfb, dict):
            continue
        median = ttfb.get("median_us")
        if isinstance(median, (int, float)):
            return float(median)
    return None


def _parse_algo_rows(microbench_json: dict[str, Any]) -> list[AlgoRow]:
    rows: list[AlgoRow] = []
    for raw in microbench_json.get("results") or []:
        operations: dict[str, OpStats] = {}
        for op_name, op_raw in (raw.get("operations") or {}).items():
            operations[str(op_name)] = OpStats(
                median_us=op_raw.get("median_us"),
                p95_us=op_raw.get("p95_us"),
                p99_us=op_raw.get("p99_us"),
                sample_count=op_raw.get("sample_count"),
            )

        sizes_raw = raw.get("sizes") or {}
        sizes = {
            "public_key_bytes": _coerce_int(sizes_raw.get("public_key_bytes")),
            "secret_key_bytes": _coerce_int(sizes_raw.get("secret_key_bytes")),
            "ciphertext_bytes": _coerce_int(sizes_raw.get("ciphertext_bytes")),
            "signature_bytes": _coerce_int(sizes_raw.get("signature_bytes")),
        }

        tls = raw.get("tls") or {}
        rows.append(
            AlgoRow(
                algorithm=str(raw.get("algorithm", "")),
                type=raw.get("type"),
                is_hybrid=bool(raw.get("is_hybrid", False)),
                is_experimental=bool(raw.get("is_experimental", False)),
                is_tls=bool(raw.get("is_tls", False)),
                operations=operations,
                sizes=sizes,
                tls_kem=tls.get("kem"),
                tls_sig=tls.get("sig"),
            )
        )
    return rows


def _iter_json_files(results_dir: Path) -> Iterable[Path]:
    for path in sorted(results_dir.glob("*.json")):
        if path.is_file():
            yield path


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.strip().lower())
    return slug.strip("-") or "dataset"


def _openssl_version_key_from_name(name: str) -> tuple[int, int, int] | None:
    match = re.search(r"openssl-(\d+)\.(\d+)\.(\d+)", name)
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _discover_datasets(results_dir: Path) -> list[Dataset]:
    if any(results_dir.glob("*.json")):
        label = results_dir.name
        title = label

        if results_dir.name.startswith("openssl-"):
            version = results_dir.name.replace("openssl-", "OpenSSL ", 1)
            if results_dir.parent.name == "lab-server":
                label = f"lab-{results_dir.name}"
                title = f"Lab server — {version}"
            else:
                label = f"laptop-{results_dir.name}"
                title = f"Laptop — {version}"

        return [Dataset(label=label, title=title, results_dir=results_dir, slug=_slugify(label))]

    datasets: list[Dataset] = []

    for local_dir in sorted(results_dir.glob("openssl-*")):
        if not local_dir.is_dir():
            continue
        version = local_dir.name.replace("openssl-", "OpenSSL ", 1)
        label = f"laptop-{local_dir.name}"
        datasets.append(
            Dataset(
                label=label,
                title=f"Laptop — {version}",
                results_dir=local_dir,
                slug=_slugify(label),
            )
        )

    lab_root = results_dir / "lab-server"
    if lab_root.exists():
        for lab_dir in sorted(lab_root.iterdir()):
            if not lab_dir.is_dir():
                continue
            version = lab_dir.name.replace("openssl-", "OpenSSL ", 1)
            label = f"lab-{lab_dir.name}"
            datasets.append(
                Dataset(
                    label=label,
                    title=f"Lab server — {version}",
                    results_dir=lab_dir,
                    slug=_slugify(label),
                )
            )

    def sort_key(ds: Dataset) -> tuple[tuple[int, int, int], int, str]:
        version_key = _openssl_version_key_from_name(ds.results_dir.name) or (999, 999, 999)
        host_key = 0 if ds.label.startswith("laptop-") else 1 if ds.label.startswith("lab-") else 2
        return (version_key, host_key, ds.label)

    return sorted(datasets, key=sort_key)


def _pick_environment(all_envs: list[dict[str, Any]]) -> dict[str, Any]:
    for env in all_envs:
        if isinstance(env, dict) and env:
            return env
    return {}


def _normalize_openssl_version(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    match = re.search(r"(\\d+\\.\\d+\\.\\d+)", text)
    if match:
        return match.group(1)
    return text if text else None


def _select_environment(
    envs: list[dict[str, Any]],
    *,
    dataset_version: str | None = None,
) -> dict[str, Any]:
    if not envs:
        return {}

    keys = [
        "openssl_version",
        "oqs_provider_version",
        "platform",
        "kernel_version",
        "cpu_model",
    ]

    selected: dict[str, Any] = {}

    for key in keys:
        raw_values = [env.get(key) for env in envs if isinstance(env, dict)]
        normalized: list[str] = []

        if key == "openssl_version":
            if dataset_version:
                selected[key] = dataset_version
                continue
            for value in raw_values:
                norm = _normalize_openssl_version(value)
                if norm:
                    normalized.append(norm)
        else:
            for value in raw_values:
                text = str(value or "").strip()
                if text:
                    normalized.append(text)

        if not normalized:
            continue

        counts = defaultdict(int)
        for value in normalized:
            counts[value] += 1

        # Pick the most frequent value; break ties deterministically.
        top_value = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
        selected[key] = top_value

    return selected


def _merge_environments(envs: list[dict[str, Any]]) -> dict[str, Any]:
    if not envs:
        return {}

    merged: dict[str, Any] = {}

    def uniq_str(values: Iterable[Any]) -> list[str]:
        seen: list[str] = []
        for value in values:
            if value in (None, ""):
                continue
            text = str(value).strip()
            if text and text not in seen:
                seen.append(text)
        return seen

    keys = [
        "openssl_version",
        "oqs_provider_version",
        "platform",
        "kernel_version",
        "cpu_model",
    ]

    for key in keys:
        values = uniq_str(env.get(key) for env in envs)
        if not values:
            continue

        if key == "openssl_version":
            values.sort(
                key=lambda v: _openssl_version_key_from_name(f"openssl-{v}") or (999, 999, 999)
            )
            merged[key] = ", ".join(values)
        else:
            merged[key] = values[0] if len(values) == 1 else " / ".join(values)

    return merged


def _render_environment_table(
    env: dict[str, Any],
    *,
    context: str | None = None,
    label: str = "tab:pqc:env",
) -> str:
    fields = [
        ("OpenSSL versions", env.get("openssl_version")),
        ("oqs-provider version", env.get("oqs_provider_version")),
        ("Platform", env.get("platform")),
        ("Kernel", env.get("kernel_version")),
        ("CPU", env.get("cpu_model")),
    ]
    suffix = f" ({context})" if context else ""
    short_caption = f"Benchmark environment{suffix}"
    long_caption = f"Benchmark environment{suffix}."
    lines: list[str] = []
    lines.append("% Auto-generated by report/generate_pqc_report.py. Do not edit by hand.")
    lines.append(r"\begin{table}[H]")
    lines.append(r"    \sf")
    lines.append(r"    \small")
    lines.append(r"    \centering")
    lines.append(r"    \renewcommand{\arraystretch}{1.2}")
    lines.append(r"    \begin{tabular}{|l|l|}")
    lines.append(r"    \hline")
    lines.append(r"    \rowcolor{lightgray}\textbf{Field} & \textbf{Value} \\ \hline")
    for key, value in fields:
        val = "N/A" if value in (None, "") else str(value)
        lines.append(f"    {_latex_escape(key)} & {_latex_escape(val)} \\\\ \\hline")
    lines.append(r"    \end{tabular}")
    lines.append(rf"    \caption[{_latex_escape(short_caption)}]{{{_latex_escape(long_caption)}}}")
    lines.append(rf"    \label{{{label}}}")
    lines.append(r"\end{table}")
    lines.append("")
    return "\n".join(lines)


def _render_kem_table(
    rows: list[AlgoRow],
    *,
    context: str | None = None,
    label: str = "tab:pqc:kem",
) -> str:
    kem = [r for r in rows if (not r.is_tls) and r.type == "kem"]
    kem.sort(key=lambda r: r.algorithm)

    def op_cell(row: AlgoRow, op: str) -> str:
        s = row.operations.get(op)
        if not s:
            return "N/A"
        return _fmt_us(s.median_us)

    lines: list[str] = []
    lines.append("% Auto-generated by report/generate_pqc_report.py. Do not edit by hand.")
    lines.append(r"\begingroup")
    lines.append(r"\sf")
    lines.append(r"\small")
    lines.append(r"\setlength{\tabcolsep}{1.4pt}")
    lines.append(r"\renewcommand{\arraystretch}{1.2}")
    lines.append(r"\begin{longtable}{|p{5.8cm}|c|r|r|r|p{3.2cm}|}")
    lines.append(r"\hline")
    lines.append(
        r"\rowcolor{lightgray}\textbf{Algorithm} & \textbf{Hybrid} & "
        r"\shortstack{\textbf{Keygen}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Encaps}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Decaps}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Sizes}\\\textbf{pk/sk/ct (B)}} \\ \hline"
    )
    lines.append(r"\endfirsthead")
    lines.append(r"\hline")
    lines.append(
        r"\rowcolor{lightgray}\textbf{Algorithm} & \textbf{Hybrid} & "
        r"\shortstack{\textbf{Keygen}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Encaps}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Decaps}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Sizes}\\\textbf{pk/sk/ct (B)}} \\ \hline"
    )
    lines.append(r"\endhead")

    for r in kem:
        pk = r.sizes.get("public_key_bytes")
        sk = r.sizes.get("secret_key_bytes")
        ct = r.sizes.get("ciphertext_bytes")
        sizes = f"{pk}/{sk}/{ct}" if pk is not None and sk is not None and ct is not None else ""
        lines.append(
            " & ".join(
                [
                    r"\texttt{" + _latex_escape_code(_format_algo_display(r.algorithm)) + "}",
                    _fmt_bool(r.is_hybrid),
                    op_cell(r, "keygen"),
                    op_cell(r, "encaps"),
                    op_cell(r, "decaps"),
                    _latex_escape_code(sizes),
                ]
            )
            + r" \\ \hline"
        )
    suffix = f" ({context})" if context else ""
    short_caption = f"KEM microbenchmarks{suffix}"
    long_caption = (
        f"KEM microbenchmarks{suffix}. Latencies are median values in microseconds. "
        "Algorithm names are normalized for readability."
    )
    lines.append(rf"\caption[{_latex_escape(short_caption)}]{{{_latex_escape(long_caption)}}}")
    lines.append(rf"\label{{{label}}}")
    lines.append(r"\end{longtable}")
    lines.append(r"\endgroup")
    lines.append("")
    return "\n".join(lines)


def _render_signature_table(
    rows: list[AlgoRow],
    *,
    context: str | None = None,
    label: str = "tab:pqc:sig",
) -> str:
    sig = [r for r in rows if (not r.is_tls) and r.type == "signature"]
    sig.sort(key=lambda r: r.algorithm)

    def op_cell(row: AlgoRow, op: str) -> str:
        s = row.operations.get(op)
        if not s:
            return "N/A"
        return _fmt_us(s.median_us)

    lines: list[str] = []
    lines.append("% Auto-generated by report/generate_pqc_report.py. Do not edit by hand.")
    lines.append(r"\begingroup")
    lines.append(r"\sf")
    lines.append(r"\scriptsize")
    lines.append(r"\setlength{\tabcolsep}{1.4pt}")
    lines.append(r"\renewcommand{\arraystretch}{1.2}")
    lines.append(r"\begin{longtable}{|p{5.8cm}|c|r|r|r|p{3.2cm}|}")
    lines.append(r"\hline")
    lines.append(
        r"\rowcolor{lightgray}\textbf{Algorithm} & \textbf{Hybrid} & "
        r"\shortstack{\textbf{Keygen}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Sign}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Verify}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Sizes}\\\textbf{pk/sk/sig (B)}} \\ \hline"
    )
    lines.append(r"\endfirsthead")
    lines.append(r"\hline")
    lines.append(
        r"\rowcolor{lightgray}\textbf{Algorithm} & \textbf{Hybrid} & "
        r"\shortstack{\textbf{Keygen}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Sign}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Verify}\\\textbf{(µs)}} & "
        r"\shortstack{\textbf{Sizes}\\\textbf{pk/sk/sig (B)}} \\ \hline"
    )
    lines.append(r"\endhead")

    for r in sig:
        pk = r.sizes.get("public_key_bytes")
        sk = r.sizes.get("secret_key_bytes")
        sig_bytes = r.sizes.get("signature_bytes")
        sizes = (
            f"{pk}/{sk}/{sig_bytes}"
            if pk is not None and sk is not None and sig_bytes is not None
            else ""
        )
        lines.append(
            " & ".join(
                [
                    r"\texttt{" + _latex_escape_code(_format_algo_display(r.algorithm)) + "}",
                    _fmt_bool(r.is_hybrid),
                    op_cell(r, "keygen"),
                    op_cell(r, "sign"),
                    op_cell(r, "verify"),
                    _latex_escape_code(sizes),
                ]
            )
            + r" \\ \hline"
        )
    suffix = f" ({context})" if context else ""
    short_caption = f"Signature microbenchmarks{suffix}"
    long_caption = (
        f"Signature microbenchmarks{suffix}. Latencies are median values in microseconds. "
        "Algorithm names are normalized for readability."
    )
    lines.append(rf"\caption[{_latex_escape(short_caption)}]{{{_latex_escape(long_caption)}}}")
    lines.append(rf"\label{{{label}}}")
    lines.append(r"\end{longtable}")
    lines.append(r"\endgroup")
    lines.append("")
    return "\n".join(lines)


def _render_tls_table(
    rows: list[AlgoRow],
    tls_meta: dict[str, dict[str, Any]],
    *,
    context: str | None = None,
    label: str = "tab:pqc:tls",
) -> str:
    tls = [r for r in rows if r.is_tls]
    tls.sort(key=lambda r: r.algorithm)

    lines: list[str] = []
    lines.append("% Auto-generated by report/generate_pqc_report.py. Do not edit by hand.")
    lines.append(r"\begingroup")
    lines.append(r"\sf")
    lines.append(r"\scriptsize")
    lines.append(r"\setlength{\tabcolsep}{1.5pt}")
    lines.append(r"\renewcommand{\arraystretch}{1.2}")
    lines.append(r"\begin{longtable}{|p{7.0cm}|p{4.0cm}|r|c|}")
    lines.append(r"\hline")
    lines.append(
        r"\rowcolor{lightgray}\textbf{KEM} & \textbf{Signature} & "
        r"\shortstack{\textbf{Handshake}\\\textbf{(µs)}} & \textbf{OK/Fail} \\ \hline"
    )
    lines.append(r"\endfirsthead")
    lines.append(r"\hline")
    lines.append(
        r"\rowcolor{lightgray}\textbf{KEM} & \textbf{Signature} & "
        r"\shortstack{\textbf{Handshake}\\\textbf{(µs)}} & \textbf{OK/Fail} \\ \hline"
    )
    lines.append(r"\endhead")

    for r in tls:
        hs = r.operations.get("handshake")
        meta = tls_meta.get(r.algorithm, {})
        ok = meta.get("success_count") if isinstance(meta, dict) else None
        fail = meta.get("fail_count") if isinstance(meta, dict) else None
        ok_fail = f"{ok}/{fail}" if ok is not None and fail is not None else ""
        lines.append(
            " & ".join(
                [
                    r"\texttt{" + _latex_escape_code(_format_algo_display(r.tls_kem or "")) + "}",
                    r"\texttt{" + _latex_escape_code(_format_algo_display(r.tls_sig or "")) + "}",
                    _fmt_us(hs.median_us if hs else None),
                    _latex_escape(ok_fail),
                ]
            )
            + r" \\ \hline"
        )

    suffix = f" ({context})" if context else ""
    short_caption = f"TLS handshakes{suffix}"
    long_caption = (
        f"TLS 1.3 handshakes{suffix}. Latencies are median values in microseconds. "
        "Algorithm names are normalized for readability."
    )
    lines.append(rf"\caption[{_latex_escape(short_caption)}]{{{_latex_escape(long_caption)}}}")
    lines.append(rf"\label{{{label}}}")
    lines.append(r"\end{longtable}")
    lines.append(r"\endgroup")
    lines.append("")
    return "\n".join(lines)


def _render_http_table(
    http_runs: list[tuple[str, dict[str, Any]]],
    *,
    context: str | None = None,
    label: str = "tab:pqc:http",
) -> str:
    def metric_cell(metrics: dict[str, Any], key: str) -> str:
        m = metrics.get(key) or {}
        if not isinstance(m, dict):
            return "N/A"
        return _fmt_us(m.get("median_us"))

    rows = sorted(http_runs, key=lambda t: t[0])
    lines: list[str] = []
    lines.append("% Auto-generated by report/generate_pqc_report.py. Do not edit by hand.")
    lines.append(r"\begingroup")
    lines.append(r"\sf")
    lines.append(r"\scriptsize")
    lines.append(r"\setlength{\tabcolsep}{1.4pt}")
    lines.append(r"\renewcommand{\arraystretch}{1.2}")
    lines.append(r"\begin{longtable}{|p{3.8cm}|l|p{4.0cm}|p{1.8cm}|l|r|r|}")
    lines.append(r"\hline")
    lines.append(
        r"\rowcolor{lightgray}\textbf{Scenario} & \textbf{Client} & \textbf{Groups} & "
        r"\textbf{Cert Sig} & \textbf{Reuse} & \textbf{TTFB (µs)} & \textbf{Total (µs)} \\ \hline"
    )
    lines.append(r"\endfirsthead")
    lines.append(r"\hline")
    lines.append(
        r"\rowcolor{lightgray}\textbf{Scenario} & \textbf{Client} & \textbf{Groups} & "
        r"\textbf{Cert Sig} & \textbf{Reuse} & \textbf{TTFB (µs)} & \textbf{Total (µs)} \\ \hline"
    )
    lines.append(r"\endhead")

    for filename, data in rows:
        meta = data.get("metadata") or {}
        metrics = data.get("metrics") or {}
        tls_info = data.get("tls") or {}
        # Get signature_type from tls block (for full PQC benchmarks)
        sig_type = tls_info.get("signature_type") or ""
        lines.append(
            " & ".join(
                [
                    r"\texttt{" + _latex_escape_code(filename) + "}",
                    _latex_escape(str(meta.get("client") or "")),
                    r"\texttt{" + _latex_escape_code(str(meta.get("groups") or "")) + "}",
                    r"\texttt{" + _latex_escape_code(sig_type) + "}" if sig_type else "",
                    _latex_escape(str(meta.get("reuse") or "")),
                    metric_cell(metrics, "ttfb_us"),
                    metric_cell(metrics, "total_us"),
                ]
            )
            + r" \\ \hline"
        )

    suffix = f" ({context})" if context else ""
    short_caption = f"HTTP benchmarks{suffix}"
    long_caption = (
        f"HTTP benchmarks{suffix}. Latencies are median values in microseconds. "
        "Cert Sig shows the certificate signature algorithm for full PQC tests."
    )
    lines.append(rf"\caption[{_latex_escape(short_caption)}]{{{_latex_escape(long_caption)}}}")
    lines.append(rf"\label{{{label}}}")
    lines.append(r"\end{longtable}")
    lines.append(r"\endgroup")
    lines.append("")
    return "\n".join(lines)


def _render_http_overhead_table(
    http_runs: list[tuple[str, dict[str, Any]]],
    *,
    title: str,
    label: str,
) -> tuple[str, dict[str, float | str] | None]:
    def fmt_ms(value_us: float | None, *, digits: int = 1) -> str:
        if value_us is None:
            return "N/A"
        return f"{(float(value_us) / 1000.0):.{digits}f}\\,ms"

    def fmt_delta_ms(value_us: float | None, baseline_us: float | None, *, digits: int = 1) -> str:
        if value_us is None or baseline_us is None:
            return "N/A"
        delta_ms = (float(value_us) - float(baseline_us)) / 1000.0
        sign = "+" if delta_ms >= 0 else "-"
        return f"{sign}{abs(delta_ms):.{digits}f}\\,ms"

    def fmt_overhead_pct(value_us: float | None, baseline_us: float | None) -> str:
        if value_us is None or baseline_us is None:
            return "N/A"
        if baseline_us == 0:
            return "N/A"
        pct = ((float(value_us) - float(baseline_us)) / float(baseline_us)) * 100.0
        sign = "+" if pct >= 0 else "-"
        return f"{sign}{abs(pct):.1f}\\%"

    classical = _pick_http_median(http_runs, groups="X25519", sig_label="RSA-PSS")
    hybrid = _pick_http_median(http_runs, groups="X25519MLKEM768", sig_label="RSA-PSS")
    pure = _pick_http_median(http_runs, groups="mlkem768", sig_label="RSA-PSS")
    full = _pick_http_median(http_runs, groups="mlkem768", sig_prefix="ML-DSA")

    short_caption = f"HTTP performance overhead ({title})"
    long_caption = f"HTTP performance overhead compared to classical TLS ({title}). Values are TTFB medians in milliseconds."
    lines: list[str] = []
    lines.append(r"\begin{table}[H]")
    lines.append(r"    \sf")
    lines.append(r"    \small")
    lines.append(r"    \centering")
    lines.append(r"    \renewcommand{\arraystretch}{1.3}")
    lines.append(r"    \begin{tabular}{|l|r|r|r|}")
    lines.append(r"    \hline")
    lines.append(
        r"    \rowcolor{lightgray}\textbf{Configuration} & "
        r"\shortstack{\textbf{Median TTFB}\\\textbf{(ms)}} & "
        r"\shortstack{\textbf{$\Delta$ vs classical}\\\textbf{(ms)}} & "
        r"\textbf{$\Delta$ (\%)} \\ \hline"
    )
    lines.append(rf"    Classical (X25519 + RSA) & {fmt_ms(classical)} & --- & baseline \\ \hline")
    lines.append(
        rf"    Hybrid (X25519+ML-KEM768 + RSA) & {fmt_ms(hybrid)} & {fmt_delta_ms(hybrid, classical)} & {fmt_overhead_pct(hybrid, classical)} \\ \hline"
    )
    lines.append(
        rf"    Pure ML-KEM768 + RSA & {fmt_ms(pure)} & {fmt_delta_ms(pure, classical)} & {fmt_overhead_pct(pure, classical)} \\ \hline"
    )
    lines.append(
        rf"    Full PQC (ML-KEM768 + ML-DSA) & {fmt_ms(full)} & {fmt_delta_ms(full, classical)} & {fmt_overhead_pct(full, classical)} \\ \hline"
    )
    lines.append(r"    \end{tabular}")
    lines.append(rf"    \caption[{_latex_escape(short_caption)}]{{{_latex_escape(long_caption)}}}")
    lines.append(rf"    \label{{{label}}}")
    lines.append(r"\end{table}")
    lines.append("")
    data: dict[str, float | str] | None = None
    if classical is not None and hybrid is not None and classical != 0:
        data = {
            "title": title,
            "slug": label,
            "classical": classical,
            "hybrid": hybrid,
            "hybrid_tax_us": hybrid - classical,
            "hybrid_overhead_pct": ((hybrid - classical) / classical) * 100.0,
        }
    return "\n".join(lines), data


def _render_exec_summary_table(rows: list[dict[str, Any]]) -> str:
    def fmt_ms(value_us: float | None) -> str:
        if value_us is None:
            return "N/A"
        return f"{(float(value_us) / 1000.0):.1f} ms"

    def fmt_pct(value_us: float | None, baseline_us: float | None) -> str:
        if value_us is None or baseline_us in (None, 0):
            return "N/A"
        pct = ((float(value_us) - float(baseline_us)) / float(baseline_us)) * 100.0
        sign = "+" if pct >= 0 else "-"
        return f"{sign}{abs(pct):.1f}\\%"

    row_map = {(row["version"], row["host"]): row for row in rows}
    version_order = ("3.4.1", "3.5.0")
    host_order = ("Laptop", "Lab server")
    stack_labels = {
        "3.4.1": "OpenSSL 3.4.1 + oqs-provider",
        "3.5.0": "OpenSSL 3.5.0 (native)",
    }

    lines: list[str] = []
    lines.append("% Auto-generated by report/generate_pqc_report.py. Do not edit by hand.")
    lines.append(r"\begin{table}[H]")
    lines.append(r"    \small")
    lines.append(r"    \centering")
    lines.append(r"    \begin{tabular}{@{}llccc@{}}")
    lines.append(r"        \toprule")
    lines.append(
        r"        \textbf{Stack} & \textbf{Env} & \textbf{Classical} & \textbf{Hybrid} & \textbf{Full PQC} \\"
    )
    lines.append(r"        \midrule")

    for version in version_order:
        stack = stack_labels.get(version, f"OpenSSL {version}")
        for host in host_order:
            row = row_map.get((version, host))
            if not row:
                continue
            env = "Laptop" if host == "Laptop" else "Lab"
            classical_us = row.get("classical_us")
            hybrid_us = row.get("hybrid_us")
            full_us = row.get("full_us")
            lines.append(
                "        "
                + " & ".join(
                    [
                        _latex_escape(stack),
                        _latex_escape(env),
                        fmt_ms(classical_us),
                        fmt_pct(hybrid_us, classical_us),
                        fmt_pct(full_us, classical_us),
                    ]
                )
                + r" \\"
            )

    lines.append(r"        \bottomrule")
    lines.append(r"    \end{tabular}")
    lines.append(
        r"    \caption*{Hybrid = X25519+ML-KEM768, Full PQC = ML-KEM768 + ML-DSA-65. Classical = X25519 + RSA-PSS. N/A indicates not measured.}"
    )
    lines.append(r"\end{table}")
    lines.append("")
    return "\n".join(lines)


def _netem_p99_value(
    entries: list[NetemEntry],
    *,
    label: str,
    mtu: int,
    rtt_ms: float,
    loss_pct: float,
) -> float | None:
    target_rtt = _normalize_float(rtt_ms)
    target_loss = _normalize_float(loss_pct)
    target_label = label.strip().lower()
    for entry in entries:
        if entry.label != target_label:
            continue
        if entry.mtu != mtu:
            continue
        if entry.rtt_ms != target_rtt:
            continue
        if entry.loss_pct != target_loss:
            continue
        return entry.p99_ms
    return None


def _format_netem_cell(p99_loss0: float | None, p99_loss1: float | None) -> str:
    if p99_loss0 is None or p99_loss1 is None:
        return "N/A"
    if p99_loss0 <= 0:
        return "N/A"
    ratio = p99_loss1 / p99_loss0
    return f"{p99_loss0:.1f} $\\rightarrow$ {p99_loss1:.1f} ms ($\\times${ratio:.2f})"


def _render_netem_p99_table(
    *,
    entries_by_version: dict[str, list[NetemEntry]],
    host_short: str,
    host_long: str,
    label: str,
    rtt_ms: float = 50.0,
    mtu: int = 1500,
    loss0: float = 0.0,
    loss1: float = 1.0,
) -> str:
    versions = ("3.4.1", "3.5.0")
    header_host = _latex_escape(host_short)
    caption_host = _latex_escape(host_long)

    lines: list[str] = []
    lines.append("% Auto-generated by report/generate_pqc_report.py. Do not edit by hand.")
    lines.append(r"\begin{table}[H]")
    lines.append(r"    \small")
    lines.append(r"    \centering")
    lines.append(r"    \renewcommand{\arraystretch}{1.2}")
    lines.append(r"    \begin{tabular}{|l|c|c|}")
    lines.append(r"    \hline")
    lines.append(
        rf"    \rowcolor{{lightgray}}\textbf{{Config}} & \textbf{{OpenSSL {versions[0]} ({header_host})}} & "
        rf"\textbf{{OpenSSL {versions[1]} ({header_host})}} \\ \hline"
    )

    for raw_label, display in (
        ("classical", "Classical"),
        ("hybrid", "Hybrid"),
        ("fullpqc", "Full PQC"),
    ):
        entry34 = _netem_p99_value(
            entries_by_version.get(versions[0], []),
            label=raw_label,
            mtu=mtu,
            rtt_ms=rtt_ms,
            loss_pct=loss0,
        )
        entry35 = _netem_p99_value(
            entries_by_version.get(versions[1], []),
            label=raw_label,
            mtu=mtu,
            rtt_ms=rtt_ms,
            loss_pct=loss0,
        )
        entry34_loss1 = _netem_p99_value(
            entries_by_version.get(versions[0], []),
            label=raw_label,
            mtu=mtu,
            rtt_ms=rtt_ms,
            loss_pct=loss1,
        )
        entry35_loss1 = _netem_p99_value(
            entries_by_version.get(versions[1], []),
            label=raw_label,
            mtu=mtu,
            rtt_ms=rtt_ms,
            loss_pct=loss1,
        )

        lines.append(
            rf"    {display} & {_format_netem_cell(entry34, entry34_loss1)} & {_format_netem_cell(entry35, entry35_loss1)} \\ \hline"
        )

    lines.append(r"    \end{tabular}")
    lines.append(
        rf"    \caption[p99 inflation under loss ({caption_host})]{{p99 TTFB at RTT {int(rtt_ms)} ms, MTU {mtu}, comparing loss 0\% to loss 1\% ({caption_host}).}}"
    )
    lines.append(rf"    \label{{{label}}}")
    lines.append(r"\end{table}")
    lines.append("")
    return "\n".join(lines)


def _format_loss_pct(loss: float | None) -> str:
    if loss is None:
        return "N/A"
    text = f"{loss:g}"
    return f"{text}\\%"


def _max_fail_rate(entries: list[NetemEntry], label: str) -> float | None:
    rates = [
        entry.fail_rate
        for entry in entries
        if entry.label == label and isinstance(entry.fail_rate, (int, float))
    ]
    return max(rates) if rates else None


def _loss_threshold(
    entries: list[NetemEntry],
    *,
    label: str,
    mtu: int,
    rtt_ms: float,
    baseline_loss: float,
    threshold: float,
) -> float | None:
    baseline = _netem_p99_value(
        entries,
        label=label,
        mtu=mtu,
        rtt_ms=rtt_ms,
        loss_pct=baseline_loss,
    )
    if baseline is None or baseline <= 0:
        return None

    target_rtt = _normalize_float(rtt_ms)
    losses = sorted(
        {
            entry.loss_pct
            for entry in entries
            if entry.label == label and entry.mtu == mtu and entry.rtt_ms == target_rtt
        }
    )
    for loss in losses:
        if loss <= baseline_loss:
            continue
        value = _netem_p99_value(
            entries,
            label=label,
            mtu=mtu,
            rtt_ms=rtt_ms,
            loss_pct=loss,
        )
        if value is not None and value >= baseline * threshold:
            return loss
    return None


def _render_netem_breakpoints_table(
    *,
    entries_by_host_version: dict[str, dict[str, list[NetemEntry]]],
    label: str,
    mtu: int = 1500,
    rtt_ms: float = 50.0,
) -> str:
    lines: list[str] = []
    lines.append("% Auto-generated by report/generate_pqc_report.py. Do not edit by hand.")
    lines.append(r"\begin{table}[H]")
    lines.append(r"    \small")
    lines.append(r"    \centering")
    lines.append(r"    \renewcommand{\arraystretch}{1.2}")
    lines.append(r"    \begin{tabular}{|l|l|l|r|c|c|c|}")
    lines.append(r"    \hline")
    lines.append(
        r"    \rowcolor{lightgray}\textbf{System} & \textbf{OpenSSL} & \textbf{Config} & "
        r"\shortstack{\textbf{Baseline}\\\textbf{p99 (ms)}} & \textbf{Loss@2$\times$} & "
        r"\textbf{Loss@5$\times$} & \textbf{Max fail} \\ \hline"
    )

    host_order = ("Laptop", "Lab server")
    version_order = ("3.4.1", "3.5.0")
    config_rows = (("classical", "Classical"), ("hybrid", "Hybrid"), ("fullpqc", "Full PQC"))

    for host in host_order:
        versions = entries_by_host_version.get(host, {})
        for version in version_order:
            entries = versions.get(version)
            if not entries:
                continue
            for key, label_name in config_rows:
                baseline = _netem_p99_value(
                    entries,
                    label=key,
                    mtu=mtu,
                    rtt_ms=rtt_ms,
                    loss_pct=0.0,
                )
                loss_2x = _loss_threshold(
                    entries,
                    label=key,
                    mtu=mtu,
                    rtt_ms=rtt_ms,
                    baseline_loss=0.0,
                    threshold=2.0,
                )
                loss_5x = _loss_threshold(
                    entries,
                    label=key,
                    mtu=mtu,
                    rtt_ms=rtt_ms,
                    baseline_loss=0.0,
                    threshold=5.0,
                )
                max_fail = _max_fail_rate(entries, key)
                max_fail_pct = (
                    f"{max_fail * 100.0:.1f}\\%" if isinstance(max_fail, (int, float)) else "N/A"
                )
                baseline_str = f"{baseline:.1f}" if isinstance(baseline, (int, float)) else "N/A"

                lines.append(
                    r"    "
                    + " & ".join(
                        [
                            _latex_escape(host),
                            _latex_escape(version),
                            _latex_escape(label_name),
                            baseline_str,
                            _format_loss_pct(loss_2x),
                            _format_loss_pct(loss_5x),
                            max_fail_pct,
                        ]
                    )
                    + r" \\ \hline"
                )

    lines.append(r"    \end{tabular}")
    lines.append(
        rf"    \caption[Netem breakpoint summary]{{Netem breakpoint summary at MTU {mtu} and RTT {int(rtt_ms)} ms. "
        r"Baseline p99 is measured at 0\% loss; Loss@2$\times$ and Loss@5$\times$ report the smallest loss level "
        r"where p99 exceeds 2$\times$ or 5$\times$ the baseline for the same MTU/RTT slice. Max fail is the "
        r"highest failure rate observed anywhere in the netem grid for that configuration. Thresholds are based "
        r"on the discrete loss levels tested (0/0.1/0.5/1/2\%), so boundaries may fall between grid points.}"
    )
    lines.append(rf"    \label{{{label}}}")
    lines.append(r"\end{table}")
    lines.append("")
    return "\n".join(lines)


def _capacity_entry(
    entries: list[CapacityEntry],
    *,
    label: str,
    concurrency: int,
) -> CapacityEntry | None:
    target_label = label.strip().lower()
    for entry in entries:
        if entry.label != target_label:
            continue
        if entry.concurrency != concurrency:
            continue
        return entry
    return None


def _render_capacity_table(
    *,
    entries_by_version: dict[str, list[CapacityEntry]],
    host_long: str,
    label: str,
) -> str:
    versions = ("3.4.1", "3.5.0")
    caption_host = _latex_escape(host_long)

    def fmt_rps(value: float | None) -> str:
        return f"{value:.1f}" if isinstance(value, (int, float)) else "N/A"

    def fmt_ms(value: float | None) -> str:
        return f"{value:.1f}" if isinstance(value, (int, float)) else "N/A"

    lines: list[str] = []
    lines.append("% Auto-generated by report/generate_pqc_report.py. Do not edit by hand.")
    lines.append(r"\begin{table}[H]")
    lines.append(r"    \small")
    lines.append(r"    \centering")
    lines.append(r"    \renewcommand{\arraystretch}{1.2}")
    lines.append(r"    \begin{tabular}{|l|c|c|c|c|}")
    lines.append(r"    \hline")
    lines.append(
        rf"    \rowcolor{{lightgray}}\textbf{{Scenario}} & \textbf{{RPS {versions[0]}}} & "
        rf"\textbf{{p99 {versions[0]} (ms)}} & \textbf{{RPS {versions[1]}}} & \textbf{{p99 {versions[1]} (ms)}} \\ \hline"
    )

    for raw_label, display in (
        ("classical", "Classical"),
        ("hybrid", "Hybrid"),
        ("fullpqc", "Full PQC"),
    ):
        for concurrency in (1, 10, 50, 100, 200):
            entry34 = _capacity_entry(
                entries_by_version.get(versions[0], []),
                label=raw_label,
                concurrency=concurrency,
            )
            entry35 = _capacity_entry(
                entries_by_version.get(versions[1], []),
                label=raw_label,
                concurrency=concurrency,
            )
            lines.append(
                rf"    {display} ($c={concurrency}$) & {fmt_rps(entry34.rps if entry34 else None)} & "
                rf"{fmt_ms(entry34.p99_ms if entry34 else None)} & {fmt_rps(entry35.rps if entry35 else None)} & "
                rf"{fmt_ms(entry35.p99_ms if entry35 else None)} \\ \hline"
            )

    lines.append(r"    \end{tabular}")
    lines.append(
        rf"    \caption[Capacity and concurrency ({caption_host})]{{Capacity under concurrency on the {caption_host.lower()} (HTTP/1.1, 1000 samples). RPS = measured requests per second.}}"
    )
    lines.append(rf"    \label{{{label}}}")
    lines.append(r"\end{table}")
    lines.append("")
    return "\n".join(lines)


def _render_derived_insights(
    *,
    http_items: list[dict[str, float | str]],
    tls_items: list[dict[str, float | str]],
    rtt_ms: float = 50.0,
) -> str:
    def get_http(host: str, version: str) -> dict[str, float | str] | None:
        for item in http_items:
            if item.get("host") == host and item.get("version") == version:
                return item
        return None

    def ms(value_us: float | str | None) -> float | None:
        if not isinstance(value_us, (int, float)):
            return None
        return float(value_us) / 1000.0

    def fmt_ms(value_us: float | str | None, *, digits: int = 1) -> str:
        value_ms = ms(value_us)
        if value_ms is None:
            return "N/A"
        return f"{value_ms:.{digits}f}"

    def fmt_pct(value: float | None, *, digits: int = 1) -> str:
        if value is None:
            return "N/A"
        return f"{value:.{digits}f}\\%"

    def projected_overhead_pct(item: dict[str, float | str], *, rtt_us: float) -> float | None:
        classical = item.get("classical")
        tax = item.get("hybrid_tax_us")
        if not isinstance(classical, (int, float)) or not isinstance(tax, (int, float)):
            return None
        denom = float(classical) + rtt_us
        if denom <= 0:
            return None
        return (float(tax) / denom) * 100.0

    rtt_us = rtt_ms * 1000.0

    lines: list[str] = []
    lines.append(r"\subsubsection*{Derived Insights}")
    lines.append(
        r"\noindent The following tables are derived from the existing local HTTP and TLS datasets in \texttt{results/}."
    )
    lines.append(
        r"\noindent Because the measurements run locally, the RTT projection below illustrates how relative overhead shrinks when network latency dominates."
    )
    lines.append("")

    # Baseline normalization (hybrid HTTP).
    lines.append(r"\begin{table}[H]")
    lines.append(r"    \sf")
    lines.append(r"    \small")
    lines.append(r"    \centering")
    lines.append(r"    \renewcommand{\arraystretch}{1.2}")
    lines.append(r"    \begin{tabular}{|l|r|r|}")
    lines.append(r"    \hline")
    lines.append(
        r"    \rowcolor{lightgray}\textbf{System} & \textbf{Classical TTFB (ms)} & \textbf{Hybrid tax (ms)} \\ \hline"
    )
    for host in ("Laptop", "Lab server"):
        old = get_http(host, "3.4.1")
        new = get_http(host, "3.5.0")
        if not old or not new:
            continue
        classical_arrow = "N/A"
        if isinstance(old.get("classical"), (int, float)) and isinstance(
            new.get("classical"), (int, float)
        ):
            old_ms = float(old["classical"]) / 1000.0
            new_ms = float(new["classical"]) / 1000.0
            classical_arrow = rf"{old_ms:.1f} $\rightarrow$ {new_ms:.1f} ({new_ms - old_ms:+.1f})"

        hybrid_arrow = "N/A"
        if isinstance(old.get("hybrid_tax_us"), (int, float)) and isinstance(
            new.get("hybrid_tax_us"), (int, float)
        ):
            old_tax = float(old["hybrid_tax_us"]) / 1000.0
            new_tax = float(new["hybrid_tax_us"]) / 1000.0
            hybrid_arrow = rf"{old_tax:.1f} $\rightarrow$ {new_tax:.1f} ({new_tax - old_tax:+.1f})"

        lines.append(
            r"    "
            + " & ".join(
                [
                    _latex_escape(host),
                    classical_arrow,
                    hybrid_arrow,
                ]
            )
            + r" \\ \hline"
        )
    lines.append(r"    \end{tabular}")
    lines.append(
        r"    \caption[Derived baseline normalization]{Baseline normalization for hybrid HTTP TTFB (X25519+ML-KEM-768 + RSA). "
        r"Hybrid tax is the absolute delta between hybrid and classical medians within the same OpenSSL version. "
        r"Arrows show 3.4.1 $\rightarrow$ 3.5.0.}"
    )
    lines.append(r"    \label{tab:pqc:derived:baseline-normalization}")
    lines.append(r"\end{table}")
    lines.append("")

    # RTT projection (illustrative).
    lines.append(r"\begin{table}[H]")
    lines.append(r"    \sf")
    lines.append(r"    \small")
    lines.append(r"    \centering")
    lines.append(r"    \renewcommand{\arraystretch}{1.2}")
    lines.append(r"    \begin{tabular}{|l|l|r|r|}")
    lines.append(r"    \hline")
    lines.append(
        rf"    \rowcolor{{lightgray}}\textbf{{System}} & \textbf{{OpenSSL}} & \textbf{{Measured overhead}} & \textbf{{Projected overhead (+{int(rtt_ms)}ms RTT)}} \\ \hline"
    )
    for host in ("Laptop", "Lab server"):
        for version in ("3.4.1", "3.5.0"):
            item = get_http(host, version)
            if not item:
                continue
            measured = item.get("hybrid_overhead_pct")
            measured_pct = float(measured) if isinstance(measured, (int, float)) else None
            proj_pct = projected_overhead_pct(item, rtt_us=rtt_us)
            lines.append(
                r"    "
                + " & ".join(
                    [
                        _latex_escape(host),
                        _latex_escape(version),
                        fmt_pct(measured_pct),
                        fmt_pct(proj_pct),
                    ]
                )
                + r" \\ \hline"
            )
    lines.append(r"    \end{tabular}")
    lines.append(
        rf"    \caption[Derived RTT projection]{{\textbf{{Illustrative (not a benchmark):}} Projection of hybrid overhead if local TTFB is dominated by an additional {int(rtt_ms)}\,ms network RTT. "
        r"This adds RTT to both classical and hybrid medians and does not model packet loss or retransmissions.}"
    )
    lines.append(r"    \label{tab:pqc:derived:rtt-projection}")
    lines.append(r"\end{table}")
    lines.append("")

    # Single-thread handshake capacity estimate (derived).
    lines.append(r"\begin{table}[H]")
    lines.append(r"    \sf")
    lines.append(r"    \small")
    lines.append(r"    \centering")
    lines.append(r"    \renewcommand{\arraystretch}{1.2}")
    lines.append(r"    \begin{tabular}{|l|l|r|r|}")
    lines.append(r"    \hline")
    lines.append(
        r"    \rowcolor{lightgray}\textbf{System} & \textbf{OpenSSL} & \textbf{TLS handshake (ms)} & \textbf{Est. sequential handshakes/s} \\ \hline"
    )
    for item in sorted(tls_items, key=lambda d: (str(d.get("host")), str(d.get("version")))):
        hs_us = item.get("handshake_us")
        if not isinstance(hs_us, (int, float)) or hs_us <= 0:
            continue
        hs_ms = hs_us / 1000.0
        hps = 1_000_000.0 / float(hs_us)
        lines.append(
            r"    "
            + " & ".join(
                [
                    _latex_escape(str(item.get("host") or "")),
                    _latex_escape(str(item.get("version") or "")),
                    f"{hs_ms:.1f}",
                    f"{hps:.1f}",
                ]
            )
            + r" \\ \hline"
        )
    lines.append(r"    \end{tabular}")
    lines.append(
        r"    \caption[Derived TLS throughput estimate]{\textbf{Illustrative (not a benchmark):} Back-of-envelope TLS throughput estimate from the median handshake time for "
        r"\texttt{X25519MLKEM768} with an \texttt{ML-DSA-65} server certificate (single-thread, sequential). "
        r"This does not measure concurrency.}"
    )
    lines.append(r"    \label{tab:pqc:derived:tls-throughput}")
    lines.append(r"\end{table}")
    lines.append("")

    return "\n".join(lines).strip() + "\n"


def _try_generate_figures(
    rows: list[AlgoRow],
    http_runs: list[tuple[str, dict[str, Any]]],
    out_dir: Path,
) -> list[Path]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return []

    out_dir.mkdir(parents=True, exist_ok=True)

    plt.style.use(
        "seaborn-v0_8-whitegrid"
    ) if "seaborn-v0_8-whitegrid" in plt.style.available else None

    # Use the same colors across figures.
    COLORS = {
        "classical": "#2ecc71",  # green
        "hybrid": "#3498db",  # blue
        "pqc": "#9b59b6",  # purple
        "fullpqc": "#e74c3c",  # red
    }

    def top_barh(
        items: list[tuple[str, float]],
        title: str,
        xlabel: str,
        out_name: str,
        top_n: int = 20,
        color: str = "#3498db",
    ) -> Path | None:
        items = sorted(items, key=lambda t: t[1])[:top_n]
        if not items:
            return None

        labels = [_format_algo_display(a) for a, _ in items][::-1]
        values = [v for _, v in items][::-1]

        fig_h = max(3.5, 0.28 * len(labels) + 1.0)
        fig, ax = plt.subplots(figsize=(10, fig_h))
        bars = ax.barh(labels, values, color=color, edgecolor="white", linewidth=0.5)
        ax.set_title(title, fontsize=12, fontweight="bold", pad=10)
        ax.set_xlabel(xlabel, fontsize=10)
        ax.grid(axis="x", linestyle=":", linewidth=0.6, alpha=0.6)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        for bar, val in zip(bars, values):
            ax.text(
                val + max(values) * 0.01,
                bar.get_y() + bar.get_height() / 2,
                f"{val:.0f}",
                va="center",
                fontsize=7,
                color="#555",
            )

        for tick in ax.get_yticklabels():
            tick.set_fontsize(8)
        fig.tight_layout()

        out_path = out_dir / out_name
        fig.savefig(out_path, bbox_inches="tight", dpi=150)
        plt.close(fig)
        return out_path

    def http_comparison_chart(
        http_data: list[tuple[str, dict[str, Any]]],
        out_name: str,
    ) -> Path | None:
        """Generate a comparison bar chart for HTTP benchmarks."""
        # Extract key scenarios for comparison
        scenarios: list[tuple[str, float, str]] = []  # (label, ttfb, category)

        for filename, data in http_data:
            if "playwright" in filename.lower():
                continue

            metrics = data.get("metrics") or {}
            ttfb = metrics.get("ttfb_us", {})
            if not isinstance(ttfb, dict):
                continue
            median = ttfb.get("median_us")
            if median is None:
                continue

            meta = data.get("metadata") or {}
            if str(meta.get("client") or "") != "openssl":
                continue
            if str(meta.get("reuse") or "") not in ("", "none"):
                continue
            # Prefer the canonical openssl scenarios for the main comparison (avoid duplicate native runs).
            if "http-openssl" not in filename.lower():
                continue

            groups = str(meta.get("groups") or "")
            tls_info = data.get("tls") or {}
            sig_type = tls_info.get("signature_type") or ""

            # Categorize and create readable labels.
            sig_label = _normalize_http_sig(str(sig_type))
            if groups == "X25519":
                label = "Classical\n(X25519)"
                category = "classical"
            elif groups == "X25519MLKEM768":
                label = "Hybrid\n(X25519+ML-KEM768)"
                category = "hybrid"
            elif groups == "mlkem768" and sig_label == "RSA-PSS":
                label = "Pure ML-KEM768\n(RSA cert)"
                category = "pqc"
            elif groups == "mlkem768" and sig_label.startswith("ML-DSA"):
                label = f"Full PQC\n(ML-KEM768+{sig_label})"
                category = "fullpqc"
            else:
                continue  # Skip other scenarios for main comparison

            scenarios.append((label, float(median), category))

        if len(scenarios) < 2:
            return None

        # Sort by latency for visual comparison
        scenarios.sort(key=lambda x: x[1])

        labels = [s[0] for s in scenarios]
        values = [s[1] for s in scenarios]
        colors = [COLORS.get(s[2], "#999") for s in scenarios]

        fig, ax = plt.subplots(figsize=(10, 5))
        bars = ax.bar(labels, values, color=colors, edgecolor="white", linewidth=1)

        ax.set_title(
            "HTTP Latency Comparison: Classical vs PQC", fontsize=14, fontweight="bold", pad=15
        )
        ax.set_ylabel("Median TTFB (µs)", fontsize=11)
        ax.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                val + max(values) * 0.02,
                f"{val / 1000:.1f}ms",
                ha="center",
                va="bottom",
                fontsize=10,
                fontweight="bold",
            )

        # Add baseline reference line (classical)
        classical_val = next((v for l, v, c in scenarios if c == "classical"), None)
        if classical_val:
            ax.axhline(y=classical_val, color="#2ecc71", linestyle="--", linewidth=1.5, alpha=0.7)
            ax.text(
                len(labels) - 0.5,
                classical_val,
                "baseline",
                va="bottom",
                ha="right",
                fontsize=9,
                color="#27ae60",
            )

        # Add overhead percentage annotations
        if classical_val:
            for i, (label, val, cat) in enumerate(scenarios):
                if cat != "classical":
                    overhead = ((val - classical_val) / classical_val) * 100
                    ax.text(
                        i,
                        val / 2,
                        f"+{overhead:.1f}%",
                        ha="center",
                        va="center",
                        fontsize=9,
                        color="white",
                        fontweight="bold",
                    )

        plt.xticks(fontsize=9)
        fig.tight_layout()

        out_path = out_dir / out_name
        fig.savefig(out_path, bbox_inches="tight", dpi=150)
        plt.close(fig)
        return out_path

    kem_encaps: list[tuple[str, float]] = []
    sig_sign: list[tuple[str, float]] = []
    tls_hs: list[tuple[str, float]] = []

    for r in rows:
        if r.is_tls:
            hs = r.operations.get("handshake")
            if hs and isinstance(hs.median_us, (int, float)):
                tls_hs.append((r.algorithm, float(hs.median_us)))
            continue

        if r.type == "kem":
            enc = r.operations.get("encaps")
            if enc and isinstance(enc.median_us, (int, float)):
                kem_encaps.append((r.algorithm, float(enc.median_us)))
        elif r.type == "signature":
            s = r.operations.get("sign")
            if s and isinstance(s.median_us, (int, float)):
                sig_sign.append((r.algorithm, float(s.median_us)))

    created: list[Path] = []
    for maybe in (
        top_barh(
            kem_encaps,
            "KEM Encapsulation Latency (Top 20, Lower is Better)",
            "Median latency (µs)",
            "kem-encaps-median.pdf",
            color="#3498db",
        ),
        top_barh(
            sig_sign,
            "Signature Signing Latency (Top 20, Lower is Better)",
            "Median latency (µs)",
            "sig-sign-median.pdf",
            color="#9b59b6",
        ),
        top_barh(
            tls_hs,
            "TLS 1.3 Handshake Latency (Top 20, Lower is Better)",
            "Median latency (µs)",
            "tls-handshake-median.pdf",
            color="#e74c3c",
        ),
        http_comparison_chart(http_runs, "http-overhead-comparison.pdf"),
    ):
        if maybe is not None:
            created.append(maybe)
    return created


def _netem_riskmap_values(entries: list[NetemEntry], *, mtu: int) -> list[float]:
    by_label: dict[str, list[NetemEntry]] = defaultdict(list)
    for entry in entries:
        if entry.mtu != mtu:
            continue
        by_label[entry.label].append(entry)

    values: list[float] = []
    for items in by_label.values():
        baseline = {entry.rtt_ms: entry.p99_ms for entry in items if entry.loss_pct == 0.0}
        for entry in items:
            base = baseline.get(entry.rtt_ms)
            if not base or base <= 0:
                continue
            values.append(entry.p99_ms / base)
    return values


def _try_generate_netem_riskmap(
    entries: list[NetemEntry],
    out_dir: Path,
    *,
    title: str,
    mtu: int = 1500,
    vmin: float | None = None,
    vmax: float | None = None,
) -> Path | None:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except Exception:
        return None

    by_label: dict[str, list[NetemEntry]] = defaultdict(list)
    for entry in entries:
        if entry.mtu != mtu:
            continue
        by_label[entry.label].append(entry)

    labels = ("classical", "hybrid", "fullpqc")
    if not any(by_label.values()):
        return None

    out_dir.mkdir(parents=True, exist_ok=True)

    fig = plt.figure(figsize=(12.6, 3.6))
    grid = fig.add_gridspec(1, 4, width_ratios=[1, 1, 1, 0.05], wspace=0.12)
    axes = [fig.add_subplot(grid[0, 0])]
    axes.append(fig.add_subplot(grid[0, 1], sharey=axes[0]))
    axes.append(fig.add_subplot(grid[0, 2], sharey=axes[0]))
    cax = fig.add_subplot(grid[0, 3])
    fig.suptitle(
        f"Netem risk map (MTU {mtu}) — {title}",
        fontsize=11,
        fontweight="bold",
        y=0.98,
    )

    # Determine global min/max for color scaling.
    all_values: list[float] = []
    label_data: dict[str, tuple[list[float], list[float], np.ndarray]] = {}

    for label in labels:
        items = by_label.get(label, [])
        if not items:
            continue

        rtts = sorted({entry.rtt_ms for entry in items})
        losses = sorted({entry.loss_pct for entry in items})
        baseline = {entry.rtt_ms: entry.p99_ms for entry in items if entry.loss_pct == 0.0}

        data = np.full((len(losses), len(rtts)), np.nan, dtype=float)
        for entry in items:
            base = baseline.get(entry.rtt_ms)
            if not base or base <= 0:
                continue
            if entry.loss_pct not in losses or entry.rtt_ms not in rtts:
                continue
            row = losses.index(entry.loss_pct)
            col = rtts.index(entry.rtt_ms)
            value = entry.p99_ms / base
            data[row, col] = value
            all_values.append(value)

        label_data[label] = (rtts, losses, data)

    if not all_values:
        return None

    if vmin is None:
        vmin = min(all_values)
    if vmax is None:
        vmax = max(all_values)
    vmax = max(vmax, 2.0)

    last_im = None
    title_map = {
        "classical": "Classical",
        "hybrid": "Hybrid",
        "fullpqc": "Full PQC",
    }
    for ax, label in zip(axes, labels):
        if label not in label_data:
            ax.axis("off")
            continue

        rtts, losses, data = label_data[label]
        im = ax.imshow(
            data,
            origin="lower",
            aspect="auto",
            vmin=vmin,
            vmax=vmax,
            cmap="magma",
        )
        last_im = im
        ax.set_title(title_map.get(label, label.title()), fontsize=9)
        ax.set_xticks(range(len(rtts)))
        ax.set_xticklabels([f"{int(r)}" for r in rtts], fontsize=8)
        ax.set_yticks(range(len(losses)))
        if ax is axes[0]:
            ax.set_yticklabels([f"{l:g}" for l in losses], fontsize=8)
        else:
            ax.set_yticklabels([])
        ax.set_xlabel("RTT (ms)", fontsize=8)
        if ax is axes[0]:
            ax.set_ylabel("Loss (%)", fontsize=8)

        # Contour for the 2x boundary.
        try:
            ax.contour(
                data,
                levels=[2.0],
                colors="white",
                linewidths=1.0,
                origin="lower",
            )
        except Exception:
            pass

    if last_im is None:
        return None

    cbar = fig.colorbar(last_im, cax=cax)
    cbar.set_label("p99 inflation vs 0% loss", fontsize=8)
    cbar.ax.tick_params(labelsize=8)

    fig.subplots_adjust(top=0.88, bottom=0.2, left=0.06, right=0.96)
    out_path = out_dir / f"netem-riskmap-mtu{mtu}.pdf"
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def _build_pdf(alcazar_dir: Path) -> None:
    latexmk_cmd = [
        "latexmk",
        "-shell-escape",
        "-synctex=1",
        "-interaction=nonstopmode",
        "-file-line-error",
        "-pdf",
        "main",
    ]

    subprocess.run(latexmk_cmd, cwd=str(alcazar_dir), check=True)

    # latexmk versions vary in their glossary integration. Run makeglossaries explicitly if needed.
    if (alcazar_dir / "main.glo").exists():
        subprocess.run(["makeglossaries", "main"], cwd=str(alcazar_dir), check=True)
        subprocess.run(latexmk_cmd, cwd=str(alcazar_dir), check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", type=Path, default=Path("results"))
    parser.add_argument("--alcazar-dir", type=Path, default=Path("report/alcazar"))
    parser.add_argument(
        "--no-figures",
        action="store_true",
        help="Skip matplotlib figure generation",
    )
    parser.add_argument("--build", action="store_true", help="Run latexmk to build the PDF")
    args = parser.parse_args()

    results_dir: Path = args.results_dir
    alcazar_dir: Path = args.alcazar_dir

    if not results_dir.exists():
        raise SystemExit(f"results dir not found: {results_dir}")
    if not alcazar_dir.exists():
        raise SystemExit(f"alcazar dir not found: {alcazar_dir}")

    datasets = _discover_datasets(results_dir)
    if not datasets:
        raise SystemExit(f"no datasets found under: {results_dir}")

    def figure_block(rel_path: str, short_caption: str, caption: str, label: str) -> str:
        return "\n".join(
            [
                rf"\IfFileExists{{{rel_path}}}{{%",
                r"    \begin{figure}[H]",
                r"        \centering",
                rf"        \includegraphics[width=\linewidth]{{{rel_path}}}",
                rf"        \caption[{_latex_escape(short_caption)}]{{{caption}}}",
                rf"        \label{{{label}}}",
                r"    \end{figure}%",
                r"}{}",
                "",
            ]
        )

    parsed: list[
        tuple[
            Dataset,
            dict[str, Any],
            list[AlgoRow],
            dict[str, dict[str, Any]],
            list[tuple[str, dict[str, Any]]],
            list[NetemEntry],
            list[CapacityEntry],
        ]
    ] = []
    packetization_observations: list[PacketizationObservation] = []

    for ds in datasets:
        micro_files: list[dict[str, Any]] = []
        http_runs: list[tuple[str, dict[str, Any]]] = []
        envs: list[dict[str, Any]] = []
        tls_meta: dict[str, dict[str, Any]] = {}
        host = (
            "Laptop"
            if ds.label.startswith("laptop-")
            else "Lab server"
            if ds.label.startswith("lab-")
            else ds.title
        )

        for path in _iter_json_files(ds.results_dir):
            data = _load_json(path)

            if _is_packetization_json(data):
                packetization_observations.extend(
                    _parse_packetization_observations(data, host=host)
                )
                continue

            env = data.get("environment")
            if isinstance(env, dict) and env:
                envs.append(env)

            if _is_microbench_json(data):
                # Skip native microbench duplicates; keep HTTP native runs (different schema).
                if path.name.endswith("-native.json"):
                    continue
                micro_files.append(data)
                for td in data.get("tls_details") or []:
                    if not isinstance(td, dict):
                        continue
                    kem = td.get("kem_algorithm")
                    sig = td.get("sig_algorithm")
                    if not kem:
                        continue
                    algo = f"{kem}+{sig}" if sig else str(kem)
                    tls_meta[algo] = td

            if isinstance(data.get("metrics"), dict) and isinstance(data.get("samples"), list):
                http_runs.append((path.name, data))

        rows: list[AlgoRow] = []
        for mf in micro_files:
            rows.extend(_parse_algo_rows(mf))

        netem_entries = _parse_netem_entries(http_runs)
        capacity_entries = _parse_capacity_entries(http_runs)
        dataset_version = ds.results_dir.name.replace("openssl-", "", 1)
        selected_env = _select_environment(envs, dataset_version=dataset_version)
        parsed.append(
            (ds, selected_env, rows, tls_meta, http_runs, netem_entries, capacity_entries)
        )

    out_tables_dir = alcazar_dir / "text/chapters/generated"
    multi = len(parsed) > 1

    env_parts: list[str] = []
    kem_parts: list[str] = []
    sig_parts: list[str] = []
    tls_parts: list[str] = []
    http_parts: list[str] = []
    overhead_parts: list[str] = []
    kem_parts_by_host: dict[str, list[str]] = defaultdict(list)
    sig_parts_by_host: dict[str, list[str]] = defaultdict(list)
    tls_parts_by_host: dict[str, list[str]] = defaultdict(list)
    http_parts_by_host: dict[str, list[str]] = defaultdict(list)
    native_vs_provider: list[dict[str, float | str]] = []

    riskmap_limits: dict[tuple[str, int], tuple[float, float]] = {}
    riskmap_values: dict[tuple[str, int], list[float]] = defaultdict(list)
    for ds, _env, _rows, _tls_meta, _http_runs, netem_entries, _capacity_entries in parsed:
        if not netem_entries:
            continue
        version_match = _openssl_version_key_from_name(ds.results_dir.name)
        version = (
            ".".join(str(p) for p in version_match)
            if version_match is not None
            else ds.results_dir.name.replace("openssl-", "")
        )
        key = (version, 1500)
        riskmap_values[key].extend(_netem_riskmap_values(netem_entries, mtu=1500))

    for key, values in riskmap_values.items():
        if not values:
            continue
        vmin = min(values)
        vmax = max(values)
        vmax = max(vmax, 2.0)
        riskmap_limits[key] = (vmin, vmax)
    tls_summary: list[dict[str, float | str]] = []
    exec_summary_rows: list[dict[str, Any]] = []

    env_by_host: dict[str, list[dict[str, Any]]] = {}

    for ds, env, rows, tls_meta, http_runs, netem_entries, _capacity_entries in parsed:
        host = (
            "Laptop"
            if ds.label.startswith("laptop-")
            else "Lab server"
            if ds.label.startswith("lab-")
            else ds.title
        )
        version_title = ds.results_dir.name.replace("openssl-", "OpenSSL ", 1)
        host_section = rf"\subsection*{{{_latex_escape(version_title)}}}"

        if multi:
            heading = rf"\subsection*{{{_latex_escape(ds.title)}}}"
            kem_parts.append(heading)
            sig_parts.append(heading)
            tls_parts.append(heading)
            http_parts.append(heading)
            overhead_parts.append(rf"\subsubsection*{{{_latex_escape(ds.title)}}}")

        host = (
            "Laptop"
            if ds.label.startswith("laptop-")
            else "Lab server"
            if ds.label.startswith("lab-")
            else ds.title
        )
        env_by_host.setdefault(host, []).append(env)

        kem_parts_by_host[host].append(host_section)
        kem_parts.append(_render_kem_table(rows, context=ds.title, label=f"tab:pqc:kem:{ds.slug}"))
        kem_parts_by_host[host].append(
            _render_kem_table(rows, context=version_title, label=f"tab:pqc:kem:{ds.slug}")
        )
        kem_parts.append(
            figure_block(
                f"figures/pqc/{ds.slug}/kem-encaps-median.pdf",
                f"KEM encapsulation latency ({ds.title})",
                f"Median KEM encapsulation latency on {ds.title} (lower is better). Bars show \\si{{\\micro\\second}}.",
                f"fig:pqc:kem:encaps:{ds.slug}",
            )
        )
        kem_parts_by_host[host].append(
            figure_block(
                f"figures/pqc/{ds.slug}/kem-encaps-median.pdf",
                f"KEM encapsulation latency ({version_title})",
                f"Median KEM encapsulation latency on {version_title} (lower is better). Bars show \\si{{\\micro\\second}}.",
                f"fig:pqc:kem:encaps:{ds.slug}",
            )
        )

        sig_parts_by_host[host].append(host_section)
        sig_parts.append(
            _render_signature_table(rows, context=ds.title, label=f"tab:pqc:sig:{ds.slug}")
        )
        sig_parts_by_host[host].append(
            _render_signature_table(rows, context=version_title, label=f"tab:pqc:sig:{ds.slug}")
        )
        sig_parts.append(
            figure_block(
                f"figures/pqc/{ds.slug}/sig-sign-median.pdf",
                f"Signature signing latency ({ds.title})",
                f"Median signature signing latency on {ds.title} (lower is better). Values are in \\si{{\\micro\\second}}.",
                f"fig:pqc:sig:sign:{ds.slug}",
            )
        )
        sig_parts_by_host[host].append(
            figure_block(
                f"figures/pqc/{ds.slug}/sig-sign-median.pdf",
                f"Signature signing latency ({version_title})",
                f"Median signature signing latency on {version_title} (lower is better). Values are in \\si{{\\micro\\second}}.",
                f"fig:pqc:sig:sign:{ds.slug}",
            )
        )

        tls_parts_by_host[host].append(host_section)
        tls_parts.append(
            _render_tls_table(rows, tls_meta, context=ds.title, label=f"tab:pqc:tls:{ds.slug}")
        )
        tls_parts_by_host[host].append(
            _render_tls_table(rows, tls_meta, context=version_title, label=f"tab:pqc:tls:{ds.slug}")
        )
        tls_parts.append(
            figure_block(
                f"figures/pqc/{ds.slug}/tls-handshake-median.pdf",
                f"TLS 1.3 handshake latency ({ds.title})",
                f"Median TLS 1.3 handshake latency on {ds.title} (lower is better). Values are in \\si{{\\micro\\second}}.",
                f"fig:pqc:tls:handshake:{ds.slug}",
            )
        )
        tls_parts_by_host[host].append(
            figure_block(
                f"figures/pqc/{ds.slug}/tls-handshake-median.pdf",
                f"TLS 1.3 handshake latency ({version_title})",
                f"Median TLS 1.3 handshake latency on {version_title} (lower is better). Values are in \\si{{\\micro\\second}}.",
                f"fig:pqc:tls:handshake:{ds.slug}",
            )
        )

        http_parts_by_host[host].append(host_section)
        http_parts.append(
            _render_http_table(http_runs, context=ds.title, label=f"tab:pqc:http:{ds.slug}")
        )
        http_parts_by_host[host].append(
            _render_http_table(http_runs, context=version_title, label=f"tab:pqc:http:{ds.slug}")
        )
        http_parts.append(
            figure_block(
                f"figures/pqc/{ds.slug}/http-overhead-comparison.pdf",
                f"HTTP latency comparison ({ds.title})",
                f"Median HTTP total latency on {ds.title} by configuration (lower is better). Values are in \\si{{\\micro\\second}}.",
                f"fig:pqc:http:comparison:{ds.slug}",
            )
        )
        http_parts_by_host[host].append(
            figure_block(
                f"figures/pqc/{ds.slug}/http-overhead-comparison.pdf",
                f"HTTP latency comparison ({version_title})",
                f"Median HTTP total latency on {version_title} by configuration (lower is better). Values are in \\si{{\\micro\\second}}.",
                f"fig:pqc:http:comparison:{ds.slug}",
            )
        )

        overhead_tex, overhead_data = _render_http_overhead_table(
            http_runs,
            title=ds.title,
            label=f"tab:pqc:overhead:{ds.slug}",
        )
        overhead_parts.append(overhead_tex)
        if overhead_data:
            host = (
                "Laptop"
                if ds.label.startswith("laptop-")
                else "Lab server"
                if ds.label.startswith("lab-")
                else ds.title
            )
            version_match = _openssl_version_key_from_name(ds.results_dir.name)
            version = (
                ".".join(str(p) for p in version_match)
                if version_match is not None
                else ds.results_dir.name.replace("openssl-", "")
            )
            overhead_data["host"] = host
            overhead_data["version"] = version
            overhead_data["dataset"] = ds.slug
            overhead_data["label"] = ds.label
            native_vs_provider.append(overhead_data)

        exec_classical = _pick_http_median(http_runs, groups="X25519", sig_label="RSA-PSS")
        exec_hybrid = _pick_http_median(http_runs, groups="X25519MLKEM768", sig_label="RSA-PSS")
        exec_full = _pick_http_median(http_runs, groups="mlkem768", sig_prefix="ML-DSA")
        version = ds.results_dir.name.replace("openssl-", "")
        exec_summary_rows.append(
            {
                "host": host,
                "version": version,
                "classical_us": exec_classical,
                "hybrid_us": exec_hybrid,
                "full_us": exec_full,
            }
        )

        # Capture median handshake time for the recommended hybrid group (derived throughput estimate).
        for r in rows:
            if not r.is_tls:
                continue
            if (r.tls_kem or "") != "X25519MLKEM768":
                continue
            if (r.tls_sig or "") != "mldsa65":
                continue
            hs = r.operations.get("handshake")
            if hs and isinstance(hs.median_us, (int, float)):
                host = (
                    "Laptop"
                    if ds.label.startswith("laptop-")
                    else "Lab server"
                    if ds.label.startswith("lab-")
                    else ds.title
                )
                version_match = _openssl_version_key_from_name(ds.results_dir.name)
                version = (
                    ".".join(str(p) for p in version_match)
                    if version_match is not None
                    else ds.results_dir.name.replace("openssl-", "")
                )
                tls_summary.append(
                    {
                        "host": host,
                        "version": version,
                        "handshake_us": float(hs.median_us),
                    }
                )
                break

        if not args.no_figures:
            _try_generate_figures(rows, http_runs, alcazar_dir / "figures/pqc" / ds.slug)
            version_match = _openssl_version_key_from_name(ds.results_dir.name)
            version = (
                ".".join(str(p) for p in version_match)
                if version_match is not None
                else ds.results_dir.name.replace("openssl-", "")
            )
            scale = riskmap_limits.get((version, 1500))
            _try_generate_netem_riskmap(
                netem_entries,
                alcazar_dir / "figures/pqc" / ds.slug,
                title=ds.title,
                mtu=1500,
                vmin=scale[0] if scale else None,
                vmax=scale[1] if scale else None,
            )

    # Environment tables: same host hardware/OS across OpenSSL versions, so deduplicate by host.
    for host in ("Laptop", "Lab server"):
        envs = env_by_host.get(host)
        if not envs:
            continue
        env_parts.append(rf"\subsection*{{{_latex_escape(host)}}}")
        env_parts.append(
            _render_environment_table(
                _merge_environments(envs),
                context=host,
                label=f"tab:pqc:env:{_slugify(host)}",
            )
        )

    for host in sorted(env_by_host):
        if host in ("Laptop", "Lab server"):
            continue
        env_parts.append(rf"\subsection*{{{_latex_escape(host)}}}")
        env_parts.append(
            _render_environment_table(
                _merge_environments(env_by_host[host]),
                context=host,
                label=f"tab:pqc:env:{_slugify(host)}",
            )
        )

    _write_text(out_tables_dir / "environment.tex", "\n".join(env_parts).strip() + "\n")
    _write_text(out_tables_dir / "kem.tex", "\n".join(kem_parts).strip() + "\n")
    _write_text(out_tables_dir / "signature.tex", "\n".join(sig_parts).strip() + "\n")
    _write_text(out_tables_dir / "tls.tex", "\n".join(tls_parts).strip() + "\n")
    _write_text(out_tables_dir / "http.tex", "\n".join(http_parts).strip() + "\n")
    _write_text(out_tables_dir / "http_overhead.tex", "\n".join(overhead_parts).strip() + "\n")
    _write_text(
        out_tables_dir / "derived_insights.tex",
        _render_derived_insights(http_items=native_vs_provider, tls_items=tls_summary, rtt_ms=50.0),
    )

    exec_summary_path = out_tables_dir / "executive_summary_table.tex"
    if exec_summary_rows:
        _write_text(exec_summary_path, _render_exec_summary_table(exec_summary_rows))
    else:
        exec_summary_path.unlink(missing_ok=True)

    netem_by_host_version: dict[str, dict[str, list[NetemEntry]]] = defaultdict(dict)
    capacity_by_host_version: dict[str, dict[str, list[CapacityEntry]]] = defaultdict(dict)

    for ds, _env, _rows, _tls_meta, _http_runs, netem_entries, capacity_entries in parsed:
        host = (
            "Laptop"
            if ds.label.startswith("laptop-")
            else "Lab server"
            if ds.label.startswith("lab-")
            else ds.title
        )
        version = ds.results_dir.name.replace("openssl-", "")
        if netem_entries:
            netem_by_host_version[host][version] = netem_entries
        if capacity_entries:
            capacity_by_host_version[host][version] = capacity_entries

    netem_laptop_path = out_tables_dir / "netem_p99_laptop.tex"
    if netem_by_host_version.get("Laptop"):
        _write_text(
            netem_laptop_path,
            _render_netem_p99_table(
                entries_by_version=netem_by_host_version["Laptop"],
                host_short="Laptop",
                host_long="Laptop",
                label="tab:netem:laptop-p99",
            ),
        )
    else:
        netem_laptop_path.unlink(missing_ok=True)

    netem_lab_path = out_tables_dir / "netem_p99_lab.tex"
    if netem_by_host_version.get("Lab server"):
        _write_text(
            netem_lab_path,
            _render_netem_p99_table(
                entries_by_version=netem_by_host_version["Lab server"],
                host_short="Lab",
                host_long="Lab server",
                label="tab:netem:lab-p99",
            ),
        )
    else:
        netem_lab_path.unlink(missing_ok=True)

    netem_breakpoints_path = out_tables_dir / "netem_breakpoints.tex"
    if netem_by_host_version:
        _write_text(
            netem_breakpoints_path,
            _render_netem_breakpoints_table(
                entries_by_host_version=netem_by_host_version,
                label="tab:netem:breakpoints",
            ),
        )
    else:
        netem_breakpoints_path.unlink(missing_ok=True)

    capacity_laptop_path = out_tables_dir / "capacity_laptop.tex"
    if capacity_by_host_version.get("Laptop"):
        _write_text(
            capacity_laptop_path,
            _render_capacity_table(
                entries_by_version=capacity_by_host_version["Laptop"],
                host_long="Laptop",
                label="tab:capacity:laptop",
            ),
        )
    else:
        capacity_laptop_path.unlink(missing_ok=True)

    def host_file_key(host: str) -> str:
        if host == "Laptop":
            return "laptop"
        if host == "Lab server":
            return "lab"
        return _slugify(host).replace("-", "_")

    for host in sorted(
        set(kem_parts_by_host)
        | set(sig_parts_by_host)
        | set(tls_parts_by_host)
        | set(http_parts_by_host)
    ):
        key = host_file_key(host)

        kem_path = out_tables_dir / f"kem_{key}.tex"
        sig_path = out_tables_dir / f"signature_{key}.tex"
        tls_path = out_tables_dir / f"tls_{key}.tex"
        http_path = out_tables_dir / f"http_{key}.tex"

        if kem_parts_by_host.get(host):
            _write_text(kem_path, "\n".join(kem_parts_by_host[host]).strip() + "\n")
        else:
            kem_path.unlink(missing_ok=True)

        if sig_parts_by_host.get(host):
            _write_text(sig_path, "\n".join(sig_parts_by_host[host]).strip() + "\n")
        else:
            sig_path.unlink(missing_ok=True)

        if tls_parts_by_host.get(host):
            _write_text(tls_path, "\n".join(tls_parts_by_host[host]).strip() + "\n")
        else:
            tls_path.unlink(missing_ok=True)

        if http_parts_by_host.get(host):
            _write_text(http_path, "\n".join(http_parts_by_host[host]).strip() + "\n")
        else:
            http_path.unlink(missing_ok=True)

    packetization_tex = out_tables_dir / "packetization.tex"
    if packetization_observations:
        _write_text(
            packetization_tex,
            _render_packetization_appendix(packetization_observations).strip() + "\n",
        )
    else:
        packetization_tex.unlink(missing_ok=True)

    # Aggregate native vs provider hybrid overhead into a single figure + snippet.
    if not args.no_figures and native_vs_provider:
        try:
            import matplotlib

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except Exception:
            pass
        else:
            fig_dir = alcazar_dir / "figures/pqc"
            fig_dir.mkdir(parents=True, exist_ok=True)

            # Normalize into env/version buckets.
            buckets: dict[str, dict[str, float]] = {}
            for item in native_vs_provider:
                title = str(item.get("title", ""))
                overhead = float(item.get("hybrid_overhead_pct", 0.0))
                env = "Laptop" if "Laptop" in title else "Lab"
                version = "3.5.0" if "3.5" in title else "3.4.1"
                buckets.setdefault(env, {})[version] = overhead

            envs = []
            data_34 = []
            data_35 = []
            for env in ("Laptop", "Lab"):
                envs.append(env)
                data_34.append(buckets.get(env, {}).get("3.4.1"))
                data_35.append(buckets.get(env, {}).get("3.5.0"))

            x = range(len(envs))
            width = 0.35
            fig, ax = plt.subplots(figsize=(7, 4))
            bars34 = ax.bar(
                [i - width / 2 for i in x],
                data_34,
                width,
                label="OpenSSL 3.4.1 (provider)",
                color="#f39c12",
            )
            bars35 = ax.bar(
                [i + width / 2 for i in x],
                data_35,
                width,
                label="OpenSSL 3.5.0 (native)",
                color="#3498db",
            )

            ax.set_ylabel("Hybrid overhead vs classical (X25519) [%]")
            ax.set_title("Impact of native PQC support (Hybrid X25519+ML-KEM768)")
            ax.set_xticks(list(x), envs)
            ax.grid(axis="y", linestyle=":", linewidth=0.6, alpha=0.6)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            ax.legend()

            def _annotate(bars):
                for bar in bars:
                    h = bar.get_height()
                    if h is None:
                        continue
                    ax.text(
                        bar.get_x() + bar.get_width() / 2,
                        h + 0.1,
                        f"{h:.1f}%",
                        ha="center",
                        va="bottom",
                        fontsize=8,
                    )

            _annotate(bars34)
            _annotate(bars35)

            native_vs_provider_fig = fig_dir / "native-vs-provider.pdf"
            fig.tight_layout()
            fig.savefig(native_vs_provider_fig, bbox_inches="tight", dpi=150)
            plt.close(fig)

            snippet = "\n".join(
                [
                    r"\IfFileExists{figures/pqc/native-vs-provider.pdf}{%",
                    r"    \begin{figure}[H]",
                    r"        \centering",
                    r"        \includegraphics[width=0.9\linewidth]{figures/pqc/native-vs-provider.pdf}",
                    r"        \caption[Native vs provider overhead]{Hybrid HTTP overhead (X25519+ML-KEM768) on laptop vs lab: OpenSSL 3.5.0 (native) versus 3.4.1 (provider). Lower is better. Values show overhead vs classical X25519.}",
                    r"        \label{fig:pqc:native-vs-provider}",
                    r"    \end{figure}%",
                    r"}{}",
                    "",
                ]
            )
            _write_text(out_tables_dir / "native_vs_provider.tex", snippet)

    if args.build:
        _build_pdf(alcazar_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
