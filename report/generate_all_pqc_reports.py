#!/usr/bin/env python3
"""Generate PQC PDF report bundles for all known results directories.

This is a small wrapper around `report/generate_pqc_report.py` that:
  - Detects per-run results directories under `./results/`
  - Builds the Alcázar-based PDF report for each run in an isolated temp dir
  - Writes outputs under `./results/reports/<label>/`

Raw results remain untouched; only derived artifacts are written.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class Dataset:
    label: str
    results_dir: Path


def _discover_datasets(results_root: Path) -> list[Dataset]:
    datasets: list[Dataset] = []

    for local_dir in sorted(results_root.glob("openssl-*")):
        if local_dir.is_dir():
            datasets.append(Dataset(label=f"laptop-{local_dir.name}", results_dir=local_dir))

    lab_root = results_root / "lab-server"
    if lab_root.exists():
        for lab_dir in sorted(lab_root.iterdir()):
            if lab_dir.is_dir():
                datasets.append(Dataset(label=f"lab-{lab_dir.name}", results_dir=lab_dir))

    return datasets


def _copy_dir_contents(src: Path, dst: Path, *, pattern: str = "*") -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for path in sorted(src.glob(pattern)):
        if path.is_file():
            shutil.copy2(path, dst / path.name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-root", type=Path, default=Path("results"))
    parser.add_argument("--out-dir", type=Path, default=Path("results/reports"))
    parser.add_argument("--alcazar-src", type=Path, default=Path("report/alcazar"))
    parser.add_argument(
        "--no-figures",
        action="store_true",
        help="Skip matplotlib figure generation",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip latexmk PDF build (tables only)",
    )
    args = parser.parse_args()

    results_root: Path = args.results_root
    out_dir: Path = args.out_dir
    alcazar_src: Path = args.alcazar_src

    if not results_root.exists():
        raise SystemExit(f"results root not found: {results_root}")
    if not alcazar_src.exists():
        raise SystemExit(f"alcazar template not found: {alcazar_src}")

    datasets = _discover_datasets(results_root)
    if not datasets:
        raise SystemExit(f"no datasets found under: {results_root}")

    out_dir.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(UTC).isoformat()
    index: dict[str, object] = {
        "generated_at": generated_at,
        "datasets": [],
    }

    generator = Path(__file__).with_name("generate_pqc_report.py").resolve()
    for ds in datasets:
        bundle_dir = out_dir / ds.label
        if bundle_dir.exists():
            shutil.rmtree(bundle_dir)
        bundle_dir.mkdir(parents=True, exist_ok=True)

        (bundle_dir / "source.txt").write_text(
            f"label={ds.label}\nresults_dir={ds.results_dir}\ngenerated_at={generated_at}\n",
            encoding="utf-8",
        )

        with tempfile.TemporaryDirectory(prefix=f"pqc-report-{ds.label}-") as tmp:
            tmpdir = Path(tmp)
            tmp_alcazar = tmpdir / "alcazar"
            shutil.copytree(alcazar_src, tmp_alcazar)

            cmd = [
                sys.executable,
                str(generator),
                "--results-dir",
                str(ds.results_dir),
                "--alcazar-dir",
                str(tmp_alcazar),
            ]
            if args.no_figures:
                cmd.append("--no-figures")
            if not args.no_build:
                cmd.append("--build")

            subprocess.run(cmd, check=True)

            tables_src = tmp_alcazar / "text/chapters/generated"
            if tables_src.exists():
                _copy_dir_contents(tables_src, bundle_dir / "tables", pattern="*.tex")

            figs_src = tmp_alcazar / "figures/pqc"
            if figs_src.exists():
                _copy_dir_contents(figs_src, bundle_dir / "figures", pattern="*.pdf")

            pdf_src = tmp_alcazar / "main.pdf"
            if pdf_src.exists():
                shutil.copy2(pdf_src, bundle_dir / "pqc-report.pdf")

        index["datasets"].append(
            {
                "label": ds.label,
                "results_dir": str(ds.results_dir),
                "bundle_dir": str(bundle_dir),
                "has_pdf": (bundle_dir / "pqc-report.pdf").exists(),
            }
        )

    (out_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
