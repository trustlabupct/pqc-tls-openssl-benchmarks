#!/usr/bin/env python3
"""Verify the raw-data checksums, then run every analysis script in order.

Usage (from the repository root):  python3 analysis/run_all.py
Figures additionally require matplotlib; they are skipped if it is missing.
"""
import hashlib
import importlib.util
import runpy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))


def verify():
    bad = 0
    lines = (ROOT / "data" / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    for line in lines:
        digest, name = line.split(maxsplit=1)
        path = ROOT / "data" / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            print("CHECKSUM MISMATCH:", name)
            bad += 1
    print(f"raw data: {len(lines)} files checked, {bad} mismatches")
    return bad == 0


def main():
    if not verify():
        return 1
    for script in sorted(HERE.glob("0*_*.py")):
        print(f"\n=== {script.name}")
        runpy.run_path(str(script), run_name="__main__")
    if importlib.util.find_spec("matplotlib"):
        print("\n=== make_figures.py")
        runpy.run_path(str(HERE / "make_figures.py"), run_name="__main__")
    else:
        print("\nmatplotlib not installed: figures skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
