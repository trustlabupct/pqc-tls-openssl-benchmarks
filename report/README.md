# Report

`alcazar/` contains the Alcázar LaTeX template and report files.
The generator converts benchmark JSON files in `results/` to LaTeX tables and figures.

Run these commands from the project root.

## Generate and build

```bash
python3 report/generate_pqc_report.py --build
```

Output: `report/alcazar/main.pdf`.

To generate tables without figures:

```bash
python3 report/generate_pqc_report.py --no-figures --build
```

To use one results directory:

```bash
python3 report/generate_pqc_report.py --results-dir results/openssl-3.5.0 --build
```
