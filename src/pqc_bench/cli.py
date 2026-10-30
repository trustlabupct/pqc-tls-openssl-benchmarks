"""Command-line interface for PQC Benchmarking Suite."""

import sys
from typing import Any

import click

from . import __version__
from .algorithms.registry import AlgorithmType, registry
from .checker import capture_environment, check_all_dependencies, check_reproducibility


@click.group()
@click.version_option(version=__version__, prog_name="pqc-bench")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.option("-q", "--quiet", is_flag=True, help="Suppress non-essential output")
@click.pass_context
def main(ctx: click.Context, verbose: bool, quiet: bool) -> None:
    """PQC Benchmarking Suite - Post-Quantum Cryptography Performance Analysis.

    Benchmark KEM and digital signature algorithms using OpenSSL 3.x with oqs-provider.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet


@main.command()
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option("--fix-suggestions", is_flag=True, help="Include suggestions for fixing issues")
@click.pass_context
def check(ctx: click.Context, output_format: str, fix_suggestions: bool) -> None:
    """Verify system dependencies meet requirements.

    Checks that OpenSSL 3.x and oqs-provider are properly installed and configured.
    """
    quiet = ctx.obj.get("quiet", False)

    if not quiet:
        click.echo("Checking system dependencies...")
        click.echo()

    system_check = check_all_dependencies()

    if output_format == "json":
        import json

        result = {
            "openssl_version": system_check.openssl.version,
            "openssl_valid": system_check.openssl.is_valid,
            "oqs_provider_version": system_check.oqs_provider.version,
            "oqs_provider_valid": system_check.oqs_provider.is_valid,
            "perf_available": system_check.perf_available,
            "overall_valid": system_check.overall_valid,
        }
        if not system_check.openssl.is_valid:
            result["openssl_error"] = system_check.openssl.error_message
        if not system_check.oqs_provider.is_valid:
            result["oqs_provider_error"] = system_check.oqs_provider.error_message
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo("Dependency Check Results")
        click.echo("=" * 40)

        # OpenSSL status
        openssl_status = "PASS" if system_check.openssl.is_valid else "FAIL"
        openssl_version = system_check.openssl.version or "not found"
        click.echo(f"OpenSSL version:      {openssl_version} {openssl_status}")
        if not system_check.openssl.is_valid and system_check.openssl.error_message:
            click.echo(f"  Error: {system_check.openssl.error_message}")
            if fix_suggestions:
                click.echo("  Fix: Install OpenSSL 3.x from https://www.openssl.org/source/")

        # OQS-provider status
        oqs_status = "PASS" if system_check.oqs_provider.is_valid else "FAIL"
        oqs_version = system_check.oqs_provider.version or "not found"
        click.echo(f"oqs-provider version: {oqs_version} {oqs_status}")
        if not system_check.oqs_provider.is_valid and system_check.oqs_provider.error_message:
            click.echo(f"  Error: {system_check.oqs_provider.error_message}")
            if fix_suggestions:
                click.echo(
                    "  Fix: Install oqs-provider from "
                    "https://github.com/open-quantum-safe/oqs-provider"
                )

        # Perf status (optional)
        perf_status = "yes" if system_check.perf_available else "no"
        click.echo(f"perf available:       {perf_status} (optional)")

        click.echo()
        if system_check.overall_valid:
            click.echo("All required dependencies satisfied.")
            sys.exit(0)
        else:
            click.echo("Required dependencies not met. See errors above.")
            sys.exit(3)


@main.command("list")
@click.option(
    "-t",
    "--type",
    "algo_type",
    type=click.Choice(["kem", "sig", "all"]),
    default="all",
    help="Filter by algorithm type",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.option("--include-experimental", is_flag=True, help="Include experimental algorithms")
@click.option("--hybrids-only", is_flag=True, help="Show only hybrid algorithms")
@click.option("--pure-only", is_flag=True, help="Show only pure PQC algorithms")
@click.pass_context
def list_algorithms(
    ctx: click.Context,
    algo_type: str,
    output_format: str,
    include_experimental: bool,
    hybrids_only: bool,
    pure_only: bool,
) -> None:
    """List available algorithms and their metadata."""
    # Import algorithm registries
    from .algorithms import kem, sig  # noqa: F401 - registers algorithms

    # Get algorithms based on type filter
    if algo_type == "kem":
        algorithms = registry.get_by_type(AlgorithmType.KEM)
    elif algo_type == "sig":
        algorithms = registry.get_by_type(AlgorithmType.SIGNATURE)
    else:
        algorithms = registry.get_all()

    # Apply filters
    if not include_experimental:
        algorithms = [a for a in algorithms if not a.is_experimental]

    if hybrids_only:
        algorithms = [a for a in algorithms if a.is_hybrid]
    elif pure_only:
        algorithms = [a for a in algorithms if not a.is_hybrid]

    if output_format == "json":
        import json

        result = [
            {
                "name": a.name,
                "display_name": a.display_name,
                "type": a.type.value,
                "security_level": a.security_level,
                "is_hybrid": a.is_hybrid,
                "is_experimental": a.is_experimental,
                "classical_component": a.classical_component,
            }
            for a in algorithms
        ]
        click.echo(json.dumps(result, indent=2))
    else:
        quiet = ctx.obj.get("quiet", False)
        if not quiet:
            click.echo(f"Available Algorithms ({len(algorithms)} total)")
            click.echo("=" * 60)
            click.echo()

        # Group by type
        kems = [a for a in algorithms if a.type == AlgorithmType.KEM]
        sigs = [a for a in algorithms if a.type == AlgorithmType.SIGNATURE]

        if kems and (algo_type in ["kem", "all"]):
            click.echo("KEMs (Key Encapsulation Mechanisms)")
            click.echo("-" * 40)
            for a in kems:
                hybrid_marker = " [hybrid]" if a.is_hybrid else ""
                exp_marker = " [experimental]" if a.is_experimental else ""
                level = f" L{a.security_level}" if a.security_level else ""
                click.echo(f"  {a.name:<25} {a.display_name}{level}{hybrid_marker}{exp_marker}")
            click.echo()

        if sigs and (algo_type in ["sig", "all"]):
            click.echo("Digital Signatures")
            click.echo("-" * 40)
            for a in sigs:
                hybrid_marker = " [hybrid]" if a.is_hybrid else ""
                exp_marker = " [experimental]" if a.is_experimental else ""
                level = f" L{a.security_level}" if a.security_level else ""
                click.echo(f"  {a.name:<25} {a.display_name}{level}{hybrid_marker}{exp_marker}")
            click.echo()


@main.command()
@click.argument("algorithms", nargs=-1)
@click.option(
    "-t",
    "--type",
    "algo_type",
    type=click.Choice(["kem", "sig", "all"]),
    default="all",
    help="Algorithm type to benchmark",
)
@click.option(
    "-n",
    "--samples",
    default=10,
    type=click.IntRange(min=1),
    help="Number of repeated benchmark runs for statistics",
)
@click.option("-o", "--output", "output_file", type=click.Path(), help="Output file path")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "csv", "text"]),
    default="text",
    help="Output format",
)
@click.option("--include-tls", is_flag=True, help="Include TLS handshake benchmarks")
@click.option("--include-perf", is_flag=True, help="Include CPU cycle counts (requires perf)")
@click.option(
    "--warm-up", default=2, type=click.IntRange(min=0), help="Number of warm-up runs (discarded)"
)
@click.option(
    "--seconds",
    default=3,
    type=click.IntRange(min=1),
    help="Duration of each openssl speed run in seconds",
)
@click.option(
    "--timeout", default=300, type=click.IntRange(min=1), help="Timeout per algorithm in seconds"
)
@click.option(
    "--pin-cpu",
    type=click.IntRange(min=0),
    default=None,
    help="Pin benchmark to specific CPU core (requires taskset)",
)
@click.option("--no-warnings", is_flag=True, help="Suppress reproducibility warnings")
@click.option(
    "--openssl-path",
    default=None,
    help="Path to OpenSSL binary (default: uses PQC_BENCH_OPENSSL env or 'openssl')",
)
@click.option(
    "--library-path",
    default=None,
    help="LD_LIBRARY_PATH for OpenSSL (default: uses PQC_BENCH_LD_LIBRARY_PATH env)",
)
@click.option(
    "--use-native",
    is_flag=True,
    help="Use native OpenSSL 3.5+ PQC instead of oqs-provider for supported algorithms",
)
@click.pass_context
def run(
    ctx: click.Context,
    algorithms: tuple[str, ...],
    algo_type: str,
    samples: int,
    output_file: str | None,
    output_format: str,
    include_tls: bool,
    include_perf: bool,
    warm_up: int,
    seconds: int,
    timeout: int,
    pin_cpu: int | None,
    no_warnings: bool,
    openssl_path: str | None,
    library_path: str | None,
    use_native: bool,
) -> None:
    """Run benchmarks for specified algorithms.

    If no ALGORITHMS are specified, benchmarks all available algorithms.

    Statistics (median, p95, p99) are computed across multiple samples.
    Each sample runs openssl speed for --seconds duration.

    Use --use-native with OpenSSL 3.5+ to benchmark native ML-KEM and ML-DSA
    implementations without oqs-provider. This allows comparing native vs
    oqs-provider performance.
    """
    quiet = ctx.obj.get("quiet", False)
    verbose = ctx.obj.get("verbose", False)

    # Check dependencies first
    system_check = check_all_dependencies()
    # If using native mode, oqs-provider is optional (only needed for non-native algorithms)
    if use_native:
        # Only require OpenSSL for native mode
        if not system_check.openssl.is_valid:
            click.echo("Error: OpenSSL not found or invalid.", err=True)
            click.echo("Run 'pqc-bench check' for details.", err=True)
            sys.exit(3)
        # Warn if oqs-provider not available (some algorithms may fail)
        if not system_check.oqs_provider.is_valid and not quiet:
            click.echo(
                "Note: oqs-provider not available. Only native PQC algorithms will work.",
                err=True,
            )
    elif not system_check.overall_valid:
        click.echo("Error: System dependencies not met.", err=True)
        click.echo("Run 'pqc-bench check' for details.", err=True)
        sys.exit(3)

    if include_perf and not system_check.perf_available:
        click.echo("Warning: perf not available, skipping CPU metrics", err=True)
        include_perf = False

    # Check reproducibility environment and show warnings
    if not quiet and not no_warnings:
        repro_check = check_reproducibility()
        if repro_check.warnings:
            click.echo("Reproducibility warnings:", err=True)
            for warning in repro_check.warnings:
                click.echo(f"  [{warning.category}] {warning.message}", err=True)
                if verbose:
                    click.echo(f"    Recommendation: {warning.recommendation}", err=True)
            click.echo("", err=True)

        # Check if --pin-cpu requested but taskset not available
        if pin_cpu is not None and not repro_check.taskset_available:
            click.echo("Warning: --pin-cpu requires taskset, which is not available", err=True)
            pin_cpu = None

    if not quiet:
        env = capture_environment(
            openssl_path=openssl_path or "",
            provider_path="",
            library_path=library_path or "",
        )
        click.echo(f"PQC Benchmarking Suite v{__version__}")
        if use_native:
            click.echo(f"OpenSSL: {env.openssl_version} (native PQC mode)")
        else:
            click.echo(f"OpenSSL: {env.openssl_version}, oqs-provider: {env.oqs_provider_version}")
        click.echo(f"Platform: {env.platform}")
        click.echo()

    # Import runner and execute benchmarks
    from .runner import run_benchmarks

    try:
        results = run_benchmarks(
            algorithm_names=list(algorithms) if algorithms else None,
            algo_type=algo_type,
            samples=samples,
            warm_up=warm_up,
            seconds_per_sample=seconds,
            timeout=timeout,
            include_tls=include_tls,
            include_perf=include_perf,
            verbose=verbose,
            quiet=quiet,
            pin_cpu=pin_cpu,
            openssl_path=openssl_path,
            library_path=library_path,
            use_native=use_native,
        )

        if output_format == "json":
            from .reporters.json import format_json

            output = format_json(results)
        elif output_format == "csv":
            from .reporters.csv import format_csv

            output = format_csv(results)
        else:
            from .reporters.text import format_text

            output = format_text(results)

        if output_file:
            with open(output_file, "w") as f:
                f.write(output)
            if not quiet:
                click.echo(f"Results written to {output_file}")
        else:
            click.echo(output)

        if results.failed_algorithms:
            if results.results:
                sys.exit(1)  # Partial failure
            else:
                sys.exit(2)  # Complete failure
        sys.exit(0)

    except Exception as e:
        click.echo(f"Error during benchmark: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(2)


@main.command("http")
@click.option("--url", required=True, help="HTTPS URL to benchmark (e.g., https://localhost:4433/)")
@click.option(
    "--client",
    "client_type",
    type=click.Choice(["openssl", "playwright"]),
    default="openssl",
    show_default=True,
    help="HTTP client to use",
)
@click.option(
    "--reuse",
    type=click.Choice(["none", "session", "context", "page"]),
    default="none",
    show_default=True,
    help="Reuse strategy (OpenSSL: none/session, Playwright: none/context/page)",
)
@click.option(
    "-n",
    "--samples",
    default=20,
    type=click.IntRange(min=1),
    show_default=True,
    help="Number of measured requests (after warm-up)",
)
@click.option(
    "--warm-up",
    default=2,
    type=click.IntRange(min=0),
    show_default=True,
    help="Warm-up requests (discarded)",
)
@click.option(
    "--timeout",
    default=30,
    type=click.IntRange(min=1),
    show_default=True,
    help="Timeout per request in seconds",
)
@click.option(
    "--concurrency",
    default=1,
    type=click.IntRange(min=1),
    show_default=True,
    help="Parallel requests (OpenSSL only; Playwright currently supports 1)",
)
@click.option(
    "--groups",
    default=None,
    help="TLS groups for OpenSSL client (e.g., X25519MLKEM768)",
)
@click.option(
    "--alpn",
    default="http/1.1",
    show_default=True,
    help="ALPN for OpenSSL client (best-effort)",
)
@click.option(
    "--browser",
    type=click.Choice(["chromium", "firefox", "webkit"]),
    default="chromium",
    show_default=True,
    help="Playwright browser to use",
)
@click.option(
    "--browser-executable",
    default=None,
    help="Playwright browser executable path (avoids `playwright install` when set)",
)
@click.option(
    "--headed",
    is_flag=True,
    help="Run Playwright headed (default is headless)",
)
@click.option(
    "--ignore-https-errors/--verify-https",
    default=True,
    show_default=True,
    help="Ignore TLS cert errors in Playwright",
)
@click.option("-o", "--output", "output_file", type=click.Path(), help="Output file path")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "csv", "text"]),
    default="text",
    show_default=True,
    help="Output format",
)
@click.option(
    "--no-sample-details",
    is_flag=True,
    help="Omit per-sample details in JSON output (keeps aggregated timings/stats)",
)
@click.option(
    "--meta",
    "meta_items",
    multiple=True,
    help="Extra JSON metadata as key=value (repeatable; stored under metadata.context)",
)
@click.option(
    "--meta-json",
    "meta_json",
    default=None,
    help="Extra JSON metadata object (stored under metadata.context)",
)
@click.option(
    "--openssl-path",
    envvar="PQC_BENCH_OPENSSL",
    default=None,
    help="Path to OpenSSL binary (for native OpenSSL 3.5+ benchmarks)",
)
@click.option(
    "--library-path",
    envvar="PQC_BENCH_LD_LIBRARY_PATH",
    default=None,
    help="LD_LIBRARY_PATH for custom OpenSSL builds",
)
@click.pass_context
def http_bench(
    ctx: click.Context,
    url: str,
    client_type: str,
    reuse: str,
    samples: int,
    warm_up: int,
    timeout: int,
    concurrency: int,
    groups: str | None,
    alpn: str,
    browser: str,
    browser_executable: str | None,
    headed: bool,
    ignore_https_errors: bool,
    output_file: str | None,
    output_format: str,
    no_sample_details: bool,
    meta_items: tuple[str, ...],
    meta_json: str | None,
    openssl_path: str | None,
    library_path: str | None,
) -> None:
    """Benchmark end-to-end HTTPS request timings (TTFB/total).

    This complements `pqc-bench run` (crypto microbench) and `--include-tls`
    by measuring user-visible HTTP request latency with either OpenSSL or a real browser.
    """
    quiet = ctx.obj.get("quiet", False)
    verbose = ctx.obj.get("verbose", False)

    # For OpenSSL client, require dependencies like the main benchmark runner does.
    if client_type == "openssl":
        system_check = check_all_dependencies()
        if not system_check.overall_valid:
            click.echo("Error: System dependencies not met.", err=True)
            click.echo("Run 'pqc-bench check' for details.", err=True)
            sys.exit(3)

    if not quiet:
        click.echo(f"PQC Benchmarking Suite v{__version__}")
        click.echo(f"HTTP benchmark: {url} ({client_type})")
        click.echo()

    from .httpbench import (
        HttpBenchmarkConfig,
        HttpClient,
        HttpReuseMode,
        format_http_csv,
        format_http_json,
        format_http_text,
        run_http_benchmark,
    )

    extra_metadata: dict[str, Any] = {}
    if meta_json:
        import json

        try:
            parsed = json.loads(meta_json)
        except json.JSONDecodeError as e:
            click.echo(f"Error: --meta-json is not valid JSON: {e}", err=True)
            sys.exit(2)
        if not isinstance(parsed, dict):
            click.echo("Error: --meta-json must be a JSON object", err=True)
            sys.exit(2)
        extra_metadata.update(parsed)

    if meta_items:
        import json

        for item in meta_items:
            if "=" not in item:
                click.echo(f"Error: --meta must be in key=value form: {item}", err=True)
                sys.exit(2)
            key, raw_value = item.split("=", 1)
            key = key.strip()
            raw_value = raw_value.strip()
            if not key:
                click.echo(f"Error: --meta key is empty: {item}", err=True)
                sys.exit(2)
            # Best-effort type coercion:
            # - JSON scalars (numbers, true/false/null) are parsed
            # - everything else remains a string
            value: Any
            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError:
                value = raw_value
            extra_metadata[key] = value

    try:
        config = HttpBenchmarkConfig(
            url=url,
            client=HttpClient(client_type),
            reuse=HttpReuseMode(reuse),
            samples=samples,
            warm_up=warm_up,
            timeout=timeout,
            concurrency=concurrency,
            groups=groups,
            alpn=alpn,
            browser=browser,
            browser_executable=browser_executable,
            headless=not headed,
            ignore_https_errors=ignore_https_errors,
            openssl_path=openssl_path or "openssl",
            library_path=library_path or "",
            run_metadata=extra_metadata,
        )
        result = run_http_benchmark(config)
    except ValueError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(2)

    if output_format == "json":
        output = format_http_json(result, include_samples=not no_sample_details)
    elif output_format == "csv":
        output = format_http_csv(result)
    else:
        output = format_http_text(result)

    if output_file:
        with open(output_file, "w") as f:
            f.write(output)
        if not quiet:
            click.echo(f"Results written to {output_file}")
    else:
        click.echo(output)

    sys.exit(1 if result.fail_count else 0)


def _generate_summary(data: dict) -> str:
    """Generate summary statistics from benchmark JSON data.

    Args:
        data: Parsed JSON benchmark data

    Returns:
        Formatted summary text
    """
    lines = []
    lines.append("Benchmark Summary")
    lines.append("=" * 60)
    lines.append("")

    # Environment info
    if "environment" in data:
        env = data["environment"]
        lines.append(
            f"Environment: OpenSSL {env.get('openssl_version', 'N/A')}, "
            f"oqs-provider {env.get('oqs_provider_version', 'N/A')}"
        )
        lines.append(f"Platform: {env.get('platform', 'N/A')}")
        if env.get("cpu_model"):
            lines.append(f"CPU: {env['cpu_model']}")
        lines.append("")

    # Metadata
    if "metadata" in data:
        meta = data["metadata"]
        lines.append(f"Generated: {meta.get('generated_at', 'N/A')}")
        # Handle both old and new metadata key names
        speed_iters = meta.get("speed_iteration_count", meta.get("iteration_count", "N/A"))
        speed_samples = meta.get("speed_sample_count", meta.get("sample_count", "N/A"))
        tls_count = meta.get("tls_handshake_count", 0)
        lines.append(f"Speed iterations: {speed_iters}, samples: {speed_samples}")
        if tls_count:
            lines.append(f"TLS handshakes: {tls_count}")
        lines.append("")

    # Results summary
    results = data.get("results", [])
    if results:
        # Group by type
        kems = [r for r in results if r.get("type") == "kem"]
        sigs = [r for r in results if r.get("type") == "signature"]

        if kems:
            lines.append(f"KEMs: {len(kems)} algorithms")
            # Find fastest/slowest for each operation
            for op in ["keygen", "encaps", "decaps"]:
                op_results = []
                for r in kems:
                    ops = r.get("operations", {})
                    if op in ops:
                        median = ops[op].get("median_us")
                        # Filter out missing or zero values to avoid mis-ranking
                        if median is not None and median > 0:
                            op_results.append((r["algorithm"], median))
                if op_results:
                    op_results.sort(key=lambda x: x[1])
                    fastest = op_results[0]
                    slowest = op_results[-1]
                    lines.append(
                        f"  {op}: fastest={fastest[0]} ({fastest[1]:.1f} us), "
                        f"slowest={slowest[0]} ({slowest[1]:.1f} us)"
                    )
            lines.append("")

        if sigs:
            lines.append(f"Signatures: {len(sigs)} algorithms")
            for op in ["keygen", "sign", "verify"]:
                op_results = []
                for r in sigs:
                    ops = r.get("operations", {})
                    if op in ops:
                        median = ops[op].get("median_us")
                        # Filter out missing or zero values to avoid mis-ranking
                        if median is not None and median > 0:
                            op_results.append((r["algorithm"], median))
                if op_results:
                    op_results.sort(key=lambda x: x[1])
                    fastest = op_results[0]
                    slowest = op_results[-1]
                    lines.append(
                        f"  {op}: fastest={fastest[0]} ({fastest[1]:.1f} us), "
                        f"slowest={slowest[0]} ({slowest[1]:.1f} us)"
                    )
            lines.append("")

    # Failed algorithms
    failed = data.get("failed_algorithms", [])
    if failed:
        lines.append(f"Failed: {len(failed)} algorithms")
        for f in failed[:5]:  # Show first 5
            if isinstance(f, dict):
                lines.append(f"  - {f.get('algorithm', 'unknown')}: {f.get('reason', 'unknown')}")
            else:
                lines.append(f"  - {f}")
        if len(failed) > 5:
            lines.append(f"  ... and {len(failed) - 5} more")

    return "\n".join(lines)


def _generate_comparison(data: dict, compare_data: dict, file1: str, file2: str) -> str:
    """Generate comparison between two benchmark files.

    Args:
        data: Current benchmark data
        compare_data: Baseline benchmark data to compare against
        file1: Current file path
        file2: Baseline file path

    Returns:
        Formatted comparison text
    """
    import os

    lines = []
    lines.append("Benchmark Comparison")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Current:  {os.path.basename(file1)}")
    lines.append(f"Baseline: {os.path.basename(file2)}")
    lines.append("")

    # Build lookup for baseline results
    baseline: dict[str, dict] = {}
    for r in compare_data.get("results", []):
        baseline[r["algorithm"]] = r

    # Compare results
    current_results = data.get("results", [])

    lines.append(
        f"{'Algorithm':<25} {'Operation':<10} {'Current':>12} {'Baseline':>12} {'Diff':>10}"
    )
    lines.append("-" * 70)

    for r in current_results:
        algo = r["algorithm"]
        baseline_r = baseline.get(algo, {})

        for op_name, op_data in r.get("operations", {}).items():
            current_median = op_data.get("median_us")
            baseline_ops = baseline_r.get("operations", {})
            baseline_op = baseline_ops.get(op_name, {})
            baseline_median = baseline_op.get("median_us")

            # Format current value (handle None/missing)
            if current_median is not None and current_median > 0:
                current_str = f"{current_median:>10.1f}us"
            else:
                current_str = f"{'N/A':>12}"

            # Format baseline value and compute diff (handle None/missing)
            if baseline_median is not None and baseline_median > 0:
                baseline_str = f"{baseline_median:>10.1f}us"
                if current_median is not None and current_median > 0:
                    diff_pct = ((current_median - baseline_median) / baseline_median) * 100
                    diff_str = f"+{diff_pct:.1f}%" if diff_pct > 0 else f"{diff_pct:.1f}%"
                else:
                    diff_str = "N/A"
            else:
                baseline_str = f"{'N/A':>12}"
                diff_str = "N/A"

            lines.append(f"{algo:<25} {op_name:<10} {current_str} {baseline_str} {diff_str:>10}")

    lines.append("")
    lines.append("Legend: positive % = slower, negative % = faster")

    return "\n".join(lines)


@main.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("-o", "--output", "output_file", type=click.Path(), help="Output file path")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "csv", "markdown"]),
    default="json",
    help="Output format",
)
@click.option("--summary", is_flag=True, help="Generate summary statistics only")
@click.option(
    "--compare",
    "compare_file",
    type=click.Path(exists=True),
    help="Compare with another benchmark file",
)
@click.pass_context
def report(
    ctx: click.Context,
    input_file: str,
    output_file: str | None,
    output_format: str,
    summary: bool,
    compare_file: str | None,
) -> None:
    """Generate or convert benchmark reports.

    Takes a JSON benchmark results file as input and converts to the specified format.
    """
    import json

    quiet = ctx.obj.get("quiet", False)

    try:
        with open(input_file) as f:
            data = json.load(f)

        if compare_file:
            with open(compare_file) as f:
                compare_data = json.load(f)
            output = _generate_comparison(data, compare_data, input_file, compare_file)
            if output_file:
                with open(output_file, "w") as f:
                    f.write(output)
                if not quiet:
                    click.echo(f"Comparison written to {output_file}")
            else:
                click.echo(output)
            return

        if summary:
            # Generate summary statistics
            output = _generate_summary(data)
            if output_file:
                with open(output_file, "w") as f:
                    f.write(output)
                if not quiet:
                    click.echo(f"Summary written to {output_file}")
            else:
                click.echo(output)
            return

        # Convert format
        if output_format == "json":
            output = json.dumps(data, indent=2)
        elif output_format == "csv":
            from .reporters.csv import format_json_to_csv

            output = format_json_to_csv(data)
        elif output_format == "markdown":
            from .reporters.text import format_json_to_markdown

            output = format_json_to_markdown(data)
        else:
            output = json.dumps(data, indent=2)

        if output_file:
            with open(output_file, "w") as f:
                f.write(output)
            if not quiet:
                click.echo(f"Report written to {output_file}")
        else:
            click.echo(output)

    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON in {input_file}: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command("packetization")
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option(
    "-m",
    "--metadata",
    "metadata_file",
    type=click.Path(exists=True),
    help="Path to metadata.json from capture script",
)
@click.option("-o", "--output", "output_file", type=click.Path(), help="Output file path")
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "text"]),
    default="text",
    show_default=True,
    help="Output format",
)
@click.pass_context
def packetization_analyze(
    ctx: click.Context,
    pcap_file: str,
    metadata_file: str | None,
    output_file: str | None,
    output_format: str,
) -> None:
    """Analyze TLS handshake packet capture for packetization metrics.

    Parses a PCAP file captured by the packetization_capture.sh script
    and produces metrics about TCP segmentation and TLS record sizes.

    This helps validate the report's theoretical packetization estimates
    with actual measured packet captures.

    Example:
        pqc-bench packetization capture.pcap -m metadata.json -f json
    """
    quiet = ctx.obj.get("quiet", False)

    if not quiet:
        click.echo(f"PQC Benchmarking Suite v{__version__}")
        click.echo(f"Analyzing PCAP: {pcap_file}")
        click.echo()

    try:
        from .packetization import analyze_pcap, format_json, format_text

        result = analyze_pcap(pcap_file, metadata_file)

        output = format_json(result) if output_format == "json" else format_text(result)

        if output_file:
            with open(output_file, "w") as f:
                f.write(output)
            if not quiet:
                click.echo(f"Results written to {output_file}")
        else:
            click.echo(output)

        # Exit with warning if validation issues detected
        if result.max_payload_exceeds_mss:
            click.echo(
                "\nWarning: Payload sizes exceed MSS - possible capture artifacts",
                err=True,
            )
            sys.exit(1)

        sys.exit(0)

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command("packetization-capture")
@click.option(
    "-k",
    "--kem",
    "kem_algo",
    default="X25519",
    show_default=True,
    help="KEM algorithm for key exchange",
)
@click.option(
    "-s",
    "--sig",
    "sig_algo",
    default="rsa:2048",
    show_default=True,
    help="Signature algorithm for certificates",
)
@click.option(
    "-m",
    "--mtu",
    default=1500,
    type=click.IntRange(min=576, max=9000),
    show_default=True,
    help="MTU value for the test network",
)
@click.option(
    "-n",
    "--iterations",
    default=5,
    type=click.IntRange(min=1),
    show_default=True,
    help="Number of TLS handshakes to capture",
)
@click.option(
    "-o",
    "--output-dir",
    required=True,
    type=click.Path(),
    help="Output directory for pcap and metadata",
)
@click.option(
    "--netem",
    default=None,
    help="tc netem parameters (e.g., 'delay 20ms loss 0.1%%')",
)
@click.option(
    "--netem-dir",
    default="client",
    type=click.Choice(["client", "server", "both"]),
    show_default=True,
    help="Apply netem on which direction(s)",
)
@click.option(
    "--analyze/--no-analyze",
    default=True,
    show_default=True,
    help="Run analysis after capture",
)
@click.option(
    "--keep-pcap/--delete-pcap",
    default=True,
    show_default=True,
    help="Keep or delete pcap file after analysis",
)
@click.pass_context
def packetization_capture(
    ctx: click.Context,
    kem_algo: str,
    sig_algo: str,
    mtu: int,
    iterations: int,
    output_dir: str,
    netem: str | None,
    netem_dir: str,
    analyze: bool,
    keep_pcap: bool,
) -> None:
    """Capture TLS handshake packets for packetization analysis.

    This command runs the packetization_capture.sh script to create
    a network namespace topology, capture TLS handshakes, and optionally
    analyze the results.

    Requires root privileges for network namespace operations.

    Example:
        sudo pqc-bench packetization-capture -k X25519MLKEM768 -s mldsa65 -o ./captures
    """
    import os
    import subprocess
    from pathlib import Path

    quiet = ctx.obj.get("quiet", False)
    verbose = ctx.obj.get("verbose", False)

    # Check for root
    if os.geteuid() != 0:
        click.echo("Error: This command requires root privileges", err=True)
        click.echo("Run with: sudo pqc-bench packetization-capture ...", err=True)
        sys.exit(3)

    # Find the capture script
    script_path = Path(__file__).parent.parent / "scripts" / "packetization_capture.sh"
    if not script_path.exists():
        # Try alternative location
        script_path = Path(__file__).parent.parent.parent / "scripts" / "packetization_capture.sh"
    if not script_path.exists():
        click.echo(f"Error: Capture script not found at {script_path}", err=True)
        sys.exit(1)

    if not quiet:
        click.echo(f"PQC Benchmarking Suite v{__version__}")
        click.echo(f"Packetization Capture: {kem_algo} + {sig_algo}, MTU={mtu}")
        click.echo()

    # Build command
    cmd = [
        str(script_path),
        "-k",
        kem_algo,
        "-s",
        sig_algo,
        "-m",
        str(mtu),
        "-n",
        str(iterations),
        "-o",
        output_dir,
        "--keep-pcap",
    ]

    if netem:
        cmd.extend(["--netem", netem])
        cmd.extend(["--netem-dir", netem_dir])

    if verbose:
        cmd.append("-v")

    # Run capture script
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        if verbose or result.returncode != 0:
            if result.stdout:
                click.echo(result.stdout)
            if result.stderr:
                click.echo(result.stderr, err=True)

        if result.returncode != 0:
            click.echo(f"Capture failed with exit code {result.returncode}", err=True)
            sys.exit(result.returncode)

        # Parse output for file paths
        pcap_file = None
        metadata_file = None
        for line in result.stdout.split("\n"):
            if line.startswith("PCAP_FILE:"):
                pcap_file = line.split(":", 1)[1].strip()
            elif line.startswith("METADATA_FILE:"):
                metadata_file = line.split(":", 1)[1].strip()

        if not quiet:
            click.echo(f"Capture completed: {pcap_file}")

        # Run analysis if requested
        if analyze and pcap_file:
            click.echo()
            click.echo("Running analysis...")

            from .packetization import analyze_pcap, format_json, format_text

            analysis_result = analyze_pcap(pcap_file, metadata_file)

            # Write JSON output
            json_output_file = Path(output_dir) / "analysis.json"
            with open(json_output_file, "w") as f:
                f.write(format_json(analysis_result))

            if not quiet:
                click.echo(format_text(analysis_result))
                click.echo()
                click.echo(f"JSON results: {json_output_file}")

            # Delete pcap if requested
            if not keep_pcap and pcap_file and Path(pcap_file).exists():
                Path(pcap_file).unlink()
                if not quiet:
                    click.echo(f"Deleted: {pcap_file}")

        sys.exit(0)

    except subprocess.TimeoutExpired:
        click.echo("Error: Capture timed out after 5 minutes", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
