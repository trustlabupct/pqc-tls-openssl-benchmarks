"""HTTP/web benchmarking for PQC Bench.

This module adds an end-to-end layer on top of the existing microbenchmarks:
it measures HTTP-level timings (TTFB, total time) using either:
- OpenSSL CLI (`openssl s_client`) for controlled, PQC-group-selectable traffic
- Playwright (optional dependency) for browser-realistic measurements
"""

from __future__ import annotations

import contextlib
import csv
import io
import os
import re
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from threading import Thread
from typing import Any

from . import __version__
from .checker import capture_environment
from .stats import Stats, calculate_percentile, calculate_stats


class HttpClient(str, Enum):
    """Supported HTTP benchmark clients."""

    OPENSSL = "openssl"
    PLAYWRIGHT = "playwright"


class HttpReuseMode(str, Enum):
    """Connection/session reuse strategy."""

    NONE = "none"
    SESSION = "session"  # OpenSSL TLS resumption (new TCP, session tickets)
    CONTEXT = "context"  # Playwright: reuse browser context
    PAGE = "page"  # Playwright: reuse a single page


@dataclass(frozen=True)
class ParsedUrl:
    """Parsed HTTPS URL information."""

    raw: str
    host: str
    port: int
    target: str
    sni: str


@dataclass(frozen=True)
class TlsInfo:
    """Negotiated TLS parameters (best-effort)."""

    protocol: str | None = None
    cipher: str | None = None
    alpn: str | None = None
    key_exchange: str | None = None
    signature_type: str | None = None

    def to_dict(self) -> dict[str, str]:
        result: dict[str, str] = {}
        if self.protocol is not None:
            result["protocol"] = self.protocol
        if self.cipher is not None:
            result["cipher"] = self.cipher
        if self.alpn is not None:
            result["alpn"] = self.alpn
        if self.key_exchange is not None:
            result["key_exchange"] = self.key_exchange
        if self.signature_type is not None:
            result["signature_type"] = self.signature_type
        return result


@dataclass
class HttpSampleResult:
    """Per-sample HTTP benchmark result."""

    ok: bool
    status: int | None = None
    ttfb_us: float | None = None
    total_us: float | None = None
    ttfb_e2e_us: float | None = None
    total_e2e_us: float | None = None
    dns_us: float | None = None
    tcp_us: float | None = None
    tls_us: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "status": self.status,
            "ttfb_us": self.ttfb_us,
            "total_us": self.total_us,
            "ttfb_e2e_us": self.ttfb_e2e_us,
            "total_e2e_us": self.total_e2e_us,
            "dns_us": self.dns_us,
            "tcp_us": self.tcp_us,
            "tls_us": self.tls_us,
            "error": self.error,
        }


@dataclass
class HttpBenchmarkConfig:
    """Configuration for HTTP benchmarking."""

    url: str
    client: HttpClient = HttpClient.OPENSSL
    reuse: HttpReuseMode = HttpReuseMode.NONE
    samples: int = 20
    warm_up: int = 2
    timeout: int = 30
    concurrency: int = 1
    groups: str | None = None  # OpenSSL-only
    alpn: str = "http/1.1"  # OpenSSL-only (best-effort)
    browser: str = "chromium"  # Playwright-only
    browser_executable: str | None = None  # Playwright-only
    headless: bool = True  # Playwright-only
    ignore_https_errors: bool = True  # Playwright-only

    # Optional extra metadata embedded in JSON output.
    run_metadata: dict[str, Any] = field(default_factory=dict)

    openssl_path: str = "openssl"
    provider_path: str = ""
    library_path: str = ""  # LD_LIBRARY_PATH for custom OpenSSL builds

    def __post_init__(self) -> None:
        self.openssl_path = os.environ.get("PQC_BENCH_OPENSSL", self.openssl_path)
        self.provider_path = os.environ.get("PQC_BENCH_PROVIDER_PATH", self.provider_path)
        self.library_path = os.environ.get("PQC_BENCH_LD_LIBRARY_PATH", self.library_path)
        browser_executable = os.environ.get("PQC_BENCH_BROWSER_EXECUTABLE")
        if browser_executable:
            self.browser_executable = browser_executable

    def get_subprocess_env(self) -> dict[str, str] | None:
        """Get environment dict for subprocess calls with LD_LIBRARY_PATH if needed."""
        if not self.library_path:
            return None
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = self.library_path
        return env


@dataclass
class HttpBenchmarkRunResult:
    """Complete HTTP benchmark run results."""

    url: str
    client: HttpClient
    reuse: HttpReuseMode
    environment: Any  # models.Environment (import avoided to keep module dependency-light)
    tls: TlsInfo | None
    samples_requested: int
    warm_up: int
    concurrency: int
    timeout_s: int | None = None
    groups: str | None = None
    alpn: str | None = None
    browser: str | None = None
    headless: bool | None = None
    ignore_https_errors: bool | None = None
    browser_executable: str | None = None
    samples: list[HttpSampleResult] = field(default_factory=list)
    run_metadata: dict[str, Any] = field(default_factory=dict)
    run_started_at: datetime | None = None
    run_finished_at: datetime | None = None
    total_duration_s: float | None = None
    measured_duration_s: float | None = None

    @property
    def success_count(self) -> int:
        return sum(1 for s in self.samples if s.ok)

    @property
    def fail_count(self) -> int:
        return sum(1 for s in self.samples if not s.ok)

    def timings_us(self) -> dict[str, list[float]]:
        """Get raw timings per metric (successful samples only)."""
        out: dict[str, list[float]] = {
            "ttfb_us": [],
            "total_us": [],
            "ttfb_e2e_us": [],
            "total_e2e_us": [],
            "dns_us": [],
            "tcp_us": [],
            "tls_us": [],
        }
        for s in self.samples:
            if not s.ok:
                continue
            if s.ttfb_us is not None:
                out["ttfb_us"].append(s.ttfb_us)
            if s.total_us is not None:
                out["total_us"].append(s.total_us)
            if s.ttfb_e2e_us is not None:
                out["ttfb_e2e_us"].append(s.ttfb_e2e_us)
            if s.total_e2e_us is not None:
                out["total_e2e_us"].append(s.total_e2e_us)
            if s.dns_us is not None:
                out["dns_us"].append(s.dns_us)
            if s.tcp_us is not None:
                out["tcp_us"].append(s.tcp_us)
            if s.tls_us is not None:
                out["tls_us"].append(s.tls_us)
        # Drop empty metrics for cleaner output
        return {k: v for k, v in out.items() if v}

    def stats(self) -> dict[str, Stats]:
        """Compute Stats per metric from successful samples."""
        stats: dict[str, Stats] = {}
        for metric, timings in self.timings_us().items():
            with_timings = [t for t in timings if t is not None and t > 0]
            if with_timings:
                stats[metric] = calculate_stats(with_timings)
        return stats


def parse_https_url(url: str) -> ParsedUrl:
    """Parse and validate an HTTPS URL."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only https:// URLs are supported")

    if not parsed.hostname:
        raise ValueError("URL hostname is required")

    host = parsed.hostname
    port = parsed.port or 443
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"

    return ParsedUrl(raw=url, host=host, port=port, target=target, sni=host)


def _build_provider_args(provider_path: str) -> list[str]:
    args = ["-provider", "oqsprovider", "-provider", "default"]
    if provider_path:
        return ["-provider-path", provider_path, *args]
    return args


def _parse_http_status_from_response(prefix: bytes) -> int | None:
    try:
        text = prefix.decode("iso-8859-1", errors="replace")
    except Exception:
        return None
    first_line = text.splitlines()[0] if text.splitlines() else ""
    match = re.match(r"^HTTP/\d+(?:\.\d+)?\s+(\d{3})\b", first_line)
    if match:
        return int(match.group(1))
    return None


def parse_openssl_s_client_brief(output: str) -> TlsInfo:
    """Best-effort parse of `openssl s_client -brief` output."""
    # Protocol:
    # - OpenSSL <=3.3: "Protocol  : TLSv1.3" (older formatting)
    # - Full output: "Protocol: TLSv1.3"
    # - OpenSSL 3.4+ -brief: "Protocol version: TLSv1.3"
    protocol = None
    match = re.search(r"Protocol\s+version:\s*(\S+)", output)
    if match:
        protocol = match.group(1)
    else:
        match = re.search(r"Protocol\s*:\s*(\S+)", output)
        if match:
            protocol = match.group(1)

    # Cipher:
    # - OpenSSL <=3.3: "Cipher    : TLS_AES_256_GCM_SHA384"
    # - Full output: "Cipher is TLS_AES_256_GCM_SHA384"
    # - OpenSSL 3.4+ -brief: "Ciphersuite: TLS_AES_256_GCM_SHA384"
    cipher = None
    match = re.search(r"Ciphersuite:\s*(\S+)", output)
    if match:
        cipher = match.group(1)
    else:
        match = re.search(r"Cipher\s*(?:\:|is)\s*(\S+)", output)
        if match:
            cipher = match.group(1)

    # ALPN: "ALPN protocol: h2"
    alpn = None
    match = re.search(r"ALPN protocol:\s*(\S+)", output)
    if match:
        alpn = match.group(1)

    # Key exchange group (best-effort): "Server Temp Key: X25519, 253 bits" or "X25519MLKEM768"
    key_exchange = None
    match = re.search(r"Server Temp Key:\s*(.+)", output)
    if match:
        raw = match.group(1).strip()
        # Take first token before comma/space for compact "group" label
        key_exchange = re.split(r"[, \t]", raw, maxsplit=1)[0] or raw

    signature_type = None
    match = re.search(r"Signature type:\s*(\S+)", output)
    if match:
        signature_type = match.group(1)
    else:
        match = re.search(r"Peer signature type:\s*(\S+)", output)
        if match:
            signature_type = match.group(1)

    return TlsInfo(
        protocol=protocol,
        cipher=cipher,
        alpn=alpn,
        key_exchange=key_exchange,
        signature_type=signature_type,
    )


def _probe_openssl_tls_info(parsed_url: ParsedUrl, config: HttpBenchmarkConfig) -> TlsInfo | None:
    import subprocess

    cmd = [
        config.openssl_path,
        "s_client",
        "-brief",
        "-connect",
        f"{parsed_url.host}:{parsed_url.port}",
        "-tls1_3",
        "-servername",
        parsed_url.sni,
        *_build_provider_args(config.provider_path),
    ]
    if config.groups:
        cmd.extend(["-groups", config.groups])
    if config.alpn:
        cmd.extend(["-alpn", config.alpn])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(5, config.timeout),
            stdin=subprocess.DEVNULL,
            env=config.get_subprocess_env(),
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    combined = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    if not combined:
        return None
    tls_info = parse_openssl_s_client_brief(combined)

    # OpenSSL 3.4 `s_client -brief` does not report the negotiated group for some PQC/hybrid groups.
    # Use the requested group as a fallback if exactly one group was requested.
    if tls_info.key_exchange is None and config.groups:
        group = config.groups.strip()
        if group and not re.search(r"[\s:,]", group):
            tls_info = TlsInfo(
                protocol=tls_info.protocol,
                cipher=tls_info.cipher,
                alpn=tls_info.alpn,
                key_exchange=group,
                signature_type=tls_info.signature_type,
            )

    return tls_info


def _build_http_request(parsed_url: ParsedUrl) -> bytes:
    # Minimal HTTP/1.1 GET with Connection: close for deterministic total time.
    return (
        f"GET {parsed_url.target} HTTP/1.1\r\n"
        f"Host: {parsed_url.host}\r\n"
        f"User-Agent: pqc-bench/{__version__}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii", errors="strict")


def _drain_stream(stream, buffer: bytearray) -> None:
    try:
        for chunk in iter(lambda: stream.read(4096), b""):
            if not chunk:
                break
            buffer.extend(chunk)
    except Exception:
        # Best-effort; errors are handled by the main process return code.
        return


def _run_openssl_http_once(
    parsed_url: ParsedUrl,
    config: HttpBenchmarkConfig,
    session_file: str | None,
    capture_bytes_limit: int = 20 * 1024 * 1024,
) -> HttpSampleResult:
    import selectors
    import subprocess

    cmd: list[str] = [
        config.openssl_path,
        "s_client",
        "-quiet",
        "-connect",
        f"{parsed_url.host}:{parsed_url.port}",
        "-tls1_3",
        "-servername",
        parsed_url.sni,
        *_build_provider_args(config.provider_path),
    ]
    if config.groups:
        cmd.extend(["-groups", config.groups])
    if config.alpn:
        cmd.extend(["-alpn", config.alpn])
    if session_file:
        try:
            if os.path.exists(session_file) and os.path.getsize(session_file) > 0:
                cmd.extend(["-sess_in", session_file])
        except OSError:
            # Skip sess_in if the session file cannot be read.
            pass
        cmd.extend(["-sess_out", session_file])

    start = time.perf_counter()
    stderr_buf: bytearray = bytearray()

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            env=config.get_subprocess_env(),
        )
    except FileNotFoundError as e:
        return HttpSampleResult(ok=False, error=str(e))

    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None

    stderr_thread = Thread(target=_drain_stream, args=(proc.stderr, stderr_buf), daemon=True)
    stderr_thread.start()

    # Send request then close stdin so s_client doesn't wait for more input.
    try:
        proc.stdin.write(_build_http_request(parsed_url))
        proc.stdin.flush()
    except Exception as e:
        with contextlib.suppress(Exception):
            proc.kill()
        return HttpSampleResult(ok=False, error=str(e))
    finally:
        with contextlib.suppress(Exception):
            proc.stdin.close()

    deadline = start + float(config.timeout)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)

    # Wait for first byte (TTFB).
    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            with contextlib.suppress(Exception):
                proc.kill()
            stderr_thread.join(timeout=0.2)
            return HttpSampleResult(
                ok=False,
                error=f"Timeout after {config.timeout}s waiting for TTFB",
            )

        events = selector.select(timeout=remaining)
        if not events:
            continue

        first = proc.stdout.read(1)
        if first:
            break

        # EOF before any data.
        rc = proc.poll()
        if rc is not None:
            stderr_thread.join(timeout=0.2)
            err = stderr_buf.decode("utf-8", errors="replace").strip()
            return HttpSampleResult(ok=False, error=err or f"s_client exited with code {rc}")

    ttfb_us = (time.perf_counter() - start) * 1_000_000

    # Read the rest until EOF (or until capture limit / timeout).
    response_prefix = bytearray(first)
    total_read = len(response_prefix)

    while True:
        if total_read >= capture_bytes_limit:
            with contextlib.suppress(Exception):
                proc.kill()
            stderr_thread.join(timeout=0.2)
            return HttpSampleResult(ok=False, error="Response too large (capture limit exceeded)")

        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            with contextlib.suppress(Exception):
                proc.kill()
            stderr_thread.join(timeout=0.2)
            return HttpSampleResult(
                ok=False,
                error=f"Timeout after {config.timeout}s reading response",
            )

        events = selector.select(timeout=remaining)
        if not events:
            continue

        chunk = proc.stdout.read(4096)
        if not chunk:
            break
        # Keep only a prefix for status parsing, but still read all to get total time.
        if len(response_prefix) < 4096:
            need = 4096 - len(response_prefix)
            response_prefix.extend(chunk[:need])
        total_read += len(chunk)

    # Ensure process exited (within remaining time).
    remaining = max(0.0, deadline - time.perf_counter())
    with contextlib.suppress(Exception):
        proc.wait(timeout=remaining)

    stderr_thread.join(timeout=0.2)
    total_us = (time.perf_counter() - start) * 1_000_000

    rc = proc.returncode
    if rc and rc != 0:
        err = stderr_buf.decode("utf-8", errors="replace").strip()
        return HttpSampleResult(
            ok=False,
            ttfb_us=ttfb_us,
            total_us=total_us,
            error=err or f"exit={rc}",
        )

    status = _parse_http_status_from_response(bytes(response_prefix))
    ok = status is not None and 200 <= status <= 399

    return HttpSampleResult(ok=ok, status=status, ttfb_us=ttfb_us, total_us=total_us)


def _convert_playwright_timing_to_sample(
    timing: dict[str, Any],
    status: int | None,
) -> HttpSampleResult:
    # Playwright timings use milliseconds relative to startTime.
    # Convert durations from milliseconds to microseconds.
    def duration_ms(start_key: str, end_key: str) -> float | None:
        start = timing.get(start_key)
        end = timing.get(end_key)
        if start is None or end is None:
            return None
        try:
            start_f = float(start)
            end_f = float(end)
        except (TypeError, ValueError):
            return None
        if start_f <= 0 or end_f <= 0 or end_f < start_f:
            return None
        return end_f - start_f

    dns_ms = duration_ms("domainLookupStart", "domainLookupEnd")
    tcp_ms = duration_ms("connectStart", "connectEnd")

    tls_ms = None
    secure_start = timing.get("secureConnectionStart")
    connect_end = timing.get("connectEnd")
    try:
        secure_start_f = float(secure_start) if secure_start is not None else 0.0
        connect_end_f = float(connect_end) if connect_end is not None else 0.0
        if secure_start_f > 0 and connect_end_f > secure_start_f:
            tls_ms = connect_end_f - secure_start_f
    except (TypeError, ValueError):
        tls_ms = None

    ttfb_ms = duration_ms("requestStart", "responseStart")
    total_ms = duration_ms("requestStart", "responseEnd")

    def duration_ms_allow_zero_start(start_key: str, end_key: str) -> float | None:
        start = timing.get(start_key)
        end = timing.get(end_key)
        if start is None or end is None:
            return None
        try:
            start_f = float(start)
            end_f = float(end)
        except (TypeError, ValueError):
            return None
        if start_f < 0 or end_f <= 0 or end_f < start_f:
            return None
        return end_f - start_f

    # End-to-end: include DNS/TCP/TLS by starting at fetchStart (0 is valid).
    ttfb_e2e_ms = duration_ms_allow_zero_start("fetchStart", "responseStart")
    total_e2e_ms = duration_ms_allow_zero_start("fetchStart", "responseEnd")

    ok = status is not None and 200 <= status <= 399

    return HttpSampleResult(
        ok=ok,
        status=status,
        ttfb_us=ttfb_ms * 1000 if ttfb_ms is not None else None,
        total_us=total_ms * 1000 if total_ms is not None else None,
        ttfb_e2e_us=ttfb_e2e_ms * 1000 if ttfb_e2e_ms is not None else None,
        total_e2e_us=total_e2e_ms * 1000 if total_e2e_ms is not None else None,
        dns_us=dns_ms * 1000 if dns_ms is not None else None,
        tcp_us=tcp_ms * 1000 if tcp_ms is not None else None,
        tls_us=tls_ms * 1000 if tls_ms is not None else None,
    )


def _run_playwright_http(
    config: HttpBenchmarkConfig,
) -> list[HttpSampleResult]:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError as e:
        raise RuntimeError(
            "Playwright is not installed. Install with: pip install 'pqc-bench[web]' "
            "or pip install playwright && playwright install"
        ) from e

    results: list[HttpSampleResult] = []
    timeout_ms = int(max(1, config.timeout) * 1000)

    with sync_playwright() as p:
        browser_type = getattr(p, config.browser, None)
        if browser_type is None:
            raise RuntimeError(f"Unknown Playwright browser '{config.browser}'")

        launch_kwargs: dict[str, Any] = {"headless": config.headless}
        if config.browser_executable:
            launch_kwargs["executable_path"] = config.browser_executable
        browser = browser_type.launch(**launch_kwargs)
        try:
            if config.reuse == HttpReuseMode.PAGE:
                context = browser.new_context(ignore_https_errors=config.ignore_https_errors)
                page = context.new_page()

            for i in range(config.warm_up + config.samples):
                if config.reuse == HttpReuseMode.NONE:
                    context = browser.new_context(ignore_https_errors=config.ignore_https_errors)
                    page = context.new_page()
                elif config.reuse == HttpReuseMode.CONTEXT:
                    if i == 0:
                        context = browser.new_context(
                            ignore_https_errors=config.ignore_https_errors
                        )
                    page = context.new_page()
                elif config.reuse == HttpReuseMode.PAGE:
                    # page/context already created
                    pass
                else:
                    raise RuntimeError(
                        f"Unsupported reuse mode for Playwright: {config.reuse.value}"
                    )

                try:
                    response = page.goto(config.url, wait_until="load", timeout=timeout_ms)
                    if response is None:
                        sample = HttpSampleResult(ok=False, error="No response (navigation failed)")
                    else:
                        # Prefer Web Performance Navigation Timing for portability.
                        # Avoid relying on response timing APIs that differ by Playwright version.
                        timing = page.evaluate(
                            "() => {"
                            "  const nav = performance.getEntriesByType('navigation')[0];"
                            "  if (!nav) return null;"
                            "  return nav.toJSON ? nav.toJSON() : JSON.parse(JSON.stringify(nav));"
                            "}"
                        )
                        if not isinstance(timing, dict):
                            sample = HttpSampleResult(
                                ok=False, error="Navigation timing unavailable in browser"
                            )
                        else:
                            sample = _convert_playwright_timing_to_sample(timing, response.status)
                except PlaywrightTimeoutError:
                    sample = HttpSampleResult(ok=False, error=f"Timeout after {config.timeout}s")
                except Exception as e:
                    sample = HttpSampleResult(ok=False, error=str(e))
                finally:
                    # Close per-sample page/context depending on reuse mode.
                    if config.reuse in (HttpReuseMode.NONE, HttpReuseMode.CONTEXT):
                        with contextlib.suppress(Exception):
                            page.close()
                    if config.reuse == HttpReuseMode.NONE:
                        with contextlib.suppress(Exception):
                            context.close()

                if i >= config.warm_up:
                    results.append(sample)

            if config.reuse == HttpReuseMode.PAGE:
                with contextlib.suppress(Exception):
                    page.close()
                with contextlib.suppress(Exception):
                    context.close()
        finally:
            browser.close()

    return results


def run_http_benchmark(config: HttpBenchmarkConfig) -> HttpBenchmarkRunResult:
    """Run an HTTP benchmark based on the provided configuration."""
    parsed_url = parse_https_url(config.url)
    environment = capture_environment(
        config.openssl_path, config.provider_path, config.library_path
    )

    if config.samples < 1:
        raise ValueError("samples must be >= 1")
    if config.warm_up < 0:
        raise ValueError("warm_up must be >= 0")
    if config.concurrency < 1:
        raise ValueError("concurrency must be >= 1")

    if config.client == HttpClient.PLAYWRIGHT:
        if config.concurrency != 1:
            raise ValueError("Playwright client currently supports --concurrency=1 only")
        if config.reuse == HttpReuseMode.SESSION:
            raise ValueError("--reuse=session is only supported for --client=openssl")
        tls_info = None
        run_started_at = datetime.now()
        total_start = time.perf_counter()
        samples = _run_playwright_http(config)
        total_duration_s = time.perf_counter() - total_start
        run_finished_at = datetime.now()
        return HttpBenchmarkRunResult(
            url=config.url,
            client=config.client,
            reuse=config.reuse,
            environment=environment,
            tls=tls_info,
            samples_requested=config.samples,
            warm_up=config.warm_up,
            concurrency=config.concurrency,
            timeout_s=config.timeout,
            browser=config.browser,
            headless=config.headless,
            ignore_https_errors=config.ignore_https_errors,
            browser_executable=config.browser_executable,
            samples=samples,
            run_metadata=config.run_metadata,
            run_started_at=run_started_at,
            run_finished_at=run_finished_at,
            total_duration_s=total_duration_s,
            measured_duration_s=total_duration_s,
        )

    # OpenSSL client
    if config.reuse in (HttpReuseMode.CONTEXT, HttpReuseMode.PAGE):
        raise ValueError("--reuse=context/page is only supported for --client=playwright")
    if config.reuse == HttpReuseMode.SESSION and config.concurrency != 1:
        raise ValueError("--reuse=session requires --concurrency=1")

    tls_info = _probe_openssl_tls_info(parsed_url, config)

    session_file: str | None = None
    if config.reuse == HttpReuseMode.SESSION:
        # Keep a session ticket file for the duration of the run.
        fd, session_file = tempfile.mkstemp(prefix="pqc-bench-sess-", suffix=".pem")
        os.close(fd)

    try:
        run_started_at = datetime.now()
        total_start = time.perf_counter()

        # Warm-up runs (discarded)
        for _ in range(config.warm_up):
            _run_openssl_http_once(parsed_url, config, session_file)

        measured_start = time.perf_counter()

        samples: list[HttpSampleResult] = []
        if config.concurrency == 1:
            for _ in range(config.samples):
                samples.append(_run_openssl_http_once(parsed_url, config, session_file))
        else:
            with ThreadPoolExecutor(max_workers=config.concurrency) as executor:
                futures = {
                    executor.submit(_run_openssl_http_once, parsed_url, config, session_file): i
                    for i in range(config.samples)
                }
                samples_by_index: list[HttpSampleResult | None] = [None] * config.samples
                for future in as_completed(futures):
                    idx = futures[future]
                    samples_by_index[idx] = future.result()
                samples = [s for s in samples_by_index if s is not None]

        end = time.perf_counter()
        total_duration_s = end - total_start
        measured_duration_s = end - measured_start
        run_finished_at = datetime.now()

        return HttpBenchmarkRunResult(
            url=config.url,
            client=config.client,
            reuse=config.reuse,
            environment=environment,
            tls=tls_info,
            samples_requested=config.samples,
            warm_up=config.warm_up,
            concurrency=config.concurrency,
            timeout_s=config.timeout,
            groups=config.groups,
            alpn=config.alpn,
            samples=samples,
            run_metadata=config.run_metadata,
            run_started_at=run_started_at,
            run_finished_at=run_finished_at,
            total_duration_s=total_duration_s,
            measured_duration_s=measured_duration_s,
        )
    finally:
        if session_file:
            with contextlib.suppress(OSError):
                os.remove(session_file)


def format_http_text(run: HttpBenchmarkRunResult) -> str:
    lines: list[str] = []
    lines.append("PQC HTTP Benchmark Results")
    lines.append("=" * 60)
    lines.append(f"URL: {run.url}")
    lines.append(
        f"Client: {run.client.value} (reuse={run.reuse.value}, concurrency={run.concurrency})"
    )
    if run.client == HttpClient.OPENSSL:
        if run.groups:
            lines.append(f"OpenSSL groups: {run.groups}")
        if run.alpn:
            lines.append(f"OpenSSL ALPN: {run.alpn}")
    elif run.client == HttpClient.PLAYWRIGHT:
        if run.browser:
            lines.append(f"Browser: {run.browser} ({'headless' if run.headless else 'headed'})")
        if run.ignore_https_errors is not None:
            lines.append(f"Ignore HTTPS errors: {run.ignore_https_errors}")
        lines.append("Note: *_e2e_* metrics include DNS/TCP/TLS (start=fetchStart).")
    lines.append(
        f"Environment: OpenSSL {getattr(run.environment, 'openssl_version', 'unknown')}, "
        f"oqs-provider {getattr(run.environment, 'oqs_provider_version', 'unknown')}, "
        f"{getattr(run.environment, 'platform', 'unknown')}"
    )
    if getattr(run.environment, "cpu_model", None):
        lines.append(f"CPU: {run.environment.cpu_model}")

    if run.tls:
        tls = run.tls.to_dict()
        if tls:
            lines.append("TLS: " + ", ".join(f"{k}={v}" for k, v in tls.items()))

    lines.append("")
    lines.append(f"Samples: {run.samples_requested} (warm-up discarded: {run.warm_up})")
    lines.append(f"Success: {run.success_count}, Failed: {run.fail_count}")

    if run.fail_count:
        first_err = next((s.error for s in run.samples if not s.ok and s.error), None)
        if first_err:
            lines.append(f"First error: {first_err}")

    lines.append("")
    stats = run.stats()
    if not stats:
        lines.append("No successful samples to compute statistics.")
        return "\n".join(lines)

    lines.append("Metrics (microseconds)")
    lines.append("-" * 60)
    for metric in [
        "ttfb_e2e_us",
        "total_e2e_us",
        "ttfb_us",
        "total_us",
        "dns_us",
        "tcp_us",
        "tls_us",
    ]:
        if metric not in stats:
            continue
        s = stats[metric]
        lines.append(
            f"{metric:<10} median={s.median:>8.1f}  p95={s.p95:>8.1f}  p99={s.p99:>8.1f}  "
            f"n={s.count}"
        )

    return "\n".join(lines)


def format_http_json(run: HttpBenchmarkRunResult, include_samples: bool = True) -> str:
    import json

    output: dict[str, Any] = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "version": __version__,
            "client": run.client.value,
            "reuse": run.reuse.value,
            "samples": run.samples_requested,
            "warm_up": run.warm_up,
            "concurrency": run.concurrency,
            "success_count": run.success_count,
            "fail_count": run.fail_count,
        },
        "environment": {
            "openssl_version": getattr(run.environment, "openssl_version", "unknown"),
            "oqs_provider_version": getattr(run.environment, "oqs_provider_version", "unknown"),
            "platform": getattr(run.environment, "platform", "unknown"),
            "cpu_model": getattr(run.environment, "cpu_model", None),
            "kernel_version": getattr(run.environment, "kernel_version", None),
        },
        "url": run.url,
        "tls": run.tls.to_dict() if run.tls else None,
        "metrics": {},
    }

    if run.timeout_s is not None:
        output["metadata"]["timeout_s"] = run.timeout_s
    if run.run_started_at is not None:
        output["metadata"]["run_started_at"] = run.run_started_at.isoformat()
    if run.run_finished_at is not None:
        output["metadata"]["run_finished_at"] = run.run_finished_at.isoformat()
    if run.total_duration_s is not None:
        output["metadata"]["run_duration_s"] = run.total_duration_s
        if run.total_duration_s > 0:
            output["metadata"]["requests_per_sec"] = run.success_count / run.total_duration_s
    if run.measured_duration_s is not None:
        output["metadata"]["measured_duration_s"] = run.measured_duration_s
        if run.measured_duration_s > 0:
            output["metadata"]["measured_requests_per_sec"] = (
                run.success_count / run.measured_duration_s
            )

    if run.samples_requested > 0:
        output["metadata"]["success_rate"] = run.success_count / run.samples_requested
        output["metadata"]["fail_rate"] = run.fail_count / run.samples_requested

    if run.run_metadata:
        output["metadata"]["context"] = run.run_metadata

    if run.client == HttpClient.OPENSSL:
        if run.groups is not None:
            output["metadata"]["groups"] = run.groups
        if run.alpn is not None:
            output["metadata"]["alpn"] = run.alpn
    if run.client == HttpClient.PLAYWRIGHT:
        if run.browser is not None:
            output["metadata"]["browser"] = run.browser
        if run.headless is not None:
            output["metadata"]["headless"] = run.headless
        if run.ignore_https_errors is not None:
            output["metadata"]["ignore_https_errors"] = run.ignore_https_errors
        if run.browser_executable is not None:
            output["metadata"]["browser_executable"] = run.browser_executable

    # Add metrics and raw timings (successful samples only).
    metrics: dict[str, Any] = {}
    stats = run.stats()
    timings_by_metric = run.timings_us()

    for metric, s in stats.items():
        timings = [t for t in timings_by_metric.get(metric, []) if t > 0]
        metrics[metric] = {
            "median_us": s.median,
            "p95_us": s.p95,
            "p99_us": s.p99,
            "p999_us": calculate_percentile(sorted(timings), 99.9) if timings else None,
            "min_us": s.min,
            "max_us": s.max,
            "mean_us": s.mean,
            "count": s.count,
        }
        if s.stdev is not None:
            metrics[metric]["stdev_us"] = s.stdev
        if timings:
            metrics[metric]["timings_us"] = timings
    output["metrics"] = metrics

    if include_samples:
        output["samples"] = [s.to_dict() for s in run.samples]

    if run.fail_count:
        output["error"] = "partial_failure"
        timeout_count = 0
        failures_by_error: dict[str, int] = {}
        for sample in run.samples:
            if sample.ok:
                continue
            if sample.error and sample.error.startswith("Timeout after"):
                timeout_count += 1
            err_key = (sample.error or "unknown").strip()
            if len(err_key) > 200:
                err_key = err_key[:200] + "…"
            failures_by_error[err_key] = failures_by_error.get(err_key, 0) + 1
        output["metadata"]["timeout_count"] = timeout_count
        output["metadata"]["failures_by_error"] = failures_by_error

    return json.dumps(output, indent=2)


def format_http_csv(run: HttpBenchmarkRunResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "url",
            "client",
            "reuse",
            "concurrency",
            "timeout_s",
            "groups",
            "alpn",
            "browser",
            "headless",
            "ignore_https_errors",
            "browser_executable",
            "metric",
            "median_us",
            "p95_us",
            "p99_us",
            "min_us",
            "max_us",
            "mean_us",
            "stdev_us",
            "count",
            "success_count",
            "fail_count",
            "tls_protocol",
            "tls_cipher",
            "tls_alpn",
            "tls_key_exchange",
        ]
    )

    tls = run.tls or TlsInfo()
    stats = run.stats()

    for metric, s in stats.items():
        writer.writerow(
            [
                run.url,
                run.client.value,
                run.reuse.value,
                run.concurrency,
                run.timeout_s if run.timeout_s is not None else "",
                run.groups or "",
                run.alpn or "",
                run.browser or "",
                str(run.headless) if run.headless is not None else "",
                str(run.ignore_https_errors) if run.ignore_https_errors is not None else "",
                run.browser_executable or "",
                metric,
                f"{s.median:.2f}",
                f"{s.p95:.2f}",
                f"{s.p99:.2f}",
                f"{s.min:.2f}",
                f"{s.max:.2f}",
                f"{s.mean:.2f}",
                f"{s.stdev:.2f}" if s.stdev is not None else "",
                s.count,
                run.success_count,
                run.fail_count,
                tls.protocol or "",
                tls.cipher or "",
                tls.alpn or "",
                tls.key_exchange or "",
            ]
        )

    return output.getvalue()
