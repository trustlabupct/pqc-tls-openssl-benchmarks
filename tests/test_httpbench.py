"""Tests for HTTP benchmark layer."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from pqc_bench.httpbench import (
    HttpBenchmarkRunResult,
    HttpClient,
    HttpReuseMode,
    HttpSampleResult,
    _convert_playwright_timing_to_sample,
    _parse_http_status_from_response,
    _probe_openssl_tls_info,
    parse_https_url,
    parse_openssl_s_client_brief,
)
from pqc_bench.models import Environment


class TestParseHttpsUrl:
    def test_rejects_non_https(self):
        with pytest.raises(ValueError, match="https"):
            parse_https_url("http://example.com/")

    def test_parses_host_port_and_target(self):
        p = parse_https_url("https://example.com:8443/path?q=1")
        assert p.host == "example.com"
        assert p.port == 8443
        assert p.target == "/path?q=1"


class TestParseOpensslBrief:
    def test_parses_protocol_cipher_alpn_and_group(self):
        output = """CONNECTED(00000003)
Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
ALPN protocol: h2
Server Temp Key: X25519MLKEM768
Signature type: RSA-PSS
"""
        info = parse_openssl_s_client_brief(output)
        assert info.protocol == "TLSv1.3"
        assert info.cipher == "TLS_AES_256_GCM_SHA384"
        assert info.alpn == "h2"
        assert info.key_exchange == "X25519MLKEM768"
        assert info.signature_type == "RSA-PSS"

    def test_group_from_server_temp_key_prefix(self):
        output = "Server Temp Key: X25519, 253 bits"
        info = parse_openssl_s_client_brief(output)
        assert info.key_exchange == "X25519"


class TestProbeOpensslTlsInfo:
    def test_falls_back_to_requested_group_when_brief_has_no_group(self):
        # OpenSSL 3.4 `s_client -brief` omits Server Temp Key for PQC/hybrid groups.
        from pqc_bench.httpbench import HttpBenchmarkConfig

        output = """Connecting to 127.0.0.1
depth=0 CN=localhost
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=localhost
Hash used: SHA256
Signature type: RSA-PSS
Verification error: self-signed certificate
DONE
"""

        config = HttpBenchmarkConfig(
            url="https://example.com/",
            groups="X25519MLKEM768",
        )
        parsed_url = parse_https_url(config.url)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=output, stderr="", returncode=0)
            tls = _probe_openssl_tls_info(parsed_url, config)

        assert tls is not None
        assert tls.protocol == "TLSv1.3"
        assert tls.cipher == "TLS_AES_256_GCM_SHA384"
        assert tls.key_exchange == "X25519MLKEM768"


class TestHttpStatusParsing:
    def test_parses_http_status(self):
        resp = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        assert _parse_http_status_from_response(resp) == 200

    def test_returns_none_for_non_http(self):
        assert _parse_http_status_from_response(b"not http") is None


class TestPlaywrightTimingConversion:
    def test_converts_ms_to_us(self):
        timing = {
            "fetchStart": 5,
            "domainLookupStart": 10,
            "domainLookupEnd": 20,
            "connectStart": 20,
            "connectEnd": 50,
            "secureConnectionStart": 30,
            "requestStart": 60,
            "responseStart": 80,
            "responseEnd": 100,
        }
        sample = _convert_playwright_timing_to_sample(timing, status=200)
        assert sample.ok is True
        assert sample.dns_us == 10_000
        assert sample.tcp_us == 30_000
        assert sample.tls_us == 20_000
        assert sample.ttfb_us == 20_000
        assert sample.total_us == 40_000
        assert sample.ttfb_e2e_us == 75_000
        assert sample.total_e2e_us == 95_000

    def test_missing_or_invalid_values_become_none(self):
        timing = {"requestStart": 0, "responseStart": 0, "responseEnd": 0}
        sample = _convert_playwright_timing_to_sample(timing, status=200)
        assert sample.ttfb_us is None
        assert sample.total_us is None


class TestHttpCliPlaywrightMissing:
    @patch(
        "pqc_bench.httpbench._run_playwright_http",
        side_effect=RuntimeError("Playwright is not installed"),
    )
    def test_http_playwright_errors_cleanly(self, _mock_run):
        from click.testing import CliRunner

        from pqc_bench.cli import main

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["-q", "http", "--url", "https://example.com/", "--client", "playwright"],
        )
        assert result.exit_code != 0
        assert "playwright" in result.output.lower()


class TestHttpCliOpensslHappyPath:
    @patch("pqc_bench.httpbench.run_http_benchmark")
    @patch("pqc_bench.cli.check_all_dependencies")
    def test_http_openssl_runs_with_mocked_runner(self, mock_deps, mock_run):
        from click.testing import CliRunner

        from pqc_bench.cli import main

        mock_deps.return_value = MagicMock(overall_valid=True)

        env = Environment(
            openssl_version="3.2.0",
            oqs_provider_version="0.10.0",
            platform="Linux x86_64",
            captured_at=datetime.now(),
        )
        mock_run.return_value = HttpBenchmarkRunResult(
            url="https://example.com/",
            client=HttpClient.OPENSSL,
            reuse=HttpReuseMode.NONE,
            environment=env,
            tls=None,
            samples_requested=1,
            warm_up=0,
            concurrency=1,
            samples=[HttpSampleResult(ok=True, status=200, ttfb_us=100.0, total_us=200.0)],
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "-q",
                "http",
                "--url",
                "https://example.com/",
                "--client",
                "openssl",
                "--samples",
                "1",
            ],
        )
        assert result.exit_code == 0
        assert "PQC HTTP Benchmark Results" in result.output
