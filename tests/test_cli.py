"""Tests for the CLI (parsing plus end-to-end behavior)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from secheaders import __version__
from secheaders.cli import (
    EXIT_ERROR,
    EXIT_SUCCESS,
    EXIT_THRESHOLD,
    main,
    parse_args,
)

STRONG_RESPONSE_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "permissions-policy": "geolocation=()",
    "referrer-policy": "strict-origin-when-cross-origin",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
}


def test_url_or_input_is_required() -> None:
    # Neither a URL nor --input given -> usage error.
    with pytest.raises(SystemExit) as exc:
        parse_args([])
    assert exc.value.code == 2


def test_url_and_input_are_mutually_exclusive() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["https://example.com", "--input", "urls.txt"])
    assert exc.value.code == 2


def test_defaults() -> None:
    args = parse_args(["https://example.com"])
    assert args.url == "https://example.com"
    assert args.format == "terminal"
    assert args.output is None
    assert args.verbose is False


def test_invalid_format_exits_with_code_2() -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["https://example.com", "--format", "xml"])
    assert exc.value.code == 2


def test_flags_are_parsed() -> None:
    args = parse_args(["https://example.com", "-o", "report.json", "-f", "json", "-v"])
    assert args.output == "report.json"
    assert args.format == "json"
    assert args.verbose is True


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


@respx.mock
def test_main_returns_success(capsys: pytest.CaptureFixture[str]) -> None:
    respx.get("https://example.com").mock(return_value=httpx.Response(200))
    exit_code = main(["https://example.com"])
    assert exit_code == EXIT_SUCCESS
    assert "example.com" in capsys.readouterr().out


@respx.mock
def test_json_export_to_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, headers=STRONG_RESPONSE_HEADERS)
    )
    exit_code = main(["https://example.com", "--format", "json"])
    assert exit_code == EXIT_SUCCESS
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["grade"] == "A+"


@respx.mock
def test_output_writes_file(tmp_path) -> None:
    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, headers=STRONG_RESPONSE_HEADERS)
    )
    out = tmp_path / "report.json"
    exit_code = main(["https://example.com", "--format", "json", "--output", str(out)])
    assert exit_code == EXIT_SUCCESS
    assert json.loads(out.read_text())["grade"] == "A+"


@respx.mock
def test_fail_under_returns_threshold_when_below(
    capsys: pytest.CaptureFixture[str],
) -> None:
    respx.get("https://example.com").mock(return_value=httpx.Response(200))
    exit_code = main(["https://example.com", "--fail-under", "80", "--quiet"])
    assert exit_code == EXIT_THRESHOLD


@respx.mock
def test_fail_under_passes_when_above(
    capsys: pytest.CaptureFixture[str],
) -> None:
    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, headers=STRONG_RESPONSE_HEADERS)
    )
    exit_code = main(["https://example.com", "--fail-under", "80", "--quiet"])
    assert exit_code == EXIT_SUCCESS


@respx.mock
def test_output_error_returns_exit_error() -> None:
    respx.get("https://example.com").mock(
        return_value=httpx.Response(200, headers=STRONG_RESPONSE_HEADERS)
    )
    exit_code = main(
        [
            "https://example.com",
            "--format",
            "json",
            "--output",
            "/nonexistent-dir/report.json",
        ]
    )
    assert exit_code == EXIT_ERROR
