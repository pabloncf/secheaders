"""Tests for the CLI skeleton (Phase 1)."""

from __future__ import annotations

import pytest

from secheaders import __version__
from secheaders.cli import EXIT_SUCCESS, main, parse_args


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


def test_main_returns_success(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["https://example.com"])
    assert exit_code == EXIT_SUCCESS
    assert "example.com" in capsys.readouterr().out
