"""Tests for terminal rendering (Phase 5)."""

from __future__ import annotations

from rich.console import Console
from tests.test_analyzer import STRONG_HEADERS

from secheaders import __version__, formatter
from secheaders.analyzer import analyze
from secheaders.scanner import ScanResult
from secheaders.scorer import score


def _render(headers: dict[str, str], *, verbose: bool = False) -> str:
    scan = ScanResult(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers=headers,
    )
    analysis = analyze(scan)
    console = Console(record=True, width=120)
    formatter.render_terminal(
        analysis, score(analysis), console=console, verbose=verbose
    )
    return console.export_text()


def test_terminal_shows_score_and_grade() -> None:
    # A leakage-free strong site scores 100 (A+).
    output = _render(STRONG_HEADERS)
    assert "100/100" in output
    assert "A+" in output


def test_terminal_shows_low_score_for_empty_site() -> None:
    output = _render({})
    assert "/100" in output
    assert "Grade: F" in output


def test_terminal_lists_each_header() -> None:
    output = _render(STRONG_HEADERS)
    assert "Strict-Transport-Security" in output
    assert "Content-Security-Policy" in output


def test_terminal_uses_text_status_markers_not_emoji() -> None:
    output = _render({})
    assert "FAIL" in output
    assert "WARN" in output
    # No emoji status markers.
    assert "✅" not in output
    assert "❌" not in output


def test_missing_value_shown_as_dash() -> None:
    output = _render({})
    assert "—" in output


def test_verbose_includes_breakdown() -> None:
    output = _render(STRONG_HEADERS, verbose=True)
    assert "Score breakdown" in output
    assert "Points" in output
    assert "penalty" in output


def test_non_verbose_hides_breakdown() -> None:
    output = _render(STRONG_HEADERS)
    assert "Score breakdown" not in output


def test_quiet_is_single_line() -> None:
    scan = ScanResult(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers={},
    )
    analysis = analyze(scan)
    console = Console(record=True, width=120)
    formatter.render_quiet(score(analysis), console=console)
    output = console.export_text().strip()
    assert "\n" not in output
    assert output.endswith("F")
    assert output.split("/")[0].isdigit()


def test_version_banner_contains_version() -> None:
    assert __version__ in formatter.version_banner()
