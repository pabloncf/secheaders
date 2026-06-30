"""Tests for the weighted scoring engine (Phase 4)."""

from __future__ import annotations

import pytest
from tests.test_analyzer import STRONG_HEADERS

from secheaders.analyzer import analyze
from secheaders.scanner import ScanResult
from secheaders.scorer import grade_for, score


def _scan(headers: dict[str, str], **kwargs: object) -> ScanResult:
    return ScanResult(
        url="https://example.com",
        final_url=kwargs.get("final_url", "https://example.com"),  # type: ignore[arg-type]
        status_code=200,
        headers=headers,
        https_downgraded=bool(kwargs.get("https_downgraded", False)),
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (100, "A+"),
        (99, "A"),
        (90, "A"),
        (89, "B"),
        (80, "B"),
        (70, "C"),
        (60, "D"),
        (59, "F"),
        (0, "F"),
    ],
)
def test_grade_boundaries(value: int, expected: str) -> None:
    assert grade_for(value) == expected


def test_perfect_site_is_100_aplus() -> None:
    result = score(analyze(_scan(STRONG_HEADERS)))
    assert result.score == 100
    assert result.grade == "A+"


def test_empty_site_scores_low_and_fails() -> None:
    result = score(analyze(_scan({})))
    # Criticals FAIL (0 pts), secondary WARN (half) -> low score.
    assert result.score < 60
    assert result.grade == "F"


def test_warn_gives_half_credit() -> None:
    # Only HSTS present but weak (no includeSubDomains) -> WARN, half of 20 = 10.
    result = score(analyze(_scan({"strict-transport-security": "max-age=31536000"})))
    hsts_item = next(
        i for i in result.breakdown if i.name == "Strict-Transport-Security"
    )
    assert hsts_item.points == 10.0


def test_max_points_is_sum_of_weights() -> None:
    result = score(analyze(_scan({})))
    assert result.max_points == 95.0


def test_preload_bonus_applied() -> None:
    result = score(analyze(_scan(STRONG_HEADERS)))
    assert result.bonus == 2


def test_bonus_does_not_exceed_100() -> None:
    # Perfect headers already reach 100; the preload bonus must not overflow.
    result = score(analyze(_scan(STRONG_HEADERS)))
    assert result.score == 100


def test_info_leakage_penalty() -> None:
    leaky_headers = {**STRONG_HEADERS, "server": "nginx/1.25.3"}
    leaky = score(analyze(_scan(leaky_headers)))
    assert leaky.penalty == 5
    # base 100 + preload bonus 2 = 102, minus 5-point leakage penalty = 97.
    assert leaky.score == 97


def test_server_without_version_no_penalty() -> None:
    headers = {**STRONG_HEADERS, "server": "cloudflare"}
    result = score(analyze(_scan(headers)))
    assert result.penalty == 0


def test_downgrade_penalty() -> None:
    result = score(
        analyze(
            _scan(
                STRONG_HEADERS,
                final_url="http://example.com",
                https_downgraded=True,
            )
        )
    )
    assert result.penalty == 5
    # base 100 + preload bonus 2 = 102, minus 5-point downgrade penalty = 97.
    assert result.score == 97


def test_penalty_clamped_at_zero() -> None:
    # Empty + leaky + downgrade should never go negative.
    result = score(
        analyze(
            _scan(
                {"server": "nginx/1.25.3", "x-powered-by": "PHP/8.2.0"},
                final_url="http://example.com",
                https_downgraded=True,
            )
        )
    )
    assert result.score >= 0
