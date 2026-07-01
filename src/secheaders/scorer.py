"""Weighted scoring engine.

Converts a qualitative :class:`~secheaders.analyzer.AnalysisResult` into a
0-100 score and a letter grade. Each weighted header contributes a fraction of
its weight based on its status (PASS=full, WARN=half, FAIL=none). Good practices
add a bonus; information leakage and HTTPS downgrade subtract a penalty.

It performs no analysis itself — it only maps statuses onto points, so the
weights and thresholds live in :mod:`secheaders.constants`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from secheaders import constants as c
from secheaders.analyzer import CANONICAL_NAMES, AnalysisResult, HeaderResult
from secheaders.constants import Status


@dataclass(frozen=True)
class ScoreItem:
    """How a single weighted header contributed to the score."""

    name: str
    weight: int
    status: Status
    points: float


@dataclass(frozen=True)
class ScoreResult:
    """Final score for a scanned URL."""

    score: int
    grade: str
    earned: float
    max_points: float
    bonus: int
    penalty: int
    breakdown: list[ScoreItem] = field(default_factory=list)

    @property
    def breakdown_counts(self) -> dict[Status, int]:
        """Count weighted headers by status (PASS/WARN/FAIL)."""
        counts = {Status.PASS: 0, Status.WARN: 0, Status.FAIL: 0}
        for item in self.breakdown:
            if item.status in counts:
                counts[item.status] += 1
        return counts


def grade_for(score: int) -> str:
    """Return the letter grade for a 0-100 score.

    Args:
        score: A score in the range 0-100.

    Returns:
        The letter grade (A+, A, B, C, D, or F).
    """
    for threshold, grade in c.GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def _bonus_for(header: HeaderResult) -> int:
    """Return the bonus points a single header earns for good practices."""
    if header.name == CANONICAL_NAMES[c.HSTS] and "preload" in header.note:
        return c.HSTS_PRELOAD_BONUS
    return 0


def _penalty_for(header: HeaderResult) -> int:
    """Return the penalty points a single finding incurs."""
    if header.note == "information leakage" and header.recommendation:
        return c.INFO_LEAKAGE_PENALTY
    if header.note == "transport":  # HTTPS downgrade finding
        return c.DOWNGRADE_PENALTY
    return 0


def score(analysis: AnalysisResult) -> ScoreResult:
    """Compute the weighted score for an analysis.

    Args:
        analysis: The :class:`~secheaders.analyzer.AnalysisResult` to score.

    Returns:
        A :class:`ScoreResult` with the clamped 0-100 score, grade, and a
        per-header breakdown.
    """
    breakdown: list[ScoreItem] = []
    earned = 0.0
    bonus = 0
    penalty = 0

    by_name = {header.name: header for header in analysis.headers}
    for header_key, weight in c.HEADER_WEIGHTS.items():
        header = by_name.get(CANONICAL_NAMES[header_key])
        status = header.status if header is not None else Status.FAIL
        credit = c.STATUS_CREDIT.get(status, 0.0)
        points = weight * credit
        earned += points
        breakdown.append(
            ScoreItem(
                name=CANONICAL_NAMES[header_key],
                weight=weight,
                status=status,
                points=points,
            )
        )

    for header in analysis.headers:
        bonus += _bonus_for(header)
        penalty += _penalty_for(header)

    max_points = float(sum(c.HEADER_WEIGHTS.values()))
    base = earned / max_points * 100 if max_points else 0.0
    raw = base + bonus - penalty
    final = max(0, min(100, round(raw)))

    return ScoreResult(
        score=final,
        grade=grade_for(final),
        earned=earned,
        max_points=max_points,
        bonus=bonus,
        penalty=penalty,
        breakdown=breakdown,
    )
