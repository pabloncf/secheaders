"""Terminal rendering for scan results.

Presents an :class:`~secheaders.analyzer.AnalysisResult` and its
:class:`~secheaders.scorer.ScoreResult` using rich: a highlighted score panel,
a colored status table, an optional verbose breakdown, and a one-line quiet
mode for scripting.

The renderers take an injected :class:`~rich.console.Console`, which keeps them
pure with respect to IO and makes them testable via ``Console(record=True)``.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from secheaders import __version__
from secheaders.analyzer import AnalysisResult
from secheaders.batch import BatchResult
from secheaders.constants import Status
from secheaders.scorer import ScoreResult

# Per-status presentation: text marker and rich style. Text markers (not emoji)
# render reliably across terminals and CI logs.
STATUS_DISPLAY: dict[Status, tuple[str, str]] = {
    Status.PASS: ("PASS", "green"),
    Status.WARN: ("WARN", "yellow"),
    Status.FAIL: ("FAIL", "red"),
    Status.INFO: ("INFO", "blue"),
}

# Per-grade color, from best to worst.
GRADE_STYLE: dict[str, str] = {
    "A+": "bold green",
    "A": "green",
    "B": "cyan",
    "C": "yellow",
    "D": "dark_orange",
    "F": "bold red",
}

BANNER = r"""
 ___  ___  ___ _  _ ___ __ _ __| |___ _ _ ___
(_-< / -_)/ _| ' \/ -_) _` / _` / -_) '_(_-<
/__/ \___|\__|_||_\___\__,_\__,_\___|_| /__/
"""


def version_banner() -> str:
    """Return the ASCII banner shown by ``--version``."""
    return f"{BANNER}\nsecheaders {__version__}"


def _grade_style(grade: str) -> str:
    return GRADE_STYLE.get(grade, "white")


def render_quiet(score: ScoreResult, *, console: Console) -> None:
    """Print only the score and grade on one line, for scripting.

    Args:
        score: The computed score.
        console: Injected console (no color/markup is emitted).
    """
    console.print(f"{score.score}/100 {score.grade}", markup=False, highlight=False)


def _score_panel(analysis: AnalysisResult, score: ScoreResult) -> Panel:
    style = _grade_style(score.grade)
    body = Text()
    body.append(f"{analysis.final_url}\n")
    body.append(f"Score: {score.score}/100   ", style="bold")
    body.append(f"Grade: {score.grade}", style=style)
    return Panel(body, title="secheaders", border_style=style, expand=False)


def _status_table(analysis: AnalysisResult, *, verbose: bool) -> Table:
    table = Table(show_lines=verbose, expand=True)
    table.add_column("Status", width=6, no_wrap=True)
    table.add_column("Header", style="bold", no_wrap=True)
    table.add_column("Value", overflow="fold" if verbose else "ellipsis")
    table.add_column("Recommendation", overflow="fold")

    for header in analysis.headers:
        marker, style = STATUS_DISPLAY[header.status]
        value = header.value if header.present else "—"
        value_text = Text(value or "—", style="" if header.present else "dim")
        table.add_row(
            Text(marker, style=style),
            Text(header.name, style=style),
            value_text,
            header.recommendation or "",
        )
    return table


def _breakdown_table(score: ScoreResult) -> Table:
    table = Table(title="Score breakdown", expand=False)
    table.add_column("Header", style="bold")
    table.add_column("Weight", justify="right")
    table.add_column("Status")
    table.add_column("Points", justify="right")
    for item in score.breakdown:
        _, style = STATUS_DISPLAY[item.status]
        table.add_row(
            item.name,
            str(item.weight),
            Text(item.status.value, style=style),
            f"{item.points:g}",
        )
    table.add_row("", "", "bonus", f"+{score.bonus}")
    table.add_row("", "", "penalty", f"-{score.penalty}")
    return table


def render_terminal(
    analysis: AnalysisResult,
    score: ScoreResult,
    *,
    console: Console,
    verbose: bool = False,
) -> None:
    """Render the full report to the terminal.

    Args:
        analysis: The analyzed headers.
        score: The computed score.
        console: Injected console to render to.
        verbose: When True, show raw values and the score breakdown.
    """
    console.print(_score_panel(analysis, score))
    console.print(_status_table(analysis, verbose=verbose))
    if verbose:
        console.print(_breakdown_table(score))


def render_batch(batch: BatchResult, *, console: Console) -> None:
    """Render a comparative table for a batch scan, sorted by score.

    Args:
        batch: The batch result.
        console: Injected console to render to.
    """
    table = Table(title="Batch results", expand=True)
    table.add_column("URL", style="bold", overflow="fold")
    table.add_column("Score", justify="right")
    table.add_column("Grade", justify="center")
    table.add_column("Pass/Warn/Fail", justify="center")
    table.add_column("Note", overflow="fold")

    for item in batch.sorted_by_score():
        if item.score is None:
            table.add_row(
                item.url,
                Text("—", style="dim"),
                Text("—", style="dim"),
                "—",
                Text(item.error or "error", style="red"),
            )
            continue
        counts = (
            f"{item.score.breakdown_counts[Status.PASS]}/"
            f"{item.score.breakdown_counts[Status.WARN]}/"
            f"{item.score.breakdown_counts[Status.FAIL]}"
        )
        style = _grade_style(item.score.grade)
        table.add_row(
            item.url,
            f"{item.score.score}",
            Text(item.score.grade, style=style),
            counts,
            "",
        )
    console.print(table)


def render_batch_quiet(batch: BatchResult, *, console: Console) -> None:
    """Print one line per URL for scripting: ``url score/100 grade``.

    Failed URLs print ``url error <message>``.

    Args:
        batch: The batch result.
        console: Injected console (no color/markup is emitted).
    """
    for item in batch.items:
        if item.score is None:
            line = f"{item.url} error {item.error}"
        else:
            line = f"{item.url} {item.score.score}/100 {item.score.grade}"
        console.print(line, markup=False, highlight=False)
