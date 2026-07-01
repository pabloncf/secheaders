"""Structured export formats: JSON, HTML, and CSV.

All exporters consume a single canonical payload produced by :func:`to_dict`,
so the three formats never drift apart. Each exporter is a pure function that
returns a string; writing to disk or stdout is the CLI's responsibility.

Security note: header values are untrusted input. The HTML exporter escapes
every value with :func:`html.escape` — a security scanner must never emit XSS
in its own report.
"""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any

from secheaders import __version__
from secheaders.analyzer import AnalysisResult
from secheaders.constants import Status
from secheaders.scorer import ScoreResult

CSV_COLUMNS = (
    "url",
    "score",
    "grade",
    "header",
    "present",
    "status",
    "value",
    "recommendation",
)


def to_dict(analysis: AnalysisResult, score: ScoreResult) -> dict[str, Any]:
    """Build the canonical serializable payload for a single scan.

    Args:
        analysis: The analyzed headers.
        score: The computed score.

    Returns:
        A JSON-serializable dict shared by all exporters.
    """
    return {
        "secheaders_version": __version__,
        "url": analysis.url,
        "final_url": analysis.final_url,
        "score": score.score,
        "grade": score.grade,
        "bonus": score.bonus,
        "penalty": score.penalty,
        "summary": {
            "pass": analysis.count(Status.PASS),
            "warn": analysis.count(Status.WARN),
            "fail": analysis.count(Status.FAIL),
            "info": analysis.count(Status.INFO),
        },
        "headers": [
            {
                "name": header.name,
                "present": header.present,
                "value": header.value,
                "status": header.status.value,
                "recommendation": header.recommendation,
                "note": header.note,
            }
            for header in analysis.headers
        ],
    }


def to_json(payloads: list[dict[str, Any]]) -> str:
    """Serialize one or more payloads as JSON.

    A single scan is emitted as an object; a batch as an array.

    Args:
        payloads: The canonical payloads to serialize.

    Returns:
        Pretty-printed JSON.
    """
    data: Any = payloads[0] if len(payloads) == 1 else payloads
    return json.dumps(data, indent=2, ensure_ascii=False)


def to_csv(payloads: list[dict[str, Any]]) -> str:
    """Serialize payloads as CSV in long format (one row per header).

    Args:
        payloads: The canonical payloads to serialize.

    Returns:
        CSV text with a header row.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)
    for payload in payloads:
        if "error" in payload:
            writer.writerow(
                [payload["url"], "", "", "", "", "error", "", payload["error"]]
            )
            continue
        for header in payload["headers"]:
            writer.writerow(
                [
                    payload["url"],
                    payload["score"],
                    payload["grade"],
                    header["name"],
                    header["present"],
                    header["status"],
                    header["value"] or "",
                    header["recommendation"],
                ]
            )
    return buffer.getvalue()


def _html_row(header: dict[str, Any]) -> str:
    value = html.escape(header["value"] or "—")
    recommendation = html.escape(header["recommendation"])
    return (
        f'<tr class="{html.escape(header["status"])}">'
        f"<td>{html.escape(header['status'].upper())}</td>"
        f"<td>{html.escape(header['name'])}</td>"
        f"<td>{value}</td>"
        f"<td>{recommendation}</td>"
        "</tr>"
    )


def _html_error_report(payload: dict[str, Any]) -> str:
    url = html.escape(payload["url"])
    error = html.escape(payload.get("error") or "scan failed")
    return (
        f'<section class="report error">\n'
        f"  <h2>{url}</h2>\n"
        f'  <p class="score grade-F">Scan failed: {error}</p>\n'
        f"</section>"
    )


def _html_report(payload: dict[str, Any]) -> str:
    if "error" in payload:
        return _html_error_report(payload)
    rows = "\n".join(_html_row(h) for h in payload["headers"])
    url = html.escape(payload["final_url"])
    return f"""<section class="report">
  <h2><a href="{url}">{url}</a></h2>
  <p class="score grade-{html.escape(payload['grade'].replace('+', 'plus'))}">
    Score: {payload['score']}/100 &mdash; Grade: {html.escape(payload['grade'])}
  </p>
  <table>
    <thead><tr><th>Status</th><th>Header</th><th>Value</th>
    <th>Recommendation</th></tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
</section>"""


_HTML_STYLE = """
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
  h1 { font-size: 1.5rem; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
  th, td { border: 1px solid #ddd; padding: 0.4rem 0.6rem; text-align: left;
    font-size: 0.9rem; }
  th { background: #f4f4f4; }
  .score { font-size: 1.2rem; font-weight: bold; }
  tr.pass td:first-child { color: #1a7f37; font-weight: bold; }
  tr.warn td:first-child { color: #9a6700; font-weight: bold; }
  tr.fail td:first-child { color: #cf222e; font-weight: bold; }
  tr.info td:first-child { color: #0969da; font-weight: bold; }
""".strip()


def to_html(payloads: list[dict[str, Any]]) -> str:
    """Serialize payloads as a standalone HTML report with inline CSS.

    All values are HTML-escaped to prevent injection from scanned headers.

    Args:
        payloads: The canonical payloads to serialize.

    Returns:
        A complete, self-contained HTML document.
    """
    reports = "\n".join(_html_report(p) for p in payloads)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>secheaders report</title>
<style>
{_HTML_STYLE}
</style>
</head>
<body>
<h1>secheaders report</h1>
{reports}
</body>
</html>"""


def export(payloads: list[dict[str, Any]], fmt: str) -> str:
    """Serialize payloads in the requested structured format.

    Args:
        payloads: The canonical payloads.
        fmt: One of 'json', 'html', 'csv'.

    Returns:
        The serialized document.

    Raises:
        ValueError: If ``fmt`` is not a structured export format.
    """
    serializers = {"json": to_json, "html": to_html, "csv": to_csv}
    try:
        return serializers[fmt](payloads)
    except KeyError:
        raise ValueError(f"Not a structured export format: '{fmt}'.") from None
