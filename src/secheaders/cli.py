"""Command-line interface for secheaders.

This module owns argument parsing and the top-level entry point. It wires the
scanner, analyzer, scorer, and formatter together for both single-URL and batch
(``--input``) scanning.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence

import httpx
from rich.console import Console
from rich.progress import Progress

from secheaders import exporters, formatter
from secheaders.analyzer import analyze
from secheaders.batch import (
    DEFAULT_CONCURRENCY,
    BatchItem,
    BatchResult,
    read_urls,
    scan_all,
)
from secheaders.exceptions import OutputError, SecHeadersError
from secheaders.scanner import (
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_TIMEOUT_SECONDS,
    ScanResult,
    scan_url,
)
from secheaders.scorer import score

OutputFormat = str
SUPPORTED_FORMATS: tuple[OutputFormat, ...] = ("terminal", "json", "html", "csv")

EXIT_SUCCESS = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the secheaders CLI.

    Returns:
        A configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        prog="secheaders",
        description=(
            "Scan a URL for HTTP security headers, score it, and get "
            "actionable fix recommendations."
        ),
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="Target URL to scan (e.g. https://example.com).",
    )
    parser.add_argument(
        "-i",
        "--input",
        metavar="FILE",
        default=None,
        help="Scan every URL listed in FILE (one per line; # comments allowed).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        metavar="N",
        help=(
            "Max simultaneous requests in batch mode "
            f"(default: {DEFAULT_CONCURRENCY})."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        default=None,
        help="Write the report to a file instead of stdout.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=SUPPORTED_FORMATS,
        default="terminal",
        help="Output format (default: terminal).",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show raw header values and the score breakdown.",
    )
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Print only the score and grade (for scripting).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=f"Per-request timeout (default: {DEFAULT_TIMEOUT_SECONDS}s).",
    )
    parser.add_argument(
        "--follow-redirects",
        dest="follow_redirects",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=f"Follow redirects up to {DEFAULT_MAX_REDIRECTS} hops (default: on).",
    )
    parser.add_argument(
        "--max-redirects",
        type=int,
        default=DEFAULT_MAX_REDIRECTS,
        metavar="N",
        help=f"Maximum redirects to follow (default: {DEFAULT_MAX_REDIRECTS}).",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow scanning loopback/private/local hosts.",
    )
    parser.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="SCORE",
        help="Exit with code 1 if any score is below SCORE (for CI/CD).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=formatter.version_banner(),
    )
    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse and validate command-line arguments.

    Exactly one of a positional ``url`` or ``--input`` must be provided.

    Args:
        argv: Argument list to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        The parsed arguments namespace.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.url) == bool(args.input):
        parser.error("provide either a URL or --input FILE, but not both")
    return args


async def _scan(args: argparse.Namespace) -> ScanResult:
    """Run a single scan using an injected, pooled async client."""
    async with httpx.AsyncClient() as client:
        return await scan_url(
            args.url,
            client=client,
            timeout=args.timeout,
            follow_redirects=args.follow_redirects,
            max_redirects=args.max_redirects,
            allow_private=args.allow_private,
        )


async def _scan_batch(args: argparse.Namespace, urls: list[str]) -> BatchResult:
    """Run a batch scan with a shared client and an optional progress bar."""
    show_progress = not args.quiet and sys.stderr.isatty()
    async with httpx.AsyncClient() as client:
        if not show_progress:
            return await scan_all(
                urls,
                client=client,
                concurrency=args.concurrency,
                timeout=args.timeout,
                follow_redirects=args.follow_redirects,
                max_redirects=args.max_redirects,
                allow_private=args.allow_private,
            )
        # Progress bar goes to stderr so stdout stays pipeable.
        with Progress(console=Console(stderr=True)) as progress:
            task = progress.add_task("Scanning", total=len(urls))

            def advance(_: BatchItem) -> None:
                progress.advance(task)

            return await scan_all(
                urls,
                client=client,
                concurrency=args.concurrency,
                timeout=args.timeout,
                follow_redirects=args.follow_redirects,
                max_redirects=args.max_redirects,
                allow_private=args.allow_private,
                on_complete=advance,
            )


def _write_output(text: str, path: str) -> None:
    """Write exported text to a file, mapping IO errors to OutputError."""
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as exc:
        raise OutputError(
            f"Could not write report to '{path}': {exc.strerror or exc}. "
            "Check the path and write permissions."
        ) from exc


def _emit_export(args: argparse.Namespace, payloads: list[dict]) -> None:
    """Serialize payloads and send them to --output or stdout."""
    document = exporters.export(payloads, args.format)
    if args.output:
        _write_output(document, args.output)
    else:
        # print via stdout directly; no rich styling for machine formats.
        sys.stdout.write(document + "\n")


def _report_single(args: argparse.Namespace, scan_result: ScanResult) -> int:
    """Render or export a single-URL report; return its score."""
    analysis = analyze(scan_result)
    score_result = score(analysis)
    if args.format != "terminal":
        _emit_export(args, [exporters.to_dict(analysis, score_result)])
        return score_result.score
    console = Console()
    if args.quiet:
        formatter.render_quiet(score_result, console=console)
    else:
        formatter.render_terminal(
            analysis, score_result, console=console, verbose=args.verbose
        )
    return score_result.score


def _batch_payloads(batch: BatchResult) -> list[dict]:
    """Build export payloads for a batch, including error entries."""
    payloads: list[dict] = []
    for item in batch.items:
        if item.analysis is not None and item.score is not None:
            payloads.append(exporters.to_dict(item.analysis, item.score))
        else:
            payloads.append({"url": item.url, "error": item.error})
    return payloads


def _report_batch(args: argparse.Namespace, batch: BatchResult) -> None:
    """Render or export a batch report."""
    if args.format != "terminal":
        _emit_export(args, _batch_payloads(batch))
        return
    console = Console()
    if args.quiet:
        formatter.render_batch_quiet(batch, console=console)
        return
    formatter.render_batch(batch, console=console)


def _threshold_failed(args: argparse.Namespace, scores: list[int | None]) -> bool:
    """Return True if --fail-under is set and any score is below it or missing."""
    if args.fail_under is None:
        return False
    return any(value is None or value < args.fail_under for value in scores)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the secheaders CLI.

    Args:
        argv: Argument list to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code (0 = success, 1 = threshold, 2 = error).
    """
    args = parse_args(argv)
    try:
        scores: list[int | None]
        if args.input:
            urls = read_urls(args.input)
            batch = asyncio.run(_scan_batch(args, urls))
            _report_batch(args, batch)
            scores = [item.score.score if item.score else None for item in batch.items]
        else:
            scan_result = asyncio.run(_scan(args))
            scores = [_report_single(args, scan_result)]
    except SecHeadersError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if _threshold_failed(args, scores):
        return EXIT_THRESHOLD
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
