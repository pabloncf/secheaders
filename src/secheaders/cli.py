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

from secheaders import formatter
from secheaders.analyzer import analyze
from secheaders.batch import (
    DEFAULT_CONCURRENCY,
    BatchItem,
    BatchResult,
    read_urls,
    scan_all,
)
from secheaders.exceptions import SecHeadersError
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


def _report_single(args: argparse.Namespace, scan_result: ScanResult) -> None:
    """Render a single-URL report according to the verbosity mode."""
    analysis = analyze(scan_result)
    score_result = score(analysis)
    console = Console()
    if args.quiet:
        formatter.render_quiet(score_result, console=console)
        return
    formatter.render_terminal(
        analysis, score_result, console=console, verbose=args.verbose
    )


def _report_batch(args: argparse.Namespace, batch: BatchResult) -> None:
    """Render a batch report according to the verbosity mode."""
    console = Console()
    if args.quiet:
        formatter.render_batch_quiet(batch, console=console)
        return
    formatter.render_batch(batch, console=console)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the secheaders CLI.

    Args:
        argv: Argument list to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code (0 = success, 1 = threshold, 2 = error).
    """
    args = parse_args(argv)
    try:
        if args.input:
            urls = read_urls(args.input)
            batch = asyncio.run(_scan_batch(args, urls))
            _report_batch(args, batch)
        else:
            scan_result = asyncio.run(_scan(args))
            _report_single(args, scan_result)
    except SecHeadersError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
