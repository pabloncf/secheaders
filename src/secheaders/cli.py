"""Command-line interface for secheaders.

This module owns argument parsing and the top-level entry point. It wires the
scanner into the CLI; analysis, scoring, and formatting are added in later
phases, so for now it prints the raw extracted headers.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence

import httpx
from rich.console import Console

from secheaders import formatter
from secheaders.analyzer import analyze
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
        help="Target URL to scan (e.g. https://example.com).",
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
    """Parse command-line arguments.

    Args:
        argv: Argument list to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        The parsed arguments namespace.
    """
    parser = build_parser()
    return parser.parse_args(argv)


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


def _report(args: argparse.Namespace, scan_result: ScanResult) -> None:
    """Render the report to the terminal according to the verbosity mode."""
    analysis = analyze(scan_result)
    score_result = score(analysis)
    console = Console()
    if args.quiet:
        formatter.render_quiet(score_result, console=console)
        return
    formatter.render_terminal(
        analysis, score_result, console=console, verbose=args.verbose
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the secheaders CLI.

    Args:
        argv: Argument list to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code (0 = success, 1 = threshold, 2 = error).
    """
    args = parse_args(argv)
    try:
        scan_result = asyncio.run(_scan(args))
    except SecHeadersError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    _report(args, scan_result)
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
