"""Command-line interface for secheaders.

This module owns argument parsing and the top-level entry point. Scanning,
analysis, scoring, and formatting are added in later phases; for now ``main``
validates arguments and prints a placeholder so the CLI skeleton is runnable
end to end.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from secheaders import __version__

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
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show raw header values and detailed explanations.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
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


def main(argv: Sequence[str] | None = None) -> int:
    """Run the secheaders CLI.

    Args:
        argv: Argument list to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        Process exit code (0 = success, 1 = threshold, 2 = error).
    """
    args = parse_args(argv)
    print(
        f"secheaders {__version__} — scanning '{args.url}' "
        f"(format={args.format}, verbose={args.verbose}) [not implemented yet]"
    )
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
