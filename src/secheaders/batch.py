"""Concurrent batch scanning.

Orchestrates the scanner, analyzer, and scorer across many URLs at once. A
single :class:`httpx.AsyncClient` is reused for connection pooling and an
``asyncio.Semaphore`` bounds concurrency so we neither hammer targets nor
exhaust file descriptors.

Graceful degradation is a hard requirement: one URL failing must not abort the
batch. Each failure is captured into a :class:`BatchItem` carrying the error.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from secheaders.analyzer import AnalysisResult, analyze
from secheaders.exceptions import InputError, SecHeadersError
from secheaders.scanner import (
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_TIMEOUT_SECONDS,
    scan_url,
)
from secheaders.scorer import ScoreResult, score

DEFAULT_CONCURRENCY = 10


@dataclass(frozen=True)
class BatchItem:
    """Result of scanning a single URL within a batch."""

    url: str
    score: ScoreResult | None = None
    analysis: AnalysisResult | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Whether the URL was scanned successfully."""
        return self.error is None


@dataclass(frozen=True)
class BatchResult:
    """Aggregate result of a batch scan."""

    items: list[BatchItem] = field(default_factory=list)

    def sorted_by_score(self) -> list[BatchItem]:
        """Return items ordered by score descending; failures go last."""
        return sorted(
            self.items,
            key=lambda item: (item.score.score if item.score else -1),
            reverse=True,
        )


def read_urls(path: str | Path) -> list[str]:
    """Read target URLs from a file, one per line.

    Blank lines and lines starting with '#' are ignored.

    Args:
        path: Path to the input file.

    Returns:
        The list of URLs found.

    Raises:
        InputError: If the file cannot be read or contains no URLs.
    """
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(
            f"Could not read input file '{path}': {exc.strerror or exc}. "
            "Check that the path exists and is readable."
        ) from exc

    urls = [
        line.strip()
        for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not urls:
        raise InputError(
            f"Input file '{path}' contains no URLs. " "Add one URL per line."
        )
    return urls


async def scan_all(
    urls: Iterable[str],
    *,
    client: httpx.AsyncClient,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    allow_private: bool = False,
    on_complete: Callable[[BatchItem], None] | None = None,
) -> BatchResult:
    """Scan many URLs concurrently, tolerating individual failures.

    Args:
        urls: The target URLs.
        client: A shared, injected async client (enables pooling).
        concurrency: Maximum number of simultaneous requests.
        timeout: Per-request timeout in seconds.
        follow_redirects: Whether to follow redirects.
        max_redirects: Maximum redirects to follow.
        allow_private: Allow scanning loopback/private/local hosts.
        on_complete: Optional callback invoked as each URL finishes (used to
            advance a progress bar). Called once per URL, success or failure.

    Returns:
        A :class:`BatchResult` with one :class:`BatchItem` per URL, preserving
        input order.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_one(url: str) -> BatchItem:
        async with semaphore:
            try:
                scan_result = await scan_url(
                    url,
                    client=client,
                    timeout=timeout,
                    follow_redirects=follow_redirects,
                    max_redirects=max_redirects,
                    allow_private=allow_private,
                )
                analysis = analyze(scan_result)
                item = BatchItem(url=url, score=score(analysis), analysis=analysis)
            except SecHeadersError as exc:
                item = BatchItem(url=url, error=str(exc))
        if on_complete is not None:
            on_complete(item)
        return item

    items = await asyncio.gather(*(scan_one(url) for url in urls))
    return BatchResult(items=list(items))
