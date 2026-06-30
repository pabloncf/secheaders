"""HTTP request engine and header extraction.

This module performs the network request against a target URL and returns a
structured :class:`ScanResult`. It validates input at the boundary, enforces a
timeout on every request, optionally follows redirects, and maps low-level
``httpx`` errors onto the project's own exceptions.

It intentionally knows nothing about analysis, scoring, or formatting — it only
fetches and structures the raw response headers.
"""

from __future__ import annotations

import ipaddress
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

import httpx

from secheaders.exceptions import (
    ConnectionFailed,
    InvalidURL,
    ScanError,
    ScanTimeout,
    TLSError,
    TooManyRedirects,
)

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_REDIRECTS = 5
ALLOWED_SCHEMES = ("http", "https")
_LOCAL_HOSTNAMES = frozenset({"localhost", "localhost.localdomain"})


@dataclass(frozen=True)
class ScanResult:
    """Outcome of fetching a single URL.

    Attributes:
        url: The requested URL after normalization.
        final_url: The URL of the final response (after any redirects).
        status_code: HTTP status code of the final response.
        headers: Response headers with lowercased names for case-insensitive
            lookups. Duplicate header names are joined with ', '.
        elapsed_ms: Wall-clock duration of the request in milliseconds.
        redirected: Whether at least one redirect was followed.
        https_downgraded: Whether a redirect moved from https to http.
    """

    url: str
    final_url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    redirected: bool = False
    https_downgraded: bool = False


def normalize_url(raw_url: str) -> str:
    """Validate and normalize a target URL.

    Adds a default ``https://`` scheme when none is given and rejects any
    scheme other than http/https.

    Args:
        raw_url: URL as provided by the user.

    Returns:
        A normalized absolute URL.

    Raises:
        InvalidURL: If the URL is empty, has no host, or uses an
            unsupported scheme.
    """
    candidate = raw_url.strip()
    if not candidate:
        raise InvalidURL("No URL provided. Pass a target like https://example.com.")

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise InvalidURL(
            f"Unsupported URL scheme '{parsed.scheme}'. "
            f"Use one of: {', '.join(ALLOWED_SCHEMES)}."
        )
    if not parsed.hostname:
        raise InvalidURL(
            f"Could not parse a hostname from '{raw_url}'. "
            "Provide a full URL like https://example.com."
        )
    return urlunparse(parsed)


def is_private_host(url: str) -> bool:
    """Return True if the URL points at a loopback, private, or local host.

    Used to guard against accidental SSRF-style scans. Hostnames that are not
    IP literals (e.g. 'example.com') are treated as non-private here; only
    literal private/loopback IPs and well-known local names are flagged.

    Args:
        url: A normalized URL.

    Returns:
        True if the host is private/loopback/local, False otherwise.
    """
    hostname = urlparse(url).hostname or ""
    if hostname.lower() in _LOCAL_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _is_tls_error(exc: httpx.ConnectError) -> bool:
    """Decide whether a connection error was caused by a TLS/SSL failure.

    Checks the exception chain for an ``ssl.SSLError`` and, as httpx surfaces
    TLS problems in the message text (e.g. '[SSL: CERTIFICATE_VERIFY_FAILED]'),
    also inspects the message.
    """
    cause: BaseException | None = exc
    while cause is not None:
        if isinstance(cause, ssl.SSLError):
            return True
        cause = cause.__cause__ or cause.__context__
    message = str(exc).lower()
    return "ssl" in message or "certificate" in message


def _normalize_headers(headers: httpx.Headers) -> dict[str, str]:
    """Lowercase header names and join duplicates deterministically."""
    normalized: dict[str, str] = {}
    for name, value in headers.multi_items():
        key = name.lower()
        if key in normalized:
            normalized[key] = f"{normalized[key]}, {value}"
        else:
            normalized[key] = value
    return normalized


async def scan_url(
    raw_url: str,
    *,
    client: httpx.AsyncClient,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    follow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    allow_private: bool = False,
) -> ScanResult:
    """Fetch a URL and extract its response headers.

    Args:
        raw_url: Target URL (scheme optional; defaults to https).
        client: An injected httpx async client (enables pooling and testing).
        timeout: Per-request timeout in seconds.
        follow_redirects: Whether to follow redirects up to ``max_redirects``.
        max_redirects: Maximum number of redirects to follow.
        allow_private: Allow scanning loopback/private/local hosts.

    Returns:
        A :class:`ScanResult` with normalized headers and metadata.

    Raises:
        InvalidURL: If the URL is invalid or points at a disallowed host.
        ScanTimeout: If the request times out.
        ConnectionFailed: If the host cannot be reached.
        TLSError: If the TLS handshake fails.
        TooManyRedirects: If the redirect limit is exceeded.
        ScanError: For any other request-level failure.
    """
    url = normalize_url(raw_url)
    if not allow_private and is_private_host(url):
        raise InvalidURL(
            f"Refusing to scan private/local host '{urlparse(url).hostname}'. "
            "Pass allow_private=True to override."
        )

    client.max_redirects = max_redirects
    started = time.perf_counter()
    try:
        response = await client.get(
            url,
            timeout=timeout,
            follow_redirects=follow_redirects,
        )
    except httpx.TooManyRedirects as exc:
        raise TooManyRedirects(
            f"'{url}' exceeded {max_redirects} redirects. "
            "Lower the target's redirect chain or raise --follow-redirects."
        ) from exc
    except httpx.TimeoutException as exc:
        raise ScanTimeout(
            f"'{url}' did not respond within {timeout}s. "
            "Check that the URL is reachable or raise --timeout."
        ) from exc
    except httpx.ConnectError as exc:
        if _is_tls_error(exc):
            raise TLSError(
                f"TLS handshake with '{url}' failed: {exc}. "
                "The certificate may be invalid or expired."
            ) from exc
        raise ConnectionFailed(
            f"Could not connect to '{url}': {exc}. "
            "Check the hostname, DNS, and your network connection."
        ) from exc
    except httpx.HTTPError as exc:
        raise ScanError(f"Request to '{url}' failed: {exc}.") from exc

    elapsed_ms = (time.perf_counter() - started) * 1000
    final_url = str(response.url)
    return ScanResult(
        url=url,
        final_url=final_url,
        status_code=response.status_code,
        headers=_normalize_headers(response.headers),
        elapsed_ms=elapsed_ms,
        redirected=final_url != url,
        https_downgraded=url.startswith("https://") and final_url.startswith("http://"),
    )
