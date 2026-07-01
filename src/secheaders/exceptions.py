"""Custom exceptions for secheaders.

Each exception carries an actionable message: what went wrong *and* what the
user can do about it. The scanner maps low-level ``httpx`` errors onto these
so callers never have to import or reason about httpx internals.
"""

from __future__ import annotations


class SecHeadersError(Exception):
    """Base class for all secheaders errors."""


class InvalidURL(SecHeadersError):
    """The target URL is malformed or uses an unsupported scheme."""


class InputError(SecHeadersError):
    """The batch input file is missing, unreadable, or empty."""


class ScanError(SecHeadersError):
    """A scan failed for a reason that does not fit a more specific error."""


class ScanTimeout(ScanError):
    """The target did not respond within the configured timeout."""


class ConnectionFailed(ScanError):
    """The target could not be reached (DNS failure, refused, unreachable)."""


class TLSError(ScanError):
    """The TLS/SSL handshake with the target failed."""


class TooManyRedirects(ScanError):
    """The target exceeded the maximum number of allowed redirects."""
