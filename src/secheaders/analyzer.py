"""Security header analysis engine.

Turns the raw headers from a :class:`~secheaders.scanner.ScanResult` into a
qualitative verdict per header: present?, value, status, and an actionable
recommendation. It produces no numeric score — that is Phase 4's job.

Each header has a small pure check function. They are registered in
``HEADER_CHECKS`` so adding a header is a one-line change, not a new branch.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from secheaders import constants as c
from secheaders.constants import Status
from secheaders.scanner import ScanResult

# A check receives the raw header value (or None) and returns the verdict,
# the recommendation, and an optional contextual note.
CheckResult = tuple[Status, str, str]
HeaderCheck = Callable[[str | None], CheckResult]

_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)


@dataclass(frozen=True)
class HeaderResult:
    """Verdict for a single header."""

    name: str
    present: bool
    value: str | None
    status: Status
    recommendation: str = ""
    note: str = ""


@dataclass(frozen=True)
class AnalysisResult:
    """Aggregate verdict for a scanned URL."""

    url: str
    final_url: str
    headers: list[HeaderResult] = field(default_factory=list)

    def count(self, status: Status) -> int:
        """Return how many headers ended with the given status."""
        return sum(1 for header in self.headers if header.status is status)


# --- Critical headers ----------------------------------------------------------


def _check_hsts(value: str | None) -> CheckResult:
    if value is None:
        return (
            Status.FAIL,
            "Add 'Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload' to enforce HTTPS.",
            "",
        )
    match = _MAX_AGE_RE.search(value)
    if not match:
        return (
            Status.WARN,
            "HSTS is present but has no max-age. Set max-age=31536000.",
            "",
        )
    max_age = int(match.group(1))
    has_subdomains = "includesubdomains" in value.lower()
    if max_age < c.HSTS_MIN_MAX_AGE:
        return (
            Status.WARN,
            f"HSTS max-age is below one year ({max_age}s). "
            "Raise it to at least 31536000.",
            "",
        )
    if not has_subdomains:
        return (
            Status.WARN,
            "HSTS lacks includeSubDomains. Add it to protect all subdomains.",
            "",
        )
    note = "preload enabled" if "preload" in value.lower() else ""
    return (Status.PASS, "", note)


def _check_csp(value: str | None) -> CheckResult:
    if value is None:
        return (
            Status.FAIL,
            "Add a Content-Security-Policy to mitigate XSS and injection.",
            "",
        )
    lowered = value.lower()
    found = [token for token in c.CSP_UNSAFE_TOKENS if token in lowered]
    has_wildcard = bool(re.search(r"(^|\s)\*(\s|;|$)", value))
    if has_wildcard:
        found.append("* (wildcard source)")
    if found:
        return (
            Status.WARN,
            f"CSP weakened by: {', '.join(found)}. Remove these to harden it.",
            "",
        )
    return (Status.PASS, "", "")


# --- Important headers ---------------------------------------------------------


def _check_x_content_type_options(value: str | None) -> CheckResult:
    if value is None:
        return (
            Status.FAIL,
            "Add 'X-Content-Type-Options: nosniff' to block MIME sniffing.",
            "",
        )
    if value.strip().lower() != "nosniff":
        return (
            Status.WARN,
            f"Unexpected value '{value}'. It must be exactly 'nosniff'.",
            "",
        )
    return (Status.PASS, "", "")


def _check_x_frame_options(value: str | None) -> CheckResult:
    note = "superseded by CSP frame-ancestors"
    if value is None:
        return (
            Status.FAIL,
            "Add 'X-Frame-Options: DENY' (or SAMEORIGIN) to prevent clickjacking.",
            note,
        )
    if value.strip().lower() not in c.X_FRAME_OPTIONS_SAFE:
        return (
            Status.WARN,
            f"Unexpected value '{value}'. Use DENY or SAMEORIGIN.",
            note,
        )
    return (Status.PASS, "", note)


def _check_permissions_policy(value: str | None) -> CheckResult:
    if value is None:
        return (
            Status.WARN,
            "Add a Permissions-Policy to restrict powerful browser features "
            "(camera, microphone, geolocation).",
            "",
        )
    return (Status.PASS, "", "")


def _check_referrer_policy(value: str | None) -> CheckResult:
    if value is None:
        return (
            Status.WARN,
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit "
            "referrer leakage.",
            "",
        )
    normalized = value.strip().lower()
    if normalized in c.REFERRER_UNSAFE_VALUES:
        return (
            Status.WARN,
            f"'{value}' leaks full URLs cross-origin. "
            "Use strict-origin-when-cross-origin or no-referrer.",
            "",
        )
    if normalized not in c.REFERRER_SAFE_VALUES:
        return (
            Status.WARN,
            f"Unrecognized Referrer-Policy '{value}'. "
            "Use a privacy-preserving value like strict-origin-when-cross-origin.",
            "",
        )
    return (Status.PASS, "", "")


def _check_cross_origin(recommended: frozenset[str], header_label: str) -> HeaderCheck:
    """Build a check for a cross-origin isolation header (COOP/CORP/COEP)."""

    def check(value: str | None) -> CheckResult:
        if value is None:
            return (
                Status.WARN,
                f"Consider adding {header_label} "
                f"(recommended: {' or '.join(sorted(recommended))}).",
                "",
            )
        if value.strip().lower() not in recommended:
            return (
                Status.WARN,
                f"Unexpected value '{value}' for {header_label}. "
                f"Recommended: {' or '.join(sorted(recommended))}.",
                "",
            )
        return (Status.PASS, "", "")

    return check


# --- Informational headers -----------------------------------------------------


def _check_x_xss_protection(value: str | None) -> CheckResult:
    if value is None:
        return (Status.PASS, "", "deprecated header; absence is fine")
    return (
        Status.INFO,
        "X-XSS-Protection is deprecated and can introduce vulnerabilities. "
        "Remove it and rely on Content-Security-Policy instead.",
        "deprecated",
    )


HEADER_CHECKS: dict[str, HeaderCheck] = {
    c.HSTS: _check_hsts,
    c.CSP: _check_csp,
    c.X_CONTENT_TYPE_OPTIONS: _check_x_content_type_options,
    c.X_FRAME_OPTIONS: _check_x_frame_options,
    c.PERMISSIONS_POLICY: _check_permissions_policy,
    c.REFERRER_POLICY: _check_referrer_policy,
    c.COOP: _check_cross_origin(c.COOP_RECOMMENDED, "Cross-Origin-Opener-Policy"),
    c.CORP: _check_cross_origin(c.CORP_RECOMMENDED, "Cross-Origin-Resource-Policy"),
    c.COEP: _check_cross_origin(c.COEP_RECOMMENDED, "Cross-Origin-Embedder-Policy"),
    c.X_XSS_PROTECTION: _check_x_xss_protection,
}

# Pretty canonical names for display.
CANONICAL_NAMES: dict[str, str] = {
    c.HSTS: "Strict-Transport-Security",
    c.CSP: "Content-Security-Policy",
    c.X_CONTENT_TYPE_OPTIONS: "X-Content-Type-Options",
    c.X_FRAME_OPTIONS: "X-Frame-Options",
    c.PERMISSIONS_POLICY: "Permissions-Policy",
    c.REFERRER_POLICY: "Referrer-Policy",
    c.COOP: "Cross-Origin-Opener-Policy",
    c.CORP: "Cross-Origin-Resource-Policy",
    c.COEP: "Cross-Origin-Embedder-Policy",
    c.X_XSS_PROTECTION: "X-XSS-Protection",
    c.SERVER: "Server",
    c.X_POWERED_BY: "X-Powered-By",
}

# A Server value is "leaky" only if it exposes a version number.
_VERSION_RE = re.compile(r"\d+\.\d+")


def _check_info_leakage(header_key: str, value: str) -> HeaderResult:
    """Flag information-leakage headers that expose software/version details."""
    label = CANONICAL_NAMES[header_key]
    if header_key == c.X_POWERED_BY:
        recommendation = f"Remove the {label} header; it leaks your stack."
    elif _VERSION_RE.search(value):
        recommendation = (
            f"The {label} header exposes a version ('{value}'). "
            "Suppress the version to reduce information leakage."
        )
    else:
        # Present but no version detail — informational only, no recommendation.
        recommendation = ""
    return HeaderResult(
        name=label,
        present=True,
        value=value,
        status=Status.INFO,
        recommendation=recommendation,
        note="information leakage",
    )


def analyze(scan: ScanResult) -> AnalysisResult:
    """Analyze the headers of a scan result.

    Args:
        scan: The :class:`~secheaders.scanner.ScanResult` to evaluate.

    Returns:
        An :class:`AnalysisResult` with one :class:`HeaderResult` per analyzed
        header, plus info-leakage findings and any HTTPS-downgrade warning.
    """
    results: list[HeaderResult] = []

    for header_key, check in HEADER_CHECKS.items():
        value = scan.headers.get(header_key)
        status, recommendation, note = check(value)
        results.append(
            HeaderResult(
                name=CANONICAL_NAMES[header_key],
                present=value is not None,
                value=value,
                status=status,
                recommendation=recommendation,
                note=note,
            )
        )

    for leak_key in (c.SERVER, c.X_POWERED_BY):
        value = scan.headers.get(leak_key)
        if value is not None:
            results.append(_check_info_leakage(leak_key, value))

    if scan.https_downgraded:
        results.append(
            HeaderResult(
                name="HTTPS Downgrade",
                present=True,
                value=f"{scan.url} -> {scan.final_url}",
                status=Status.WARN,
                recommendation=(
                    "A redirect downgraded HTTPS to HTTP. Serve all redirects "
                    "over HTTPS and enable HSTS."
                ),
                note="transport",
            )
        )

    return AnalysisResult(url=scan.url, final_url=scan.final_url, headers=results)
