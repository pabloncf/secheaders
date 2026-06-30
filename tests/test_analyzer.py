"""Tests for the header analysis engine (Phase 3)."""

from __future__ import annotations

import pytest

from secheaders.analyzer import AnalysisResult, HeaderResult, analyze
from secheaders.constants import Status
from secheaders.scanner import ScanResult

# Headers from a well-configured site (all canonical, lowercase keys).
STRONG_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; object-src 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "permissions-policy": "geolocation=(), camera=()",
    "referrer-policy": "strict-origin-when-cross-origin",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
}


def _scan(headers: dict[str, str], **kwargs: object) -> ScanResult:
    return ScanResult(
        url="https://example.com",
        final_url=kwargs.get("final_url", "https://example.com"),  # type: ignore[arg-type]
        status_code=200,
        headers=headers,
        https_downgraded=bool(kwargs.get("https_downgraded", False)),
    )


def _find(analysis: AnalysisResult, name: str) -> HeaderResult:
    return next(h for h in analysis.headers if h.name == name)


def test_strong_site_all_pass() -> None:
    analysis = analyze(_scan(STRONG_HEADERS))
    assert analysis.count(Status.FAIL) == 0
    assert analysis.count(Status.WARN) == 0
    assert _find(analysis, "Strict-Transport-Security").status is Status.PASS


def test_empty_site_criticals_fail() -> None:
    analysis = analyze(_scan({}))
    assert _find(analysis, "Strict-Transport-Security").status is Status.FAIL
    assert _find(analysis, "Content-Security-Policy").status is Status.FAIL
    assert _find(analysis, "X-Content-Type-Options").status is Status.FAIL
    # Secondary headers downgrade to WARN, not FAIL, when missing.
    assert _find(analysis, "Permissions-Policy").status is Status.WARN
    assert _find(analysis, "Cross-Origin-Opener-Policy").status is Status.WARN


def test_missing_header_has_recommendation() -> None:
    analysis = analyze(_scan({}))
    hsts = _find(analysis, "Strict-Transport-Security")
    assert hsts.present is False
    assert hsts.value is None
    assert "max-age" in hsts.recommendation


def test_hsts_without_subdomains_warns() -> None:
    analysis = analyze(_scan({"strict-transport-security": "max-age=31536000"}))
    hsts = _find(analysis, "Strict-Transport-Security")
    assert hsts.status is Status.WARN
    assert "includeSubDomains" in hsts.recommendation


def test_hsts_short_max_age_warns() -> None:
    analysis = analyze(
        _scan({"strict-transport-security": "max-age=3600; includeSubDomains"})
    )
    assert _find(analysis, "Strict-Transport-Security").status is Status.WARN


def test_hsts_preload_noted() -> None:
    analysis = analyze(_scan(STRONG_HEADERS))
    assert "preload" in _find(analysis, "Strict-Transport-Security").note


@pytest.mark.parametrize("token", ["unsafe-inline", "unsafe-eval"])
def test_csp_unsafe_tokens_warn(token: str) -> None:
    analysis = analyze(
        _scan({"content-security-policy": f"default-src 'self' '{token}'"})
    )
    csp = _find(analysis, "Content-Security-Policy")
    assert csp.status is Status.WARN
    assert token in csp.recommendation


def test_csp_wildcard_warns() -> None:
    analysis = analyze(_scan({"content-security-policy": "default-src *"}))
    assert _find(analysis, "Content-Security-Policy").status is Status.WARN


def test_x_content_type_options_must_be_nosniff() -> None:
    analysis = analyze(_scan({"x-content-type-options": "sniff"}))
    assert _find(analysis, "X-Content-Type-Options").status is Status.WARN


def test_referrer_unsafe_url_warns() -> None:
    analysis = analyze(_scan({"referrer-policy": "unsafe-url"}))
    assert _find(analysis, "Referrer-Policy").status is Status.WARN


def test_x_xss_protection_present_is_info() -> None:
    analysis = analyze(_scan({"x-xss-protection": "1; mode=block"}))
    xss = _find(analysis, "X-XSS-Protection")
    assert xss.status is Status.INFO
    assert "deprecated" in xss.note


def test_x_xss_protection_absent_is_pass() -> None:
    analysis = analyze(_scan({}))
    assert _find(analysis, "X-XSS-Protection").status is Status.PASS


def test_server_with_version_is_info_leak() -> None:
    analysis = analyze(_scan({"server": "nginx/1.25.3"}))
    server = _find(analysis, "Server")
    assert server.status is Status.INFO
    assert "version" in server.recommendation
    assert server.note == "information leakage"


def test_server_without_version_has_no_recommendation() -> None:
    analysis = analyze(_scan({"server": "cloudflare"}))
    assert _find(analysis, "Server").recommendation == ""


def test_x_powered_by_flagged() -> None:
    analysis = analyze(_scan({"x-powered-by": "PHP"}))
    powered = _find(analysis, "X-Powered-By")
    assert powered.status is Status.INFO
    assert "Remove" in powered.recommendation


def test_https_downgrade_finding() -> None:
    scan = _scan(STRONG_HEADERS, final_url="http://example.com", https_downgraded=True)
    analysis = analyze(scan)
    downgrade = _find(analysis, "HTTPS Downgrade")
    assert downgrade.status is Status.WARN


def test_no_downgrade_finding_when_clean() -> None:
    analysis = analyze(_scan(STRONG_HEADERS))
    assert all(h.name != "HTTPS Downgrade" for h in analysis.headers)
