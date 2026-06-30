"""Single source of truth for header definitions, weights, and thresholds.

This module holds the security knowledge: which headers matter, their canonical
names, the values considered safe, and the scoring weights consumed later in
Phase 4. Keeping it declarative here lets the analyzer stay focused on logic.
"""

from __future__ import annotations

from enum import Enum

# Canonical (lowercase) header names. Headers are matched case-insensitively.
HSTS = "strict-transport-security"
CSP = "content-security-policy"
X_CONTENT_TYPE_OPTIONS = "x-content-type-options"
X_FRAME_OPTIONS = "x-frame-options"
PERMISSIONS_POLICY = "permissions-policy"
REFERRER_POLICY = "referrer-policy"
X_XSS_PROTECTION = "x-xss-protection"
COOP = "cross-origin-opener-policy"
CORP = "cross-origin-resource-policy"
COEP = "cross-origin-embedder-policy"

# Information-leakage headers: their *presence* (with a version) is undesirable.
SERVER = "server"
X_POWERED_BY = "x-powered-by"


class Status(Enum):
    """Qualitative verdict for a single header check."""

    PASS = "pass"  # present and strong
    WARN = "warn"  # present but weak / suboptimal, or missing non-critical
    FAIL = "fail"  # missing critical header, or dangerous value
    INFO = "info"  # informational (deprecated header, info leakage)


# HSTS thresholds.
HSTS_MIN_MAX_AGE = 31_536_000  # one year, in seconds

# Dangerous CSP tokens to flag.
CSP_UNSAFE_TOKENS = ("unsafe-inline", "unsafe-eval")

# Referrer-Policy values considered privacy-preserving.
REFERRER_SAFE_VALUES = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
)
REFERRER_UNSAFE_VALUES = frozenset({"unsafe-url"})

# Recommended values for the cross-origin isolation headers.
COOP_RECOMMENDED = frozenset({"same-origin", "same-origin-allow-popups"})
CORP_RECOMMENDED = frozenset({"same-origin", "same-site"})
COEP_RECOMMENDED = frozenset({"require-corp", "credentialless"})

X_FRAME_OPTIONS_SAFE = frozenset({"deny", "sameorigin"})

# Scoring weights (consumed in Phase 4). Defined here to avoid duplication.
HEADER_WEIGHTS: dict[str, int] = {
    HSTS: 20,
    CSP: 20,
    X_CONTENT_TYPE_OPTIONS: 10,
    X_FRAME_OPTIONS: 10,
    PERMISSIONS_POLICY: 10,
    REFERRER_POLICY: 10,
    COOP: 5,
    CORP: 5,
    COEP: 5,
}

# Penalty applied per information-leakage header exposing version info (Phase 4).
INFO_LEAKAGE_PENALTY = 5
