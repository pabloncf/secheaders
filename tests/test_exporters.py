"""Tests for structured export formats (Phase 7)."""

from __future__ import annotations

import csv
import io
import json

import pytest
from tests.test_analyzer import STRONG_HEADERS

from secheaders.analyzer import analyze
from secheaders.exporters import export, to_csv, to_dict, to_html, to_json
from secheaders.scanner import ScanResult
from secheaders.scorer import score


def _payload(headers: dict[str, str]) -> dict:
    scan = ScanResult(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        headers=headers,
    )
    analysis = analyze(scan)
    return to_dict(analysis, score(analysis))


def test_to_dict_has_expected_keys() -> None:
    payload = _payload(STRONG_HEADERS)
    assert payload["url"] == "https://example.com"
    assert payload["score"] == 100
    assert payload["grade"] == "A+"
    assert payload["summary"]["pass"] >= 1
    assert "secheaders_version" in payload
    assert len(payload["headers"]) >= 9


def test_json_single_is_object() -> None:
    payload = _payload(STRONG_HEADERS)
    parsed = json.loads(to_json([payload]))
    assert isinstance(parsed, dict)
    assert parsed["grade"] == "A+"


def test_json_batch_is_array() -> None:
    payloads = [_payload(STRONG_HEADERS), _payload({})]
    parsed = json.loads(to_json(payloads))
    assert isinstance(parsed, list)
    assert len(parsed) == 2


def test_csv_long_format_one_row_per_header() -> None:
    payload = _payload(STRONG_HEADERS)
    reader = list(csv.reader(io.StringIO(to_csv([payload]))))
    assert reader[0] == [
        "url",
        "score",
        "grade",
        "header",
        "present",
        "status",
        "value",
        "recommendation",
    ]
    assert len(reader) == 1 + len(payload["headers"])


def test_html_contains_score_and_grade() -> None:
    html_doc = to_html([_payload(STRONG_HEADERS)])
    assert "100/100" in html_doc
    assert "A+" in html_doc
    assert "<!DOCTYPE html>" in html_doc


def test_html_escapes_malicious_header_value() -> None:
    # A header value is untrusted input; it must not become live HTML.
    payload = _payload({"content-security-policy": "<script>alert(1)</script>"})
    html_doc = to_html([payload])
    assert "<script>alert(1)</script>" not in html_doc
    assert "&lt;script&gt;" in html_doc


def test_export_dispatches_by_format() -> None:
    payload = _payload(STRONG_HEADERS)
    assert export([payload], "json").startswith("{")
    assert "<!DOCTYPE html>" in export([payload], "html")
    assert "url,score,grade" in export([payload], "csv")


def test_export_rejects_unknown_format() -> None:
    with pytest.raises(ValueError):
        export([_payload({})], "terminal")
