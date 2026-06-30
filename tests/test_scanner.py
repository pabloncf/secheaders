"""Tests for the HTTP scanner (Phase 2). All network traffic is mocked."""

from __future__ import annotations

import httpx
import pytest
import respx

from secheaders.exceptions import (
    ConnectionFailed,
    InvalidURL,
    ScanTimeout,
    TLSError,
)
from secheaders.scanner import (
    is_private_host,
    normalize_url,
    scan_url,
)

# --- normalize_url / validation ------------------------------------------------


def test_normalize_adds_https_scheme() -> None:
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_preserves_existing_scheme() -> None:
    assert normalize_url("http://example.com/path") == "http://example.com/path"


def test_normalize_rejects_unsupported_scheme() -> None:
    with pytest.raises(InvalidURL):
        normalize_url("ftp://example.com")


def test_normalize_rejects_empty() -> None:
    with pytest.raises(InvalidURL):
        normalize_url("   ")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://localhost",
        "http://10.0.0.5",
        "http://192.168.1.1",
    ],
)
def test_is_private_host_detects_local(url: str) -> None:
    assert is_private_host(normalize_url(url)) is True


def test_is_private_host_allows_public_domain() -> None:
    assert is_private_host("https://example.com") is False


# --- scan_url ------------------------------------------------------------------


@respx.mock
async def test_scan_extracts_and_normalizes_headers() -> None:
    respx.get("https://example.com").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
            },
        )
    )
    async with httpx.AsyncClient() as client:
        result = await scan_url("example.com", client=client)

    assert result.status_code == 200
    assert result.final_url == "https://example.com"
    assert result.headers["strict-transport-security"] == "max-age=31536000"
    assert result.headers["x-frame-options"] == "DENY"
    assert result.redirected is False


@respx.mock
async def test_scan_joins_duplicate_headers() -> None:
    respx.get("https://example.com").mock(
        return_value=httpx.Response(
            200,
            headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")],
        )
    )
    async with httpx.AsyncClient() as client:
        result = await scan_url("example.com", client=client)

    assert result.headers["set-cookie"] == "a=1, b=2"


@respx.mock
async def test_scan_follows_redirect_and_records_final_url() -> None:
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            301, headers={"Location": "https://example.com/new"}
        )
    )
    respx.get("https://example.com/new").mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient() as client:
        result = await scan_url("example.com", client=client)

    assert result.final_url == "https://example.com/new"
    assert result.redirected is True


@respx.mock
async def test_scan_detects_https_downgrade() -> None:
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(302, headers={"Location": "http://example.com/"})
    )
    respx.get("http://example.com/").mock(return_value=httpx.Response(200))

    async with httpx.AsyncClient() as client:
        result = await scan_url("https://example.com", client=client)

    assert result.https_downgraded is True


async def test_scan_rejects_private_host_by_default() -> None:
    async with httpx.AsyncClient() as client:
        with pytest.raises(InvalidURL):
            await scan_url("http://127.0.0.1", client=client)


@respx.mock
async def test_scan_maps_timeout() -> None:
    respx.get("https://example.com").mock(side_effect=httpx.ConnectTimeout)
    async with httpx.AsyncClient() as client:
        with pytest.raises(ScanTimeout):
            await scan_url("example.com", client=client)


@respx.mock
async def test_scan_maps_connect_error() -> None:
    respx.get("https://example.com").mock(side_effect=httpx.ConnectError("no route"))
    async with httpx.AsyncClient() as client:
        with pytest.raises(ConnectionFailed):
            await scan_url("example.com", client=client)


@respx.mock
async def test_scan_maps_ssl_error_to_tls_error() -> None:
    # httpx surfaces TLS failures in the ConnectError message text.
    err = httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] cert verify failed")
    respx.get("https://example.com").mock(side_effect=err)
    async with httpx.AsyncClient() as client:
        with pytest.raises(TLSError):
            await scan_url("example.com", client=client)
