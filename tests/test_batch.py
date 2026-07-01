"""Tests for concurrent batch scanning (Phase 6). Network is mocked."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from secheaders.batch import BatchResult, read_urls, scan_all
from secheaders.exceptions import InputError


def _ok(headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(200, headers=headers or {})


# --- read_urls -----------------------------------------------------------------


def test_read_urls_skips_blanks_and_comments(tmp_path) -> None:
    file = tmp_path / "urls.txt"
    file.write_text(
        "https://a.com\n\n# a comment\nhttps://b.com\n   \n",
        encoding="utf-8",
    )
    assert read_urls(file) == ["https://a.com", "https://b.com"]


def test_read_urls_missing_file_raises_input_error(tmp_path) -> None:
    with pytest.raises(InputError):
        read_urls(tmp_path / "does-not-exist.txt")


def test_read_urls_empty_file_raises_input_error(tmp_path) -> None:
    file = tmp_path / "empty.txt"
    file.write_text("# only comments\n\n", encoding="utf-8")
    with pytest.raises(InputError):
        read_urls(file)


# --- scan_all ------------------------------------------------------------------


@respx.mock
async def test_scan_all_scores_each_url() -> None:
    respx.get("https://a.com").mock(return_value=_ok())
    respx.get("https://b.com").mock(return_value=_ok())
    async with httpx.AsyncClient() as client:
        result = await scan_all(["https://a.com", "https://b.com"], client=client)

    assert len(result.items) == 2
    assert all(item.ok for item in result.items)
    assert all(item.score is not None for item in result.items)


@respx.mock
async def test_scan_all_preserves_input_order() -> None:
    respx.get("https://a.com").mock(return_value=_ok())
    respx.get("https://b.com").mock(return_value=_ok())
    async with httpx.AsyncClient() as client:
        result = await scan_all(["https://a.com", "https://b.com"], client=client)
    assert [item.url for item in result.items] == [
        "https://a.com",
        "https://b.com",
    ]


@respx.mock
async def test_scan_all_tolerates_partial_failure() -> None:
    respx.get("https://good.com").mock(return_value=_ok())
    respx.get("https://bad.com").mock(side_effect=httpx.ConnectTimeout)
    async with httpx.AsyncClient() as client:
        result = await scan_all(["https://good.com", "https://bad.com"], client=client)

    by_url = {item.url: item for item in result.items}
    assert by_url["https://good.com"].ok
    assert not by_url["https://bad.com"].ok
    assert by_url["https://bad.com"].error is not None
    assert by_url["https://bad.com"].score is None


@respx.mock
async def test_scan_all_on_complete_called_per_url() -> None:
    respx.get("https://a.com").mock(return_value=_ok())
    respx.get("https://b.com").mock(return_value=_ok())
    calls: list[str] = []
    async with httpx.AsyncClient() as client:
        await scan_all(
            ["https://a.com", "https://b.com"],
            client=client,
            on_complete=lambda item: calls.append(item.url),
        )
    assert sorted(calls) == ["https://a.com", "https://b.com"]


@respx.mock
async def test_scan_all_respects_concurrency_limit() -> None:
    active = 0
    peak = 0

    async def slow(request: httpx.Request) -> httpx.Response:
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        return _ok()

    urls = [f"https://site{i}.com" for i in range(10)]
    for url in urls:
        respx.get(url).mock(side_effect=slow)

    async with httpx.AsyncClient() as client:
        await scan_all(urls, client=client, concurrency=3)

    assert peak <= 3


def test_sorted_by_score_orders_desc_failures_last() -> None:
    from secheaders.batch import BatchItem
    from secheaders.scorer import ScoreResult

    def item(url: str, value: int | None) -> BatchItem:
        if value is None:
            return BatchItem(url=url, error="boom")
        sr = ScoreResult(
            score=value,
            grade="A",
            earned=0,
            max_points=95,
            bonus=0,
            penalty=0,
        )
        return BatchItem(url=url, score=sr)

    batch = BatchResult(items=[item("low", 20), item("fail", None), item("high", 90)])
    ordered = [i.url for i in batch.sorted_by_score()]
    assert ordered == ["high", "low", "fail"]
