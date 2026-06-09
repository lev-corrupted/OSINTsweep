"""Tests for the retry-on-429 helper."""

from __future__ import annotations

import httpx
import pytest
import respx

from osint_toolkit.core.http import request_with_retry


@pytest.mark.asyncio
async def test_retry_on_429_then_success() -> None:
    async with respx.mock:
        route = respx.get("https://example.test/x").mock(
            side_effect=[
                httpx.Response(429, text="rate limited"),
                httpx.Response(200, text="ok"),
            ]
        )
        async with httpx.AsyncClient() as client:
            r = await request_with_retry(client, "GET", "https://example.test/x", backoff_base_s=0.01)
    assert r.status_code == 200
    assert route.call_count == 2


@pytest.mark.asyncio
async def test_retry_honors_retry_after() -> None:
    async with respx.mock:
        respx.get("https://example.test/x").mock(
            side_effect=[
                httpx.Response(429, headers={"Retry-After": "0.01"}, text="rate limited"),
                httpx.Response(200, text="ok"),
            ]
        )
        async with httpx.AsyncClient() as client:
            r = await request_with_retry(client, "GET", "https://example.test/x", backoff_base_s=0.001)
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_retry_exhausts_returns_last_response() -> None:
    async with respx.mock:
        respx.get("https://example.test/x").mock(return_value=httpx.Response(429, text="rate limited"))
        async with httpx.AsyncClient() as client:
            r = await request_with_retry(
                client,
                "GET",
                "https://example.test/x",
                max_attempts=2,
                backoff_base_s=0.001,
            )
    assert r.status_code == 429


@pytest.mark.asyncio
async def test_no_retry_on_success() -> None:
    async with respx.mock:
        route = respx.get("https://example.test/x").mock(return_value=httpx.Response(200, text="ok"))
        async with httpx.AsyncClient() as client:
            r = await request_with_retry(client, "GET", "https://example.test/x")
    assert r.status_code == 200
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_no_retry_on_404() -> None:
    async with respx.mock:
        route = respx.get("https://example.test/x").mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            r = await request_with_retry(client, "GET", "https://example.test/x")
    assert r.status_code == 404
    assert route.call_count == 1
