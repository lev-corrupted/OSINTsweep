"""Tests for the SQLite cache — TTL, set/get, invalidation."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from osint_toolkit.core.cache import Cache
from osint_toolkit.core.models import Confidence, Finding, Status


@pytest.fixture
async def cache(tmp_path: Path) -> Cache:
    c = Cache(path=tmp_path / "cache.db", ttl_hours=24)
    await c.init()
    return c


@pytest.mark.asyncio
async def test_cache_round_trip(cache: Cache) -> None:
    finding = Finding(
        source="gravatar",
        target_value="alice@example.com",
        status=Status.FOUND,
        confidence=Confidence.HIGH,
        data={"display_name": "Alice"},
    )
    await cache.set("gravatar", "alice@example.com", finding)

    cached = await cache.get("gravatar", "alice@example.com")
    assert cached is not None
    assert cached.source == "gravatar"
    assert cached.data == {"display_name": "Alice"}


@pytest.mark.asyncio
async def test_cache_miss_returns_none(cache: Cache) -> None:
    result = await cache.get("nonexistent", "x@x.com")
    assert result is None


@pytest.mark.asyncio
async def test_cache_expires_after_ttl(tmp_path: Path) -> None:
    c = Cache(path=tmp_path / "cache.db", ttl_hours=0)  # immediate expiry
    await c.init()
    finding = Finding(
        source="gravatar",
        target_value="x@example.com",
        status=Status.FOUND,
        confidence=Confidence.HIGH,
    )
    await c.set("gravatar", "x@example.com", finding)
    # Sleep just past 0 hours
    await asyncio.sleep(0.01)
    assert await c.get("gravatar", "x@example.com") is None


@pytest.mark.asyncio
async def test_cache_invalidate(cache: Cache) -> None:
    finding = Finding(
        source="gravatar",
        target_value="x@example.com",
        status=Status.FOUND,
        confidence=Confidence.HIGH,
    )
    await cache.set("gravatar", "x@example.com", finding)
    await cache.invalidate("gravatar", "x@example.com")
    assert await cache.get("gravatar", "x@example.com") is None
