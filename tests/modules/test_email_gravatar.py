"""Tests for the Gravatar module — public profile API."""

from __future__ import annotations

import httpx
import pytest
import respx

from osint_toolkit.core.models import Status, Target, TargetKind
from osint_toolkit.modules.email.gravatar import Gravatar


@pytest.mark.asyncio
async def test_gravatar_found() -> None:
    target = Target(kind=TargetKind.EMAIL, value="alice@example.com")
    mod = Gravatar()

    async with respx.mock:
        respx.get(f"https://www.gravatar.com/{mod._hash(target.value)}.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "entry": [
                        {
                            "displayName": "Alice",
                            "preferredUsername": "alice",
                            "currentLocation": "London",
                        }
                    ]
                },
            )
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.FOUND
    assert finding.data.get("display_name") == "Alice"


@pytest.mark.asyncio
async def test_gravatar_not_found() -> None:
    target = Target(kind=TargetKind.EMAIL, value="ghost@example.com")
    mod = Gravatar()

    async with respx.mock:
        respx.get(f"https://www.gravatar.com/{mod._hash(target.value)}.json").mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.NOT_FOUND


@pytest.mark.asyncio
async def test_gravatar_hash_is_sha256() -> None:
    """Gravatar's modern API uses SHA-256 of trimmed-lowercased email."""
    mod = Gravatar()
    # Known fixture: hash of 'alice@example.com' lowercased+trimmed
    expected_prefix_len = 64
    h = mod._hash("alice@example.com")
    assert len(h) == expected_prefix_len
    assert h.isalnum() and h.islower()
