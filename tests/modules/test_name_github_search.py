"""Tests for GitHub user search by real name."""

from __future__ import annotations

import httpx
import pytest
import respx

from osint_toolkit.core.models import Status, Target, TargetKind
from osint_toolkit.modules.name.github_search import GithubNameSearch


@pytest.mark.asyncio
async def test_github_name_found() -> None:
    target = Target(kind=TargetKind.NAME, value="Linus Torvalds")
    mod = GithubNameSearch()

    async with respx.mock:
        respx.get(
            "https://api.github.com/search/users",
            params={"q": "Linus Torvalds in:fullname", "per_page": "5"},
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "total_count": 1,
                    "items": [
                        {
                            "login": "torvalds",
                            "html_url": "https://github.com/torvalds",
                            "score": 1.0,
                        }
                    ],
                },
            )
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.FOUND
    matches = finding.data.get("matches", [])
    assert any(m["login"] == "torvalds" for m in matches)


@pytest.mark.asyncio
async def test_github_name_not_found() -> None:
    target = Target(kind=TargetKind.NAME, value="Asdfqwertyz NoOne Here")
    mod = GithubNameSearch()

    async with respx.mock:
        respx.get("https://api.github.com/search/users").mock(
            return_value=httpx.Response(200, json={"total_count": 0, "items": []})
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.NOT_FOUND
