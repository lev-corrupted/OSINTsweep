"""Tests for the Sherlock-style data-driven username checker."""

from __future__ import annotations

import httpx
import pytest
import respx

from osint_toolkit.core.models import Status, Target, TargetKind
from osint_toolkit.modules.username.sherlock_style import UsernameSite, load_username_sites

GITHUB_SITE = {
    "name": "github",
    "host": "github.com",
    "url": "https://github.com/{username}",
    "detect": {"type": "status_code", "found": 200, "not_found": 404},
    "modes_allowed": ["prospect", "selfcheck", "pentest"],
}

REDDIT_SITE = {
    "name": "reddit",
    "host": "www.reddit.com",
    "url": "https://www.reddit.com/user/{username}/about.json",
    "detect": {"type": "json_field_truthy", "field": "data.id"},
    "modes_allowed": ["prospect", "selfcheck", "pentest"],
}

MEDIUM_SITE = {
    "name": "medium",
    "host": "medium.com",
    "url": "https://medium.com/@{username}",
    "detect": {
        "type": "body_marker",
        "found_when": {"contains": "@{username}"},
        "not_found_when": {"contains": "PAGE NOT FOUND"},
    },
    "modes_allowed": ["prospect", "selfcheck", "pentest"],
}


@pytest.mark.asyncio
async def test_username_site_status_code_found() -> None:
    target = Target(kind=TargetKind.USERNAME, value="octocat")
    mod = UsernameSite(GITHUB_SITE)

    async with respx.mock:
        respx.get("https://github.com/octocat").mock(return_value=httpx.Response(200, text="<html>octocat</html>"))
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.FOUND
    assert finding.url == "https://github.com/octocat"
    assert finding.source == "github"


@pytest.mark.asyncio
async def test_username_site_status_code_not_found() -> None:
    target = Target(kind=TargetKind.USERNAME, value="ghost_404")
    mod = UsernameSite(GITHUB_SITE)

    async with respx.mock:
        respx.get("https://github.com/ghost_404").mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.NOT_FOUND


@pytest.mark.asyncio
async def test_username_site_json_field_truthy_found() -> None:
    target = Target(kind=TargetKind.USERNAME, value="octocat")
    mod = UsernameSite(REDDIT_SITE)

    async with respx.mock:
        respx.get("https://www.reddit.com/user/octocat/about.json").mock(
            return_value=httpx.Response(200, json={"kind": "t2", "data": {"id": "1234", "name": "octocat"}})
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.FOUND


@pytest.mark.asyncio
async def test_username_site_json_field_truthy_not_found() -> None:
    target = Target(kind=TargetKind.USERNAME, value="ghostuser")
    mod = UsernameSite(REDDIT_SITE)

    async with respx.mock:
        respx.get("https://www.reddit.com/user/ghostuser/about.json").mock(
            return_value=httpx.Response(200, json={"kind": "Listing", "data": {"children": []}})
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.NOT_FOUND


@pytest.mark.asyncio
async def test_username_site_body_marker_found() -> None:
    target = Target(kind=TargetKind.USERNAME, value="octocat")
    mod = UsernameSite(MEDIUM_SITE)

    async with respx.mock:
        respx.get("https://medium.com/@octocat").mock(
            return_value=httpx.Response(200, text="<title>@octocat on Medium</title>")
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.FOUND


@pytest.mark.asyncio
async def test_username_site_body_marker_not_found() -> None:
    target = Target(kind=TargetKind.USERNAME, value="ghost_no_user")
    mod = UsernameSite(MEDIUM_SITE)

    async with respx.mock:
        respx.get("https://medium.com/@ghost_no_user").mock(
            return_value=httpx.Response(200, text="<h1>PAGE NOT FOUND</h1>")
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.NOT_FOUND


def test_load_username_sites_returns_real_sites() -> None:
    """The sites.json file should load and produce at least 30 UsernameSite modules."""
    sites = list(load_username_sites())
    assert len(sites) >= 30, f"expected 30+ Sherlock-style sites, got {len(sites)}"
    # spot-check: every site has the required spec keys
    for s in sites:
        assert s.name
        assert s.host
        assert "url" in s.spec
        assert "detect" in s.spec
