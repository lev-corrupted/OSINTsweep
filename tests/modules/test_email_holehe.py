"""Tests for the Holehe-style email registration discovery."""

from __future__ import annotations

import httpx
import pytest
import respx

from osint_toolkit.core.models import Status, Target, TargetKind
from osint_toolkit.modules.email.holehe_check import HolehSite

GITHUB_SITE = {
    "name": "github",
    "host": "github.com",
    "method": "POST",
    "url": "https://github.com/password_reset",
    "form_data": {"login": "{email}"},
    "registered_when": {"contains": "Your password reset request"},
    "not_registered_when": {"contains": "no_account"},
    "modes_allowed": ["prospect", "selfcheck", "pentest"],
}


@pytest.mark.asyncio
async def test_holehe_registered() -> None:
    target = Target(kind=TargetKind.EMAIL, value="alice@example.com")
    mod = HolehSite(GITHUB_SITE)

    async with respx.mock:
        respx.post("https://github.com/password_reset").mock(
            return_value=httpx.Response(
                200, text="<html>Your password reset request was sent.</html>"
            )
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.FOUND
    assert finding.source == "github"


@pytest.mark.asyncio
async def test_holehe_not_registered() -> None:
    target = Target(kind=TargetKind.EMAIL, value="ghost@example.com")
    mod = HolehSite(GITHUB_SITE)

    async with respx.mock:
        respx.post("https://github.com/password_reset").mock(
            return_value=httpx.Response(200, text="<html>no_account exists.</html>")
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.NOT_FOUND


@pytest.mark.asyncio
async def test_holehe_inconclusive() -> None:
    """If neither fingerprint matches, status should be ERROR (we don't guess)."""
    target = Target(kind=TargetKind.EMAIL, value="alice@example.com")
    mod = HolehSite(GITHUB_SITE)

    async with respx.mock:
        respx.post("https://github.com/password_reset").mock(
            return_value=httpx.Response(200, text="<html>unrelated content</html>")
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.ERROR
    assert "inconclusive" in (finding.error or "").lower()
