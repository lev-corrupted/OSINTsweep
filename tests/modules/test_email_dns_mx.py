"""Tests for the DNS MX module — deliverability signal without sending mail."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from osint_toolkit.core.models import Status, Target, TargetKind
from osint_toolkit.modules.email.dns_mx import DnsMx


@pytest.mark.asyncio
async def test_dns_mx_found() -> None:
    target = Target(kind=TargetKind.EMAIL, value="alice@example.com")
    mod = DnsMx()

    with patch("osint_toolkit.modules.email.dns_mx.dns.asyncresolver.resolve") as resolve:
        fake = [
            type(
                "R",
                (),
                {
                    "exchange": type("E", (), {"to_text": lambda self: "mx1.example.com."})(),
                    "preference": 10,
                },
            )()
        ]

        async def _co(*a, **kw):
            return fake

        resolve.side_effect = _co
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.FOUND
    assert "mx1.example.com" in str(finding.data.get("records", ""))


@pytest.mark.asyncio
async def test_dns_mx_not_found() -> None:
    import dns.resolver

    target = Target(kind=TargetKind.EMAIL, value="alice@no-mx-domain.example")
    mod = DnsMx()

    with patch("osint_toolkit.modules.email.dns_mx.dns.asyncresolver.resolve") as resolve:

        async def _co(*a, **kw):
            raise dns.resolver.NoAnswer()

        resolve.side_effect = _co
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.NOT_FOUND
