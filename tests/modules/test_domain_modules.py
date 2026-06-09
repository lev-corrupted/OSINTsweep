"""Tests for the domain DNS + RDAP/WHOIS modules."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
import respx

from osint_toolkit.core.models import Status, Target, TargetKind
from osint_toolkit.modules.domain.dns_records import DnsRecords
from osint_toolkit.modules.domain.whois_lookup import WhoisLookup


@pytest.mark.asyncio
async def test_dns_records_aggregates_record_types() -> None:
    target = Target(kind=TargetKind.DOMAIN, value="example.com")
    mod = DnsRecords()

    with patch("osint_toolkit.modules.domain.dns_records.dns.asyncresolver.resolve") as resolve:

        async def fake_resolve(name: str, rt: str, **_kw):  # noqa: ANN001
            if rt == "A":
                return [type("R", (), {"to_text": lambda self: "93.184.216.34"})()]
            if rt == "MX":
                return [type("R", (), {"to_text": lambda self: "10 mx.example.com."})()]
            if rt == "TXT":
                return [type("R", (), {"to_text": lambda self: '"v=spf1 -all"'})()]
            import dns.resolver

            raise dns.resolver.NoAnswer

        resolve.side_effect = fake_resolve
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.FOUND
    assert "A" in finding.data["records"]
    assert "MX" in finding.data["records"]
    assert finding.data["has_mx"] is True
    assert finding.data["spf"] == "v=spf1 -all"


@pytest.mark.asyncio
async def test_dns_records_nxdomain() -> None:
    target = Target(kind=TargetKind.DOMAIN, value="nx-domain-xyz.example")
    mod = DnsRecords()

    import dns.resolver

    with patch("osint_toolkit.modules.domain.dns_records.dns.asyncresolver.resolve") as resolve:

        async def fake_resolve(*_a, **_kw):
            raise dns.resolver.NXDOMAIN

        resolve.side_effect = fake_resolve
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.NOT_FOUND


@pytest.mark.asyncio
async def test_whois_rdap_found() -> None:
    target = Target(kind=TargetKind.DOMAIN, value="example.com")
    mod = WhoisLookup()

    async with respx.mock:
        respx.get("https://rdap.org/domain/example.com").mock(
            return_value=httpx.Response(
                200,
                json={
                    "events": [
                        {"eventAction": "registration", "eventDate": "1995-08-14T00:00:00Z"},
                        {"eventAction": "expiration", "eventDate": "2027-08-13T00:00:00Z"},
                    ],
                    "nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}],
                    "status": ["client transfer prohibited"],
                    "entities": [
                        {
                            "roles": ["registrar"],
                            "vcardArray": ["vcard", [["fn", {}, "text", "Reserved Registrar LLC"]]],
                        }
                    ],
                },
            )
        )
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.FOUND
    assert finding.data["registrar"] == "Reserved Registrar LLC"
    assert "ns1.example.com" in finding.data["nameservers"]


@pytest.mark.asyncio
async def test_whois_rdap_404() -> None:
    target = Target(kind=TargetKind.DOMAIN, value="def-not-registered-xyz123.example")
    mod = WhoisLookup()

    async with respx.mock:
        respx.get(f"https://rdap.org/domain/{target.value}").mock(return_value=httpx.Response(404))
        async with httpx.AsyncClient() as client:
            finding = await mod.run(target, client)

    assert finding.status == Status.NOT_FOUND
