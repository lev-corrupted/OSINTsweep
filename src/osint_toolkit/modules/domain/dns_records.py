"""DNS record bundle for a domain: A, AAAA, MX, TXT, NS, SOA."""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.resolver
import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule

_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "CAA")


class DnsRecords(BaseModule):
    @property
    def name(self) -> str:
        return "dns_records"

    @property
    def category(self) -> str:
        return "domain"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "dns"

    @property
    def rate_limit_per_min(self) -> int:
        return 600

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        async def _resolve(rt: str) -> tuple[str, list[str]]:
            try:
                ans = await dns.asyncresolver.resolve(target.value, rt)
                return rt, [str(r.to_text()).strip('"') for r in ans]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                return rt, []
            except Exception:  # noqa: BLE001
                return rt, []

        results = await asyncio.gather(*[_resolve(rt) for rt in _RECORD_TYPES])
        records = {rt: vals for rt, vals in results if vals}

        if not records:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.NOT_FOUND,
                confidence=Confidence.HIGH,
                error="no DNS records resolved — possibly NXDOMAIN",
            )

        # Quick analysis: SPF, DMARC, MX presence
        txt_records = records.get("TXT", [])
        spf = next((t for t in txt_records if t.startswith("v=spf1")), None)
        data = {
            "records": records,
            "has_mx": bool(records.get("MX")),
            "spf": spf,
            "ns": records.get("NS", []),
        }
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            data=data,
        )
