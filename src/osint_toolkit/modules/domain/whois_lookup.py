"""WHOIS lookup via RDAP (modern, JSON, no extra deps).

RDAP is the IETF-standard JSON-over-HTTPS WHOIS replacement. Every gTLD registrar
runs a public RDAP endpoint, queried via rdap.org as a router.
"""

from __future__ import annotations

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class WhoisLookup(BaseModule):
    @property
    def name(self) -> str:
        return "rdap_whois"

    @property
    def category(self) -> str:
        return "domain"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "rdap.org"

    @property
    def rate_limit_per_min(self) -> int:
        return 30

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        from osint_toolkit.core.http import request_with_retry

        url = f"https://rdap.org/domain/{target.value}"
        r = await request_with_retry(client, "GET", url)
        if r.status_code == 404:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.NOT_FOUND,
                confidence=Confidence.HIGH,
                error="domain not registered (RDAP 404)",
            )
        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"RDAP returned {r.status_code}",
            )
        body = r.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in body.get("events", [])}
        nameservers = [ns.get("ldhName") for ns in body.get("nameservers", []) if ns.get("ldhName")]
        statuses = body.get("status", [])
        registrar = None
        for ent in body.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray") or []
                if len(vcard) > 1:
                    for entry in vcard[1]:
                        if entry and entry[0] == "fn":
                            registrar = entry[3]
                            break
                break
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            url=url,
            data={
                "registrar": registrar,
                "created": events.get("registration"),
                "expires": events.get("expiration"),
                "updated": events.get("last changed"),
                "nameservers": nameservers,
                "status": statuses,
            },
        )
