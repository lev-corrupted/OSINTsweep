"""Hunter.io company-domain email-pattern lookup.

Given an email at a custom domain, ask Hunter.io for the company's email pattern
(e.g., {first}.{last}@acme.com) and any public employees. Optional — needs HUNTER_API_KEY.
"""

from __future__ import annotations

import os

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule

_FREE_PROVIDERS = {"gmail.com", "outlook.com", "yahoo.com", "icloud.com", "hotmail.com", "proton.me"}


class HunterPattern(BaseModule):
    @property
    def name(self) -> str:
        return "hunter_io"

    @property
    def category(self) -> str:
        return "email"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "api.hunter.io"

    @property
    def requires_api_key(self) -> bool:
        return True

    @property
    def rate_limit_per_min(self) -> int:
        return 20

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        key = os.environ.get("HUNTER_API_KEY")
        if not key:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.SKIPPED,
                confidence=Confidence.LOW,
                error="HUNTER_API_KEY not set",
            )
        domain = target.value.split("@", 1)[1]
        if domain in _FREE_PROVIDERS:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.SKIPPED,
                confidence=Confidence.HIGH,
                error=f"{domain} is a free provider — pattern lookup not meaningful",
            )
        from osint_toolkit.core.http import request_with_retry

        url = "https://api.hunter.io/v2/domain-search"
        r = await request_with_retry(client, "GET", url, params={"domain": domain, "api_key": key, "limit": 10})
        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"hunter.io returned {r.status_code}",
            )
        body = r.json().get("data", {})
        pattern = body.get("pattern")
        emails = body.get("emails", [])
        if not pattern and not emails:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.NOT_FOUND,
                confidence=Confidence.MEDIUM,
                data={"domain": domain},
            )
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            data={
                "domain": domain,
                "organization": body.get("organization"),
                "pattern": pattern,
                "people_count": len(emails),
                "sample_emails": [
                    {
                        "value": e.get("value"),
                        "first": e.get("first_name"),
                        "last": e.get("last_name"),
                        "position": e.get("position"),
                    }
                    for e in emails[:5]
                ],
            },
        )
