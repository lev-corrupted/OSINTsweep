"""EmailRep.io — email reputation, breach history, social profiles, and domain intelligence.

Free tier: 100 queries/day, no API key required.
Paid tier: higher limits, API key via EMAILREP_API_KEY env var.
"""

from __future__ import annotations

import os

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class EmailRep(BaseModule):
    @property
    def name(self) -> str:
        return "emailrep"

    @property
    def category(self) -> str:
        return "email"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "emailrep.io"

    @property
    def rate_limit_per_min(self) -> int:
        return 10

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        from osint_toolkit.core.http import request_with_retry

        headers: dict[str, str] = {}
        api_key = os.environ.get("EMAILREP_API_KEY")
        if api_key:
            headers["Key"] = api_key

        r = await request_with_retry(
            client, "GET",
            f"https://emailrep.io/{target.value}",
            headers=headers if headers else None,
        )

        if r.status_code == 429:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error="rate-limited — set EMAILREP_API_KEY for higher limits",
            )

        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"HTTP {r.status_code}",
            )

        j = r.json()
        data: dict[str, object] = {}

        data["reputation"] = j.get("reputation", "unknown")
        data["suspicious"] = j.get("suspicious", False)
        data["disposable"] = j.get("references", 0) == 0 and j.get("details", {}).get("disposable", False)

        details = j.get("details", {})
        if details.get("credentials_leaked"):
            data["credentials_leaked"] = True
            data["credentials_leaked_count"] = details.get("credentials_leaked_count", 0)
        if details.get("data_breach"):
            data["data_breach"] = True
        if details.get("malicious_activity"):
            data["malicious_activity"] = True

        profiles = details.get("profiles", [])
        if profiles:
            data["social_profiles"] = profiles

        if details.get("domain_exists") is not None:
            data["domain_exists"] = details["domain_exists"]
        if details.get("free_provider") is not None:
            data["free_provider"] = details["free_provider"]
        if details.get("deliverable") is not None:
            data["deliverable"] = details["deliverable"]
        if details.get("accept_all") is not None:
            data["accept_all"] = details["accept_all"]
        if details.get("spam") is not None:
            data["spam"] = details["spam"]

        days_seen = details.get("last_seen")
        if days_seen:
            data["last_seen"] = days_seen
        first_seen = details.get("first_seen")
        if first_seen:
            data["first_seen"] = first_seen

        references = j.get("references", 0)
        data["references"] = references

        has_substance = (
            j.get("reputation") not in (None, "none")
            or details.get("credentials_leaked")
            or details.get("data_breach")
            or profiles
            or references > 0
        )

        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND if has_substance else Status.NOT_FOUND,
            confidence=Confidence.HIGH if has_substance else Confidence.MEDIUM,
            data=data,
            url=f"https://emailrep.io/{target.value}",
        )
