"""HaveIBeenPwned breach lookup.

GATED to --mode selfcheck only. Requires HIBP_API_KEY (HIBP has been paid since 2019).
Without the key, the module is loaded but returns SKIPPED.

NOTE: never enabled in --mode prospect. The dispatcher enforces this via modes_allowed.
"""

from __future__ import annotations

import os

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class HibpBreaches(BaseModule):
    @property
    def name(self) -> str:
        return "hibp_breaches"

    @property
    def category(self) -> str:
        return "email"

    @property
    def modes_allowed(self) -> set[str]:
        return {"selfcheck"}  # hard gate; not allowed in prospect

    @property
    def host(self) -> str:
        return "haveibeenpwned.com"

    @property
    def requires_api_key(self) -> bool:
        return True

    @property
    def rate_limit_per_min(self) -> int:
        return 10  # HIBP is paid + politely rate-limited

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        key = os.environ.get("HIBP_API_KEY")
        if not key:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.SKIPPED,
                confidence=Confidence.LOW,
                error="HIBP_API_KEY not set",
            )
        from osint_toolkit.core.http import request_with_retry

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target.value}"
        r = await request_with_retry(
            client, "GET", url,
            headers={"hibp-api-key": key, "User-Agent": "osint-toolkit"},
            params={"truncateResponse": "false"},
        )
        if r.status_code == 404:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.NOT_FOUND,
                confidence=Confidence.HIGH,
                data={"breaches": []},
            )
        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"HIBP returned {r.status_code}",
            )
        breaches = r.json()
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            data={"breach_count": len(breaches), "breaches": [b.get("Name") for b in breaches]},
        )
