"""OpenSanctions — global sanctions, PEPs, and watchlists.

Critical for business OSINT: before signing a clinic / vendor / partner,
check if they're on any sanctions or PEP (Politically Exposed Person) list.
Requires OPENSANCTIONS_API_KEY (free tier at opensanctions.org/api/).
"""

from __future__ import annotations

import os

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class OpenSanctionsSearch(BaseModule):
    @property
    def name(self) -> str:
        return "opensanctions"

    @property
    def category(self) -> str:
        return "name"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "api.opensanctions.org"

    @property
    def requires_api_key(self) -> bool:
        return True

    @property
    def rate_limit_per_min(self) -> int:
        return 30

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        key = os.environ.get("OPENSANCTIONS_API_KEY")
        if not key:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.SKIPPED,
                confidence=Confidence.LOW,
                error="OPENSANCTIONS_API_KEY not set — free tier at opensanctions.org/api/",
            )
        r = await client.get(
            "https://api.opensanctions.org/search/default",
            params={"q": target.value, "limit": "5", "fuzzy": "true"},
            headers={"Authorization": f"ApiKey {key}"},
        )
        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"opensanctions returned {r.status_code}",
            )
        body = r.json()
        results = body.get("results", [])
        if not results:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.NOT_FOUND,
                confidence=Confidence.HIGH,
                data={"clean": True, "total_results": body.get("total", {}).get("value", 0)},
            )
        # Anyone showing up here deserves manual review
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            data={
                "total_results": body.get("total", {}).get("value", 0),
                "warning": "match found on sanctions/PEP/watchlist — manual review required",
                "matches": [
                    {
                        "id": x.get("id"),
                        "name": (x.get("caption") or x.get("name") or x.get("schema")),
                        "schema": x.get("schema"),
                        "datasets": x.get("datasets", [])[:3],
                        "countries": x.get("properties", {}).get("country", []),
                        "topics": x.get("properties", {}).get("topics", []),
                        "url": f"https://www.opensanctions.org/entities/{x.get('id')}/",
                    }
                    for x in results[:5]
                ],
            },
        )
