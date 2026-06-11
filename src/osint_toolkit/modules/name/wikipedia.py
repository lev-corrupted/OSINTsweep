"""Wikipedia full-text search by name. Free API, no key, generous rate."""

from __future__ import annotations

import os

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class WikipediaSearch(BaseModule):
    @property
    def name(self) -> str:
        return "wikipedia"

    @property
    def category(self) -> str:
        return "name"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "en.wikipedia.org"

    @property
    def rate_limit_per_min(self) -> int:
        return 60

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        hint = os.environ.get("OSINT_HINT", "")
        query = f"{target.value} {hint}".strip()
        url = "https://en.wikipedia.org/w/api.php"
        r = await client.get(
            url,
            params={
                "action": "query",
                "list": "search",
                "srsearch": query,
                "srlimit": "5",
                "srprop": "snippet|titlesnippet",
                "format": "json",
            },
        )
        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"wikipedia returned {r.status_code}",
            )
        results = r.json().get("query", {}).get("search", [])
        if not results:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.NOT_FOUND,
                confidence=Confidence.MEDIUM,
            )
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.MEDIUM,
            data={
                "total_hits": r.json().get("query", {}).get("searchinfo", {}).get("totalhits"),
                "matches": [
                    {
                        "title": x.get("title"),
                        "url": f"https://en.wikipedia.org/wiki/{(x.get('title') or '').replace(' ', '_')}",
                        "snippet": _strip_html(x.get("snippet", "")),
                    }
                    for x in results[:5]
                ],
            },
        )


def _strip_html(s: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "", s)
