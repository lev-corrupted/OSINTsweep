"""Wikidata entity search — structured Q-id lookup by name.

Wikidata is the Linked-Open-Data spine behind Wikipedia. A name match returns
Q-ids you can then expand to occupation, country, employer, date of birth,
notable works, etc. Much more useful than Wikipedia's plain text for OSINT.
"""

from __future__ import annotations

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class WikidataSearch(BaseModule):
    @property
    def name(self) -> str:
        return "wikidata"

    @property
    def category(self) -> str:
        return "name"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "www.wikidata.org"

    @property
    def rate_limit_per_min(self) -> int:
        return 60

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        from osint_toolkit.core.http import request_with_retry

        url = "https://www.wikidata.org/w/api.php"
        r = await request_with_retry(
            client, "GET", url,
            params={
                "action": "wbsearchentities",
                "search": target.value,
                "language": "en",
                "format": "json",
                "limit": "10",
                "type": "item",
            },
        )
        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"wikidata returned {r.status_code}",
            )
        results = r.json().get("search", [])
        # Filter: keep entities whose description suggests a person
        people_hints = (
            "person",
            "actor",
            "politician",
            "scientist",
            "ceo",
            "founder",
            "doctor",
            "footballer",
            "author",
            "musician",
            "engineer",
            "physician",
            "philosopher",
            "researcher",
        )
        people = [x for x in results if any(h in (x.get("description", "") or "").lower() for h in people_hints)]
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
                "total_results": len(results),
                "people_matches": len(people),
                "top_matches": [
                    {
                        "qid": x.get("id"),
                        "label": x.get("label"),
                        "description": x.get("description"),
                        "url": f"https://www.wikidata.org/wiki/{x.get('id')}",
                    }
                    for x in (people or results)[:5]
                ],
            },
        )
