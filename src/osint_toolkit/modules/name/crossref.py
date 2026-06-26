"""CrossRef — academic papers by author name. ~140M DOI records."""

from __future__ import annotations

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class CrossrefSearch(BaseModule):
    @property
    def name(self) -> str:
        return "crossref"

    @property
    def category(self) -> str:
        return "name"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "api.crossref.org"

    @property
    def rate_limit_per_min(self) -> int:
        return 50

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        from osint_toolkit.core.http import request_with_retry

        r = await request_with_retry(
            client, "GET",
            "https://api.crossref.org/works",
            params={
                "query.author": target.value,
                "rows": "5",
                "select": "DOI,title,author,published-print,container-title,publisher,type",
            },
        )
        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"crossref returned {r.status_code}",
            )
        body = r.json().get("message", {})
        items = body.get("items", [])
        total = body.get("total-results", 0)
        if not items:
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
            confidence=Confidence.LOW if total < 3 else Confidence.MEDIUM,
            data={
                "total_results": total,
                "papers": [
                    {
                        "doi": p.get("DOI"),
                        "title": (p.get("title") or [None])[0],
                        "venue": (p.get("container-title") or [None])[0],
                        "year": _year_of(p),
                        "authors": [
                            f"{a.get('given', '')} {a.get('family', '')}".strip() for a in (p.get("author") or [])
                        ][:3],
                        "url": f"https://doi.org/{p.get('DOI')}" if p.get("DOI") else None,
                    }
                    for p in items[:5]
                ],
            },
        )


def _year_of(paper: dict) -> int | None:
    pub = paper.get("published-print") or paper.get("published-online") or {}
    parts = pub.get("date-parts") or []
    if parts and parts[0]:
        return parts[0][0]
    return None
