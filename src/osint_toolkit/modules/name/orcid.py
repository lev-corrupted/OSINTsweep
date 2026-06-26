"""ORCID author lookup — the standard ID for academic researchers worldwide."""

from __future__ import annotations

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class OrcidSearch(BaseModule):
    @property
    def name(self) -> str:
        return "orcid"

    @property
    def category(self) -> str:
        return "name"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "pub.orcid.org"

    @property
    def rate_limit_per_min(self) -> int:
        return 60

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        parts = target.value.split()
        given = parts[0] if parts else target.value
        family = parts[-1] if len(parts) > 1 else ""
        q = f'given-names:"{given}" AND family-name:"{family}"' if family else f'family-name:"{given}"'
        from osint_toolkit.core.http import request_with_retry

        r = await request_with_retry(
            client, "GET",
            "https://pub.orcid.org/v3.0/expanded-search/",
            params={"q": q, "rows": "10"},
            headers={"Accept": "application/json"},
        )
        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"orcid returned {r.status_code}",
            )
        body = r.json()
        results = body.get("expanded-result") or []
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
                "total_results": body.get("num-found"),
                "matches": [
                    {
                        "orcid": x.get("orcid-id"),
                        "given": x.get("given-names"),
                        "family": x.get("family-names"),
                        "credit_name": x.get("credit-name"),
                        "affiliations": x.get("institution-name", []),
                        "url": f"https://orcid.org/{x.get('orcid-id')}",
                    }
                    for x in results[:5]
                ],
            },
        )
