"""Search GitHub for users matching a real name."""

from __future__ import annotations

import os

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class GithubNameSearch(BaseModule):
    @property
    def name(self) -> str:
        return "github_name"

    @property
    def category(self) -> str:
        return "name"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "api.github.com"

    @property
    def rate_limit_per_min(self) -> int:
        return 30 if os.environ.get("GITHUB_TOKEN") else 10

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        headers = {"Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        params = {"q": f"{target.value} in:fullname", "per_page": "5"}
        from osint_toolkit.core.http import request_with_retry

        r = await request_with_retry(client, "GET", "https://api.github.com/search/users", params=params, headers=headers)
        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"github returned {r.status_code}",
            )
        body = r.json()
        items = body.get("items", [])
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
            confidence=Confidence.MEDIUM,
            data={
                "total_count": body.get("total_count"),
                "matches": [
                    {"login": i.get("login"), "url": i.get("html_url"), "score": i.get("score")} for i in items
                ],
            },
        )
