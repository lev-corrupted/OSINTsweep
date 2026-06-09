"""Gravatar profile lookup. Public, no key. SHA-256 of trimmed-lowercased email → JSON profile."""

from __future__ import annotations

import hashlib

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class Gravatar(BaseModule):
    @property
    def name(self) -> str:
        return "gravatar"

    @property
    def category(self) -> str:
        return "email"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "www.gravatar.com"

    @property
    def rate_limit_per_min(self) -> int:
        return 120

    def _hash(self, email: str) -> str:
        return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        h = self._hash(target.value)
        url = f"https://www.gravatar.com/{h}.json"
        r = await client.get(url)
        if r.status_code == 404:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.NOT_FOUND,
                confidence=Confidence.HIGH,
                url=f"https://gravatar.com/{h}",
            )
        if r.status_code != 200:
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"gravatar returned {r.status_code}",
            )
        body = r.json()
        entry = (body.get("entry") or [{}])[0]
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            url=f"https://gravatar.com/{h}",
            data={
                "display_name": entry.get("displayName"),
                "preferred_username": entry.get("preferredUsername"),
                "location": entry.get("currentLocation"),
                "about": entry.get("aboutMe"),
                "accounts": [
                    a.get("shortname") for a in entry.get("accounts", []) if a.get("shortname")
                ],
            },
        )
