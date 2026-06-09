"""Holehe-style email registration discovery.

Each site is described declaratively (host, URL, method, form, response fingerprints).
The check posts the email and looks for the "registered" / "not registered" fingerprint
in the response body. If neither matches, we report ERROR (we don't guess).

Rate limits per site are conservative — these endpoints are sensitive and we don't want
to land any source in blocklist hell. v0.1 ships a small set of well-fingerprinted sites
loaded from data/holehe_sites.json.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


def _match(spec: dict[str, Any] | None, body: str) -> bool:
    if not spec:
        return False
    if "contains" in spec:
        return spec["contains"] in body
    if "regex" in spec:
        return bool(re.search(spec["regex"], body))
    if "status_code" in spec:
        # status code is handled outside; this path is unused but reserved
        return False
    return False


def _format_json_body(body: Any, email: str) -> Any:  # noqa: ANN401
    """Recursively substitute {email} placeholders inside a JSON body."""
    if isinstance(body, str):
        return body.format(email=email)
    if isinstance(body, list):
        return [_format_json_body(v, email) for v in body]
    if isinstance(body, dict):
        return {k: _format_json_body(v, email) for k, v in body.items()}
    return body


class HolehSite(BaseModule):
    """One Holehe-style site, parameterized by spec dict."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.spec = spec

    @property
    def name(self) -> str:
        return self.spec["name"]

    @property
    def category(self) -> str:
        return "email"

    @property
    def modes_allowed(self) -> set[str]:
        return set(self.spec.get("modes_allowed", ["selfcheck", "pentest"]))

    @property
    def host(self) -> str:
        return self.spec["host"]

    @property
    def rate_limit_per_min(self) -> int:
        return int(self.spec.get("rate_limit_per_min", 6))

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        method = self.spec.get("method", "POST").upper()
        # URL itself may contain {email} for GET requests
        url = self.spec["url"].format(email=target.value)
        form = {k: v.format(email=target.value) for k, v in self.spec.get("form_data", {}).items()}
        headers = {k: v.format(email=target.value) for k, v in self.spec.get("headers", {}).items()}
        json_body = self.spec.get("json_body")
        if json_body is not None:
            json_body = _format_json_body(json_body, target.value)

        kwargs: dict[str, object] = {"headers": headers}
        if form:
            kwargs["data"] = form
        if json_body is not None:
            kwargs["json"] = json_body

        r = await client.request(method, url, **kwargs)
        body = r.text

        registered = self.spec.get("registered_when")
        not_registered = self.spec.get("not_registered_when")

        if registered and registered.get("status_code") == r.status_code:
            return self._found(target, url)
        if not_registered and not_registered.get("status_code") == r.status_code:
            return self._not_found(target, url)

        if _match(registered, body):
            return self._found(target, url)
        if _match(not_registered, body):
            return self._not_found(target, url)

        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            error="inconclusive: neither registered/not_registered fingerprint matched",
            url=url,
        )

    def _found(self, target: Target, url: str) -> Finding:
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.MEDIUM,
            url=url,
            data={"site": self.name, "host": self.host},
        )

    def _not_found(self, target: Target, url: str) -> Finding:
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.NOT_FOUND,
            confidence=Confidence.MEDIUM,
            url=url,
            data={"site": self.name, "host": self.host},
        )


def load_holehe_sites(path: Path | None = None) -> Iterator[HolehSite]:
    """Load HolehSite instances from data/holehe_sites.json (or override path)."""
    if path is None:
        path = Path(__file__).resolve().parents[2] / "data" / "holehe_sites.json"
    if not path.exists():
        return iter(())
    with open(path) as f:
        sites = json.load(f)
    return iter(HolehSite(s) for s in sites)
