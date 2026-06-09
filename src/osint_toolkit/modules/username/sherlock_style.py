"""Data-driven Sherlock-style username presence checker.

Each site is one JSON object in data/username_sites.json:

  {
    "name": "github",
    "host": "github.com",
    "url": "https://github.com/{username}",
    "detect": {"type": "status_code", "found": 200, "not_found": 404},
    "modes_allowed": ["prospect", "selfcheck", "pentest"]
  }

Detection schemes supported:
- status_code:        compare HTTP status to found/not_found ints
- body_marker:        substring match on response body (found_when / not_found_when)
- json_field_truthy:  fetch dot-path field from JSON; truthy = found, empty = not found
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


def _dot_get(obj: Any, path: str) -> Any:  # noqa: ANN401
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _marker_match(spec: dict[str, Any] | None, body: str) -> bool:
    if not spec:
        return False
    if "contains" in spec:
        return spec["contains"] in body
    if "regex" in spec:
        return bool(re.search(spec["regex"], body))
    return False


def _format_body(body: Any, username: str) -> Any:  # noqa: ANN401
    """Recursively substitute {username} placeholders inside a JSON body."""
    if isinstance(body, str):
        return body.format(username=username)
    if isinstance(body, list):
        return [_format_body(v, username) for v in body]
    if isinstance(body, dict):
        return {k: _format_body(v, username) for k, v in body.items()}
    return body


class UsernameSite(BaseModule):
    def __init__(self, spec: dict[str, Any]) -> None:
        self.spec = spec

    @property
    def name(self) -> str:
        return self.spec["name"]

    @property
    def category(self) -> str:
        return "username"

    @property
    def modes_allowed(self) -> set[str]:
        return set(self.spec.get("modes_allowed", ["prospect", "selfcheck", "pentest"]))

    @property
    def host(self) -> str:
        return self.spec["host"]

    @property
    def rate_limit_per_min(self) -> int:
        return int(self.spec.get("rate_limit_per_min", 20))

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        from osint_toolkit.core.http import request_with_retry

        url = self.spec["url"].format(username=target.value)
        method = self.spec.get("method", "GET").upper()
        headers = {k: v.format(username=target.value) for k, v in self.spec.get("headers", {}).items()}
        max_attempts = int(self.spec.get("max_attempts", 3))

        kwargs: dict[str, Any] = {"headers": headers}
        if "json_body" in self.spec:
            kwargs["json"] = _format_body(self.spec["json_body"], target.value)
        if "form_data" in self.spec:
            kwargs["data"] = {k: v.format(username=target.value) for k, v in self.spec["form_data"].items()}

        r = await request_with_retry(client, method, url, max_attempts=max_attempts, **kwargs)

        detect = self.spec.get("detect", {})
        scheme = detect.get("type")

        if scheme == "status_code":
            if r.status_code == detect.get("found"):
                return self._found(target, url)
            if r.status_code == detect.get("not_found"):
                return self._not_found(target, url)
            return self._error(target, f"unexpected status {r.status_code}", url)

        if scheme == "json_field_truthy":
            try:
                data = r.json()
            except Exception as exc:  # noqa: BLE001
                return self._error(target, f"json parse failed: {exc}", url)
            field = detect.get("field", "")
            value = _dot_get(data, field)
            if value:
                return self._found(target, url)
            return self._not_found(target, url)

        if scheme == "body_marker":
            body = r.text
            found_when = detect.get("found_when")
            if found_when:
                spec_subbed = {
                    k: v.format(username=target.value) if isinstance(v, str) else v for k, v in found_when.items()
                }
                if _marker_match(spec_subbed, body):
                    return self._found(target, url)
            not_found_when = detect.get("not_found_when")
            if not_found_when:
                spec_subbed = {
                    k: v.format(username=target.value) if isinstance(v, str) else v for k, v in not_found_when.items()
                }
                if _marker_match(spec_subbed, body):
                    return self._not_found(target, url)
            return self._error(target, "no detect marker matched", url)

        return self._error(target, f"unknown detect.type {scheme!r}", url)

    def _found(self, target: Target, url: str) -> Finding:
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            url=url,
            data={"site": self.name, "host": self.host},
        )

    def _not_found(self, target: Target, url: str) -> Finding:
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.NOT_FOUND,
            confidence=Confidence.HIGH,
            url=url,
            data={"site": self.name, "host": self.host},
        )

    def _error(self, target: Target, msg: str, url: str) -> Finding:
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            url=url,
            error=msg,
        )


def load_username_sites(path: Path | None = None) -> Iterator[UsernameSite]:
    if path is None:
        path = Path(__file__).resolve().parents[2] / "data" / "username_sites.json"
    if not path.exists():
        return iter(())
    with open(path) as f:
        sites = json.load(f)
    return iter(UsernameSite(s) for s in sites)
