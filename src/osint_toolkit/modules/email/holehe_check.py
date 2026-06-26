"""Holehe-style email registration discovery.

Each site is described declaratively (host, URL, method, form, response fingerprints).
The check posts the email and looks for the "registered" / "not registered" fingerprint
in the response body. If neither matches, we report ERROR (we don't guess).

Rate limits per site are conservative — these endpoints are sensitive and we don't want
to land any source in blocklist hell. v0.1 ships a small set of well-fingerprinted sites
loaded from data/holehe_sites.json.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule

_CF_MARKERS = ("challenge-platform", "cf-browser-verification", "Just a moment...", "Checking your browser", "cf-chl-bypass", "_cf_chl_opt")


def _is_cloudflare(body: str) -> bool:
    return any(m in body for m in _CF_MARKERS)


def _match(spec: dict[str, Any] | None, body: str) -> bool:
    if not spec:
        return False
    if "contains" in spec:
        return spec["contains"] in body
    if "regex" in spec:
        return bool(re.search(spec["regex"], body))
    if "status_code" in spec:
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
        from osint_toolkit.core.http import request_with_retry

        method = self.spec.get("method", "POST").upper()
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

        max_attempts = int(self.spec.get("max_attempts", 4))
        retry_on = (500, 502, 503, 504)

        for attempt in range(2):
            r = await request_with_retry(client, method, url, max_attempts=max_attempts, retry_on=retry_on, **kwargs)

            if r.status_code == 429 or "login_limit_exceeded" in r.text or "login_auth_options_throttled" in r.text or "requireCaptcha" in r.text:
                return Finding(
                    source=self.name,
                    target_value=target.value,
                    status=Status.ERROR,
                    confidence=Confidence.LOW,
                    error="rate-limited — try again later",
                    url=url,
                )

            body = r.text

            if _is_cloudflare(body):
                if attempt == 0:
                    await asyncio.sleep(2.0)
                    continue
                return Finding(
                    source=self.name,
                    target_value=target.value,
                    status=Status.ERROR,
                    confidence=Confidence.LOW,
                    error="blocked by Cloudflare challenge",
                    url=url,
                )

            registered = self.spec.get("registered_when")
            not_registered = self.spec.get("not_registered_when")

            if registered and registered.get("status_code") == r.status_code:
                return self._found(target, url, body)
            if not_registered and not_registered.get("status_code") == r.status_code:
                return self._not_found(target, url)

            if _match(registered, body):
                return self._found(target, url, body)
            if _match(not_registered, body):
                return self._not_found(target, url)

            if attempt == 0:
                await asyncio.sleep(1.5)
                continue

            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"inconclusive (HTTP {r.status_code}): fingerprint mismatch",
                url=url,
            )

        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            error="inconclusive: max retries",
            url=url,
        )

    def _found(self, target: Target, url: str, response_body: str = "") -> Finding:
        data: dict[str, object] = {"site": self.name, "host": self.host}
        data.update(self._extract_details(response_body))
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.MEDIUM,
            url=url,
            data=data,
        )

    def _extract_details(self, body: str) -> dict[str, object]:
        """Try to pull useful metadata from the response body."""
        import json as _json

        details: dict[str, object] = {}
        try:
            j = _json.loads(body)
        except (ValueError, TypeError):
            return details

        if self.name == "microsoft":
            details["has_password"] = bool(j.get("Credentials", {}).get("HasPassword"))
            if federated := j.get("Credentials", {}).get("FederationRedirectUrl"):
                details["federation_url"] = federated
            if brand := j.get("Credentials", {}).get("FederationBrandName"):
                details["federation_brand"] = brand
        elif self.name == "twitter":
            if j.get("taken"):
                details["email_registered"] = True
        elif self.name == "spotify":
            details["email_registered"] = j.get("status") == 20
        elif self.name == "github_email":
            items = j.get("items", [])
            if items:
                user = items[0]
                details["username"] = user.get("login")
                details["profile_url"] = user.get("html_url")
                details["avatar_url"] = user.get("avatar_url")
        elif self.name == "firefox":
            details["email_registered"] = j.get("exists") is True
        elif self.name == "wordpress_email":
            details["email_registered"] = True
            details["passwordless"] = j.get("passwordless")
        elif self.name == "instagram":
            details["email_registered"] = True
            suggestions = j.get("username_suggestions", [])
            if suggestions:
                details["suggested_usernames"] = suggestions[:3]
        elif self.name == "duolingo_email":
            users = j.get("users", [])
            if users:
                u = users[0]
                details["username"] = u.get("username")
                details["display_name"] = u.get("name")
                details["has_google"] = u.get("hasGoogleId")
                details["has_facebook"] = u.get("hasFacebookId")
        elif self.name == "etsy_email":
            details["login_name"] = j.get("login_name")
            details["display_name"] = j.get("real_name") or j.get("display_name")
            details["is_seller"] = j.get("is_seller")
            details["avatar_url"] = j.get("avatar_url")
            details["profile_url"] = f"https://www.etsy.com/people/{j.get('login_name')}" if j.get("login_name") else None
            details["created"] = j.get("create_date")
        elif self.name == "coursera_email":
            methods = j.get("loginMethods", [])
            if methods:
                details["login_methods"] = methods
        elif self.name == "disney_email":
            flow = j.get("data", {}).get("guestFlow")
            details["guest_flow"] = flow
        elif self.name == "anydo_email":
            details["user_exists"] = j.get("user_exists")
        elif self.name == "adobe":
            if isinstance(j, list) and j:
                acct = j[0]
                details["account_type"] = acct.get("type")
                auth_methods = [m.get("id") for m in acct.get("authenticationMethods", [])]
                if auth_methods:
                    details["auth_methods"] = auth_methods
                status = acct.get("status", {})
                if status.get("code"):
                    details["account_status"] = status["code"]

        return details

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
