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
        return body.replace("{username}", username)
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

        return await self._attempt(target, url, method, kwargs, max_attempts, client, retries_left=1)

    async def _attempt(self, target: Target, url: str, method: str, kwargs: dict, max_attempts: int, client: httpx.AsyncClient, retries_left: int) -> Finding:
        from osint_toolkit.core.http import request_with_retry

        r = await request_with_retry(client, method, url, max_attempts=max_attempts, **kwargs)

        try:
            body_text = r.text
        except Exception:
            body_text = r.content.decode("utf-8", errors="replace")

        if _is_cloudflare(body_text):
            if retries_left > 0:
                await asyncio.sleep(2.0)
                return await self._attempt(target, url, method, kwargs, max_attempts, client, retries_left - 1)
            return self._error(target, "blocked by Cloudflare challenge", url)

        detect = self.spec.get("detect", {})
        scheme = detect.get("type")

        if scheme == "status_code":
            if r.status_code == detect.get("found"):
                return self._found(target, url, r)
            if r.status_code == detect.get("not_found"):
                return self._not_found(target, url)
            return self._error(target, f"unexpected status {r.status_code}", url)

        if scheme == "json_field_truthy":
            try:
                data = r.json()
            except Exception:  # noqa: BLE001
                if r.status_code == 404:
                    return self._not_found(target, url)
                if retries_left > 0:
                    await asyncio.sleep(1.5)
                    return await self._attempt(target, url, method, kwargs, max_attempts, client, retries_left - 1)
                return self._error(target, "non-JSON response", url)
            field = detect.get("field", "")
            value = _dot_get(data, field)
            if value:
                return self._found(target, url, r)
            return self._not_found(target, url)

        if scheme == "body_marker":
            body = body_text
            found_when = detect.get("found_when")
            if found_when:
                spec_subbed = {
                    k: v.format(username=target.value) if isinstance(v, str) else v for k, v in found_when.items()
                }
                if _marker_match(spec_subbed, body):
                    return self._found(target, url, r)
            not_found_when = detect.get("not_found_when")
            if not_found_when:
                spec_subbed = {
                    k: v.format(username=target.value) if isinstance(v, str) else v for k, v in not_found_when.items()
                }
                if _marker_match(spec_subbed, body):
                    return self._not_found(target, url)
            if retries_left > 0:
                await asyncio.sleep(1.5)
                return await self._attempt(target, url, method, kwargs, max_attempts, client, retries_left - 1)
            return self._error(target, "no detect marker matched", url)

        return self._error(target, f"unknown detect.type {scheme!r}", url)

    def _found(self, target: Target, url: str, response: httpx.Response | None = None) -> Finding:
        data: dict[str, Any] = {"site": self.name, "host": self.host}
        if response is not None:
            data.update(self._extract_profile_data(response, target.value))
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            url=url,
            data=data,
        )

    def _extract_profile_data(self, response: httpx.Response, username: str) -> dict[str, Any]:
        extras: dict[str, Any] = {}
        try:
            j = response.json()
        except Exception:  # noqa: BLE001
            return extras

        name = self.spec["name"]

        if name == "github_api":
            extras["display_name"] = j.get("name")
            extras["bio"] = j.get("bio")
            extras["location"] = j.get("location")
            extras["company"] = j.get("company")
            extras["public_repos"] = j.get("public_repos")
            extras["followers"] = j.get("followers")
            extras["following"] = j.get("following")
            extras["created"] = j.get("created_at", "")[:10]
            extras["blog"] = j.get("blog")
            extras["twitter"] = j.get("twitter_username")
            extras["avatar"] = j.get("avatar_url")
            extras["profile_url"] = j.get("html_url")

        elif name == "gitlab":
            items = j if isinstance(j, list) else [j]
            if items:
                u = items[0]
                extras["display_name"] = u.get("name")
                extras["avatar"] = u.get("avatar_url")
                extras["profile_url"] = u.get("web_url")
                extras["state"] = u.get("state")

        elif name == "chess_com":
            extras["profile_url"] = j.get("url")
            extras["display_name"] = j.get("name")
            extras["title"] = j.get("title")
            extras["followers"] = j.get("followers")
            extras["country"] = j.get("country", "").split("/")[-1] if j.get("country") else None
            extras["joined"] = j.get("joined")
            extras["last_online"] = j.get("last_online")
            extras["avatar"] = j.get("avatar")
            extras["is_streamer"] = j.get("is_streamer")

        elif name == "lichess":
            extras["display_name"] = j.get("username")
            extras["bio"] = j.get("bio")
            extras["profile_url"] = j.get("url")
            extras["created"] = j.get("createdAt")
            extras["last_seen"] = j.get("seenAt")
            extras["play_time_hours"] = round(j.get("playTime", {}).get("total", 0) / 3600, 1) if j.get("playTime") else None
            perfs = j.get("perfs", {})
            for mode_key in ("blitz", "rapid", "bullet", "classical"):
                if mode_key in perfs:
                    extras[f"rating_{mode_key}"] = perfs[mode_key].get("rating")

        elif name == "hackernews":
            extras["karma"] = j.get("karma")
            extras["created"] = j.get("created")
            extras["about"] = (j.get("about") or "")[:200]
            extras["submitted_count"] = len(j.get("submitted", []))

        elif name == "mastodon_social":
            extras["display_name"] = j.get("name")
            extras["bio"] = (j.get("summary") or "")[:200]
            extras["followers"] = j.get("followers_count") if "followers_count" in j else j.get("totalItems")
            extras["following"] = j.get("following_count")
            extras["posts"] = j.get("statuses_count")
            extras["avatar"] = j.get("icon", {}).get("url") if isinstance(j.get("icon"), dict) else j.get("icon")
            extras["profile_url"] = j.get("url")
            extras["locked"] = j.get("locked") or j.get("manuallyApprovesFollowers")

        elif name == "bluesky":
            extras["did"] = j.get("did")

        elif name == "stackoverflow_user":
            items = j.get("items", [])
            if items:
                u = items[0]
                extras["display_name"] = u.get("display_name")
                extras["reputation"] = u.get("reputation")
                extras["badges_gold"] = u.get("badge_counts", {}).get("gold")
                extras["badges_silver"] = u.get("badge_counts", {}).get("silver")
                extras["badges_bronze"] = u.get("badge_counts", {}).get("bronze")
                extras["profile_url"] = u.get("link")
                extras["avatar"] = u.get("profile_image")
                extras["location"] = u.get("location")

        elif name == "roblox":
            data_list = j.get("data", [])
            if data_list:
                u = data_list[0]
                extras["user_id"] = u.get("id")
                extras["display_name"] = u.get("displayName")

        elif name == "keybase":
            them = j.get("them", [])
            if them and them[0]:
                basics = them[0].get("basics", {})
                extras["uid"] = basics.get("uid")
                extras["username"] = basics.get("username")
                extras["ctime"] = basics.get("ctime")
                extras["mtime"] = basics.get("mtime")

        elif name == "codewars":
            extras["display_name"] = j.get("name")
            extras["honor"] = j.get("honor")
            extras["clan"] = j.get("clan")
            extras["leaderboard_position"] = j.get("leaderboardPosition")
            ranks = j.get("ranks", {}).get("overall", {})
            extras["rank"] = ranks.get("name")
            extras["score"] = ranks.get("score")
            langs = j.get("ranks", {}).get("languages", {})
            if langs:
                extras["languages"] = list(langs.keys())[:8]

        elif name == "hackerrank":
            m = j.get("model", {})
            extras["display_name"] = m.get("name")
            extras["bio"] = (m.get("short_bio") or "")[:200]
            extras["country"] = m.get("country")
            extras["school"] = m.get("school")
            extras["company"] = m.get("company")
            extras["level"] = m.get("level")
            extras["followers"] = m.get("followers_count")
            extras["avatar"] = m.get("avatar")

        elif name == "speedrun":
            d = j.get("data", {})
            extras["display_name"] = d.get("names", {}).get("international")
            extras["profile_url"] = d.get("weblink")
            extras["role"] = d.get("role")
            extras["signup"] = d.get("signup")
            loc = d.get("location", {})
            if loc and loc.get("country"):
                extras["country"] = loc["country"].get("names", {}).get("international")

        elif name == "huggingface":
            extras["display_name"] = j.get("fullname")
            extras["avatar"] = j.get("avatarUrl")
            extras["bio"] = (j.get("details") or "")[:200]
            extras["num_models"] = j.get("numModels")
            extras["num_datasets"] = j.get("numDatasets")
            extras["num_spaces"] = j.get("numSpaces")

        return {k: v for k, v in extras.items() if v is not None and v != "" and v != []}

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
