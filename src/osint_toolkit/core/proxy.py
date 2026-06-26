"""Proxy rotation engine — load proxies, health-check, rotate on rate-limit/CF block, auto-cooldown."""

from __future__ import annotations

import asyncio
import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx


@dataclass
class ProxyEntry:
    url: str
    alive: bool = True
    total_requests: int = 0
    total_errors: int = 0
    cooldown_until: float = 0.0
    last_used: float = 0.0
    avg_latency_ms: float = 0.0
    label: str = ""

    @property
    def available(self) -> bool:
        return self.alive and time.monotonic() > self.cooldown_until

    def cooldown(self, seconds: float) -> None:
        self.cooldown_until = time.monotonic() + seconds

    def record_success(self, latency_ms: float) -> None:
        self.total_requests += 1
        self.last_used = time.monotonic()
        n = self.total_requests
        self.avg_latency_ms = self.avg_latency_ms * ((n - 1) / n) + latency_ms / n

    def record_error(self) -> None:
        self.total_requests += 1
        self.total_errors += 1
        self.last_used = time.monotonic()

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.total_errors / self.total_requests


RATE_LIMIT_MARKERS = (
    "login_limit_exceeded",
    "login_auth_options_throttled",
    "requireCaptcha",
    "rate limit",
    "too many requests",
    "slow down",
)

CF_MARKERS = (
    "challenge-platform",
    "cf-browser-verification",
    "Just a moment...",
    "Checking your browser",
    "cf-chl-bypass",
    "_cf_chl_opt",
)


def is_rate_limited(response: httpx.Response) -> bool:
    if response.status_code == 429:
        return True
    body = response.text.lower()
    return any(m.lower() in body for m in RATE_LIMIT_MARKERS)


def is_cloudflare_blocked(response: httpx.Response) -> bool:
    return any(m in response.text for m in CF_MARKERS)


def _normalize_proxy_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if "://" not in raw:
        if raw.startswith("socks5") or raw.startswith("socks4"):
            pass
        else:
            raw = "http://" + raw
    return raw


def load_proxies_from_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    lines = path.read_text().splitlines()
    proxies = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        proxies.append(_normalize_proxy_url(line))
    return [p for p in proxies if p]


def load_proxies_from_env() -> list[str]:
    env = os.environ.get("OSINT_PROXIES", "")
    if not env:
        return []
    return [_normalize_proxy_url(p) for p in env.split(",") if p.strip()]


class ProxyManager:
    def __init__(
        self,
        proxy_urls: list[str] | None = None,
        proxy_file: Path | None = None,
        cooldown_seconds: float = 120.0,
        max_consecutive_errors: int = 5,
        health_check_timeout: float = 8.0,
    ) -> None:
        urls: list[str] = []
        if proxy_urls:
            urls.extend(proxy_urls)
        if proxy_file:
            urls.extend(load_proxies_from_file(proxy_file))
        urls.extend(load_proxies_from_env())

        seen: set[str] = set()
        self.proxies: list[ProxyEntry] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                self.proxies.append(ProxyEntry(url=u, label=u.split("@")[-1] if "@" in u else u))

        self._index = 0
        self._lock = asyncio.Lock()
        self.cooldown_seconds = cooldown_seconds
        self.max_consecutive_errors = max_consecutive_errors
        self.health_check_timeout = health_check_timeout
        self._direct = ProxyEntry(url="", label="direct")

    @property
    def count(self) -> int:
        return len(self.proxies)

    @property
    def alive_count(self) -> int:
        return sum(1 for p in self.proxies if p.available)

    @property
    def has_proxies(self) -> bool:
        return len(self.proxies) > 0

    async def health_check(self, on_result: Any = None) -> int:
        if not self.proxies:
            return 0

        async def _check_one(entry: ProxyEntry) -> bool:
            try:
                async with httpx.AsyncClient(
                    proxy=entry.url,
                    timeout=httpx.Timeout(self.health_check_timeout, connect=5.0),
                    follow_redirects=True,
                ) as client:
                    t0 = time.monotonic()
                    r = await client.get("https://httpbin.org/ip")
                    latency = (time.monotonic() - t0) * 1000
                    if r.status_code == 200:
                        entry.alive = True
                        entry.avg_latency_ms = latency
                        if on_result:
                            on_result(entry, True, latency)
                        return True
            except Exception:
                pass
            entry.alive = False
            if on_result:
                on_result(entry, False, 0)
            return False

        results = await asyncio.gather(*[_check_one(p) for p in self.proxies])
        return sum(results)

    async def next_proxy(self) -> ProxyEntry:
        async with self._lock:
            if not self.proxies:
                return self._direct

            available = [p for p in self.proxies if p.available]
            if not available:
                oldest_cooldown = min(self.proxies, key=lambda p: p.cooldown_until)
                wait = oldest_cooldown.cooldown_until - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(min(wait, 5.0))
                available = [p for p in self.proxies if p.available]
                if not available:
                    return self._direct

            available.sort(key=lambda p: (p.error_rate, p.avg_latency_ms))
            chosen = available[0]
            chosen.last_used = time.monotonic()
            return chosen

    def report_rate_limit(self, proxy: ProxyEntry) -> None:
        proxy.record_error()
        proxy.cooldown(self.cooldown_seconds)

    def report_cf_block(self, proxy: ProxyEntry) -> None:
        proxy.record_error()
        proxy.cooldown(self.cooldown_seconds * 1.5)

    def report_success(self, proxy: ProxyEntry, latency_ms: float) -> None:
        proxy.record_success(latency_ms)

    def report_error(self, proxy: ProxyEntry) -> None:
        proxy.record_error()
        if proxy.total_errors >= self.max_consecutive_errors and proxy.error_rate > 0.8:
            proxy.alive = False

    def build_client(self, proxy: ProxyEntry, timeout_s: float = 20.0) -> httpx.AsyncClient:
        from osint_toolkit.core.http import DEFAULT_USER_AGENT
        ua = os.environ.get("OSINT_USER_AGENT", DEFAULT_USER_AGENT)
        kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(timeout_s, connect=10.0),
            "follow_redirects": True,
            "http2": False,
            "limits": httpx.Limits(
                max_connections=200,
                max_keepalive_connections=40,
                keepalive_expiry=30,
            ),
            "headers": {
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
            },
        }
        if proxy.url:
            kwargs["proxy"] = proxy.url
        return httpx.AsyncClient(**kwargs)

    def summary(self) -> dict[str, Any]:
        return {
            "total": len(self.proxies),
            "alive": self.alive_count,
            "proxies": [
                {
                    "label": p.label,
                    "alive": p.alive,
                    "available": p.available,
                    "requests": p.total_requests,
                    "errors": p.total_errors,
                    "error_rate": round(p.error_rate, 2),
                    "avg_latency_ms": round(p.avg_latency_ms, 1),
                }
                for p in self.proxies
            ],
        }
