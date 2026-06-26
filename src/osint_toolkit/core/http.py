"""Shared httpx.AsyncClient factory + retry-on-429 helper.

The default User-Agent is a real Chrome string — many sources auto-block obvious bot UAs
(Reddit returns HTML to "Python-urllib", Twitch/Cloudflare returns 403). We're still
identifiable: every request carries a `From:` header pointing at the toolkit repo,
which is the polite OSINT convention.
"""

from __future__ import annotations

import asyncio
import os
import random
from typing import Any

import httpx

# Real-ish Chrome 121 UA — generic enough to be normal, recent enough to not look stale.
# Override via OSINT_USER_AGENT env var for stealthier or more identifiable runs.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
DEFAULT_FROM = "osintsweep@github.com (https://github.com/lev-corrupted/OSINTsweep)"


def build_client(timeout_s: float = 20.0) -> httpx.AsyncClient:
    ua = os.environ.get("OSINT_USER_AGENT", DEFAULT_USER_AGENT)
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_s, connect=10.0),
        follow_redirects=True,
        http2=False,
        limits=httpx.Limits(
            max_connections=200,
            max_keepalive_connections=40,
            keepalive_expiry=30,
        ),
        headers={
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
        },
    )


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_attempts: int = 4,
    backoff_base_s: float = 1.0,
    retry_on: tuple[int, ...] = (429, 500, 502, 503, 504),
    **kwargs: Any,
) -> httpx.Response:
    """Make a request; retry on 429/5xx with exponential backoff + Retry-After honor.

    Use this from inside a module instead of `client.request` directly.
    """
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            r = await client.request(method, url, **kwargs)
        except (httpx.ReadError, httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadTimeout, httpx.PoolTimeout) as exc:
            last_exc = exc
            r = None  # type: ignore[assignment]
        else:
            if r.status_code not in retry_on:
                return r

        if attempt == max_attempts - 1:
            if last_exc is not None:
                raise last_exc
            return r

        # Honor Retry-After if present, else exponential backoff with jitter
        wait_s = backoff_base_s * (2**attempt) + random.random() * 0.25  # noqa: S311
        if r is not None and "Retry-After" in r.headers:
            try:
                wait_s = max(wait_s, float(r.headers["Retry-After"]))
            except ValueError:
                pass
        await asyncio.sleep(wait_s)

    # Unreachable, but appease the type checker
    return r
