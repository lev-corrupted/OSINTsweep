"""Shared httpx.AsyncClient factory — one client per Dispatcher run for connection reuse."""

from __future__ import annotations

import os

import httpx

DEFAULT_USER_AGENT = "osint-toolkit/0.1 (+https://github.com/levtheswag/osint-toolkit)"


def build_client(timeout_s: float = 10.0) -> httpx.AsyncClient:
    ua = os.environ.get("OSINT_USER_AGENT", DEFAULT_USER_AGENT)
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_s),
        follow_redirects=True,
        headers={"User-Agent": ua, "Accept": "text/html,application/json,*/*"},
    )
