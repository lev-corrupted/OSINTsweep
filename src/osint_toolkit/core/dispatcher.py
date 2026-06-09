"""Async fan-out runner. Filters modules by mode + target category, enforces timeout, isolates errors."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence

import httpx

from osint_toolkit.core.cache import Cache
from osint_toolkit.core.http import build_client
from osint_toolkit.core.models import Confidence, Finding, Report, Status, Target
from osint_toolkit.core.module import BaseModule
from osint_toolkit.core.ratelimit import HostLimiter


class Dispatcher:
    def __init__(
        self,
        modules: Sequence[BaseModule],
        mode: str,
        cache: Cache | None,
        global_timeout_s: float = 10.0,
        per_host_concurrency: int = 4,
    ) -> None:
        self.modules = list(modules)
        self.mode = mode
        self.cache = cache
        self.global_timeout_s = global_timeout_s
        self.limiter = HostLimiter(default_concurrency=per_host_concurrency)

    def _eligible(self, target: Target) -> list[BaseModule]:
        return [
            m
            for m in self.modules
            if self.mode in m.modes_allowed and m.category == target.kind.value
        ]

    async def run(self, target: Target) -> Report:
        eligible = self._eligible(target)
        client = build_client(timeout_s=self.global_timeout_s)
        try:
            tasks = [self._run_one(m, target, client) for m in eligible]
            findings = await asyncio.gather(*tasks)
        finally:
            await client.aclose()
        return Report(target=target, findings=list(findings), mode=self.mode)

    async def _run_one(
        self, module: BaseModule, target: Target, client: httpx.AsyncClient
    ) -> Finding:
        # Cache hit?
        if self.cache is not None:
            cached = await self.cache.get(module.name, target.value)
            if cached is not None:
                return cached

        started = time.monotonic()
        try:
            acquired = await self.limiter.acquire(module.host, module.rate_limit_per_min)
            try:
                finding = await asyncio.wait_for(
                    module.run(target, client), timeout=self.global_timeout_s
                )
            finally:
                acquired.release()
        except TimeoutError:
            return Finding(
                source=module.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"timeout after {self.global_timeout_s}s",
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        except Exception as exc:  # noqa: BLE001
            return Finding(
                source=module.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"{type(exc).__name__}: {exc}",
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )

        finding.elapsed_ms = int((time.monotonic() - started) * 1000)
        if self.cache is not None and finding.status != Status.ERROR:
            await self.cache.set(module.name, target.value, finding)
        return finding
