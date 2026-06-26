"""Async fan-out runner. Filters modules by mode + target category, enforces timeout, isolates errors."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable, Sequence

import httpx

from osint_toolkit.core.cache import Cache
from osint_toolkit.core.calibration import CalibrationStore
from osint_toolkit.core.http import build_client
from osint_toolkit.core.models import Confidence, Finding, Report, Status, Target
from osint_toolkit.core.module import BaseModule
from osint_toolkit.core.proxy import ProxyManager, is_rate_limited, is_cloudflare_blocked
from osint_toolkit.core.ratelimit import HostLimiter

OnProgress = Callable[[str, Finding], None]


class Dispatcher:
    def __init__(
        self,
        modules: Sequence[BaseModule],
        mode: str,
        cache: Cache | None,
        global_timeout_s: float = 20.0,
        per_host_concurrency: int = 4,
        calibration: CalibrationStore | None = None,
        strict: bool = False,
        on_progress: OnProgress | None = None,
        proxy_manager: ProxyManager | None = None,
    ) -> None:
        self.modules = list(modules)
        self.mode = mode
        self.cache = cache
        self.global_timeout_s = global_timeout_s
        self.limiter = HostLimiter(default_concurrency=per_host_concurrency)
        self.calibration = calibration
        self.strict = strict
        self.on_progress = on_progress
        self.proxy_manager = proxy_manager

    def _eligible(self, target: Target) -> list[BaseModule]:
        return [m for m in self.modules if self.mode in m.modes_allowed and m.category == target.kind.value]

    @property
    def eligible_count(self) -> int:
        return len(self.modules)

    async def run(self, target: Target) -> Report:
        eligible = self._eligible(target)
        if self.strict and self.calibration is not None:
            eligible = [m for m in eligible if self.calibration.is_reliable(m.name) is not False]

        if self.proxy_manager and self.proxy_manager.has_proxies:
            client = None
        else:
            client = build_client(timeout_s=self.global_timeout_s)

        try:
            stagger_window = min(6.0, len(eligible) * 0.25)
            tasks = [
                self._run_one(m, target, client, stagger_s=random.uniform(0, stagger_window))  # noqa: S311
                for m in eligible
            ]
            findings = await asyncio.gather(*tasks)
        finally:
            if client is not None:
                await client.aclose()

        if self.calibration is not None:
            for f in findings:
                if self.calibration.is_reliable(f.source) is False and f.status == Status.FOUND:
                    f.confidence = Confidence.LOW
                    f.data = {**(f.data or {}), "calibration_warning": "source false-positives on impossible handles"}
        return Report(target=target, findings=list(findings), mode=self.mode)

    async def _run_one(
        self,
        module: BaseModule,
        target: Target,
        client: httpx.AsyncClient | None,
        stagger_s: float = 0.0,
    ) -> Finding:
        if self.cache is not None:
            cached = await self.cache.get(module.name, target.value)
            if cached is not None:
                if self.on_progress:
                    self.on_progress(module.name, cached)
                return cached

        if stagger_s > 0:
            await asyncio.sleep(stagger_s)

        max_proxy_attempts = 3 if (self.proxy_manager and self.proxy_manager.has_proxies) else 1

        started = time.monotonic()
        for attempt in range(max_proxy_attempts):
            proxy_entry = None
            use_client = client

            if self.proxy_manager and self.proxy_manager.has_proxies:
                proxy_entry = await self.proxy_manager.next_proxy()
                use_client = self.proxy_manager.build_client(proxy_entry, timeout_s=self.global_timeout_s)

            try:
                acquired = await self.limiter.acquire(module.host, module.rate_limit_per_min)
                try:
                    finding = await asyncio.wait_for(
                        module.run(target, use_client),
                        timeout=self.global_timeout_s,
                    )
                finally:
                    acquired.release()

                if proxy_entry and self.proxy_manager:
                    if finding.status == Status.ERROR and finding.error:
                        if "rate-limited" in finding.error:
                            self.proxy_manager.report_rate_limit(proxy_entry)
                            if attempt < max_proxy_attempts - 1:
                                continue
                        elif "Cloudflare" in finding.error:
                            self.proxy_manager.report_cf_block(proxy_entry)
                            if attempt < max_proxy_attempts - 1:
                                continue
                        else:
                            self.proxy_manager.report_error(proxy_entry)
                    else:
                        latency = (time.monotonic() - started) * 1000
                        self.proxy_manager.report_success(proxy_entry, latency)

                finding.elapsed_ms = int((time.monotonic() - started) * 1000)
                if proxy_entry and proxy_entry.url:
                    finding.data = {**(finding.data or {}), "_proxy": proxy_entry.label}

                if self.cache is not None and finding.status != Status.ERROR:
                    await self.cache.set(module.name, target.value, finding)
                if self.on_progress:
                    self.on_progress(module.name, finding)
                return finding

            except TimeoutError:
                if proxy_entry and self.proxy_manager:
                    self.proxy_manager.report_error(proxy_entry)
                if attempt < max_proxy_attempts - 1:
                    continue
                return Finding(
                    source=module.name,
                    target_value=target.value,
                    status=Status.ERROR,
                    confidence=Confidence.LOW,
                    error=f"timeout after {self.global_timeout_s}s",
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                )
            except Exception as exc:  # noqa: BLE001
                if proxy_entry and self.proxy_manager:
                    self.proxy_manager.report_error(proxy_entry)
                if attempt < max_proxy_attempts - 1:
                    continue
                return Finding(
                    source=module.name,
                    target_value=target.value,
                    status=Status.ERROR,
                    confidence=Confidence.LOW,
                    error=f"{type(exc).__name__}: {exc}",
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                )
            finally:
                if proxy_entry and use_client is not client:
                    await use_client.aclose()

        return Finding(
            source=module.name,
            target_value=target.value,
            status=Status.ERROR,
            confidence=Confidence.LOW,
            error="all proxies exhausted",
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
