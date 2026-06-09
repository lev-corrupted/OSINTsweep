"""Per-host async semaphore + simple token-bucket. Keeps us off any source's blocklist."""

from __future__ import annotations

import asyncio
import time


class HostLimiter:
    """One semaphore per host (max concurrent in flight) + one token bucket per host (req/min ceiling)."""

    def __init__(self, default_concurrency: int = 4) -> None:
        self.default_concurrency = default_concurrency
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        self._buckets: dict[str, _TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def _semaphore(self, host: str) -> asyncio.Semaphore:
        async with self._lock:
            if host not in self._semaphores:
                self._semaphores[host] = asyncio.Semaphore(self.default_concurrency)
            return self._semaphores[host]

    def _bucket(self, host: str, rate_per_min: int) -> _TokenBucket:
        if host not in self._buckets:
            self._buckets[host] = _TokenBucket(rate_per_min)
        return self._buckets[host]

    async def acquire(self, host: str, rate_per_min: int) -> _Acquired:
        sem = await self._semaphore(host)
        await sem.acquire()
        bucket = self._bucket(host, rate_per_min)
        await bucket.take()
        return _Acquired(sem)


class _Acquired:
    def __init__(self, sem: asyncio.Semaphore) -> None:
        self._sem = sem

    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *_args: object) -> None:
        self._sem.release()

    def release(self) -> None:
        self._sem.release()


class _TokenBucket:
    """Refills `rate_per_min` tokens over 60s; .take() waits if empty."""

    def __init__(self, rate_per_min: int) -> None:
        self.capacity = max(1, rate_per_min)
        self.tokens = float(self.capacity)
        self.refill_per_s = self.capacity / 60.0
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.refill_per_s)
            self.last = now
            if self.tokens >= 1:
                self.tokens -= 1
                return
            needed = (1 - self.tokens) / self.refill_per_s
        await asyncio.sleep(needed)
        async with self._lock:
            self.tokens = max(0.0, self.tokens - 1)
            self.last = time.monotonic()
