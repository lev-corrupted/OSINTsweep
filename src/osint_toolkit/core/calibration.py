"""Per-source calibration — detects sources that false-positive on impossible handles.

The trick: pick a username that physically cannot exist (40+ random chars), run every
username module against it, and any source that returns FOUND is unreliable — its
detection logic is too loose (typically an SPA shell returning HTTP 200 for any URL).

Calibration runs once, persists to ~/.osint-toolkit/calibration.json, and the dispatcher
reads it to demote findings from unreliable sources to confidence=low.

Re-run when sites change endpoints: `osint calibrate --refresh`.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from osint_toolkit.core.http import build_client
from osint_toolkit.core.models import Status, Target, TargetKind
from osint_toolkit.core.module import BaseModule

DEFAULT_CALIBRATION_PATH = Path.home() / ".osint-toolkit" / "calibration.json"


def _impossible_handle() -> str:
    """Return a username that no real user could have, conforming to typical
    site rules (alphanumeric only, lowercase, ~32 chars). Underscores would
    cause some sites (WordPress, Bandcamp) to redirect to signup pages or
    reject as invalid, making calibration miss real false-positives."""
    return f"zzimpossible{secrets.token_hex(10)}xx"


@dataclass
class CalibrationEntry:
    source: str
    reliable: bool  # True if the source did NOT false-positive on the impossible handle
    impossible_status: str  # "not_found" | "found" | "error" | "skipped"
    impossible_elapsed_ms: int
    calibrated_at: str  # ISO timestamp

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "reliable": self.reliable,
            "impossible_status": self.impossible_status,
            "impossible_elapsed_ms": self.impossible_elapsed_ms,
            "calibrated_at": self.calibrated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> CalibrationEntry:
        return cls(
            source=d["source"],
            reliable=d["reliable"],
            impossible_status=d["impossible_status"],
            impossible_elapsed_ms=d["impossible_elapsed_ms"],
            calibrated_at=d["calibrated_at"],
        )


class CalibrationStore:
    """Reads/writes calibration.json. Provides .is_reliable(source_name) -> bool|None."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(os.environ.get("OSINT_CALIBRATION_PATH", str(DEFAULT_CALIBRATION_PATH)))
        self._cache: dict[str, CalibrationEntry] | None = None

    def _load(self) -> dict[str, CalibrationEntry]:
        if self._cache is not None:
            return self._cache
        if not self.path.exists():
            self._cache = {}
            return self._cache
        try:
            data = json.loads(self.path.read_text())
            self._cache = {k: CalibrationEntry.from_dict(v) for k, v in data.get("entries", {}).items()}
        except Exception:  # noqa: BLE001
            self._cache = {}
        return self._cache

    def is_reliable(self, source_name: str) -> bool | None:
        """True/False if calibrated, None if no calibration data."""
        entry = self._load().get(source_name)
        if entry is None:
            return None
        return entry.reliable

    def all_entries(self) -> dict[str, CalibrationEntry]:
        return self._load()

    def save(self, entries: dict[str, CalibrationEntry]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at": datetime.now(UTC).isoformat(),
            "entries": {k: v.to_dict() for k, v in entries.items()},
        }
        self.path.write_text(json.dumps(payload, indent=2))
        self._cache = entries

    def exists(self) -> bool:
        return self.path.exists()

    def age_days(self) -> float:
        if not self.path.exists():
            return float("inf")
        return (time.time() - self.path.stat().st_mtime) / 86400.0


async def calibrate_modules(
    modules: list[BaseModule],
    impossible_handle: str | None = None,
    per_host_concurrency: int = 4,
    global_timeout_s: float = 10.0,
    rounds: int = 3,
) -> dict[str, CalibrationEntry]:
    """Run every module against N (default 3) impossible handles and majority-vote.

    A source is marked reliable only if it returns FOUND on a strict minority
    of attempts. Single-shot calibration is flaky — SPA sites randomly serve
    404 for one impossible handle and 200 for another."""
    if impossible_handle is not None:
        handles = [impossible_handle]
    else:
        handles = [_impossible_handle() for _ in range(rounds)]

    now = datetime.now(UTC).isoformat()
    per_source_results: dict[str, list[tuple[str, int]]] = {m.name: [] for m in modules}

    client = build_client(timeout_s=global_timeout_s)
    sem = asyncio.Semaphore(per_host_concurrency * 4)

    async def run_one(mod: BaseModule, handle: str) -> None:
        target = Target(kind=TargetKind.USERNAME, value=handle)
        async with sem:
            started = time.monotonic()
            try:
                finding = await asyncio.wait_for(mod.run(target, client), timeout=global_timeout_s)
                elapsed = int((time.monotonic() - started) * 1000)
                status = finding.status.value
            except (TimeoutError, Exception):  # noqa: BLE001
                elapsed = int((time.monotonic() - started) * 1000)
                status = "error"
            per_source_results[mod.name].append((status, elapsed))

    try:
        for handle in handles:
            await asyncio.gather(*[run_one(m, handle) for m in modules])
    finally:
        await client.aclose()

    results: dict[str, CalibrationEntry] = {}
    threshold = (len(handles) // 2) + 1  # majority of FOUND votes = unreliable
    for source, rounds_data in per_source_results.items():
        if not rounds_data:
            continue
        found_count = sum(1 for s, _ in rounds_data if s == Status.FOUND.value)
        reliable = found_count < threshold
        common_status = max(
            {s for s, _ in rounds_data},
            key=lambda x: sum(1 for s, _ in rounds_data if s == x),
        )
        avg_elapsed = sum(e for _, e in rounds_data) // len(rounds_data)
        results[source] = CalibrationEntry(
            source=source,
            reliable=reliable,
            impossible_status=common_status,
            impossible_elapsed_ms=avg_elapsed,
            calibrated_at=now,
        )

    return results
