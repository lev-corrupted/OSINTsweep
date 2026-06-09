"""SQLite-backed cache with TTL. Async via aiosqlite."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import aiosqlite

from osint_toolkit.core.models import Finding


class Cache:
    """One row per (source, target_value). TTL enforced on get()."""

    def __init__(self, path: Path | str, ttl_hours: int = 24) -> None:
        self.path = Path(path)
        self.ttl_hours = ttl_hours

    async def init(self) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    source TEXT NOT NULL,
                    target_value TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    cached_at TEXT NOT NULL,
                    PRIMARY KEY (source, target_value)
                )
                """
            )
            await db.commit()

    async def get(self, source: str, target_value: str) -> Finding | None:
        cutoff = datetime.now(UTC) - timedelta(hours=self.ttl_hours)
        async with aiosqlite.connect(self.path) as db:
            cursor = await db.execute(
                "SELECT finding_json, cached_at FROM findings WHERE source = ? AND target_value = ?",
                (source, target_value),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            finding_json, cached_at_str = row
            cached_at = datetime.fromisoformat(cached_at_str)
            if cached_at < cutoff:
                return None
            return Finding.model_validate_json(finding_json)

    async def set(self, source: str, target_value: str, finding: Finding) -> None:
        now = datetime.now(UTC).isoformat()
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO findings (source, target_value, finding_json, cached_at)
                VALUES (?, ?, ?, ?)
                """,
                (source, target_value, finding.model_dump_json(), now),
            )
            await db.commit()

    async def invalidate(self, source: str, target_value: str) -> None:
        async with aiosqlite.connect(self.path) as db:
            await db.execute(
                "DELETE FROM findings WHERE source = ? AND target_value = ?",
                (source, target_value),
            )
            await db.commit()
