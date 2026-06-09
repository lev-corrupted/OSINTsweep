"""Tests for the calibration store + majority-vote logic."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from osint_toolkit.core.calibration import (
    CalibrationEntry,
    CalibrationStore,
    calibrate_modules,
)
from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class _StubMod(BaseModule):
    def __init__(self, name: str, statuses: list[Status]) -> None:
        self._name = name
        self._statuses = list(statuses)

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> str:
        return "username"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return f"{self._name}.example"

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        status = self._statuses.pop(0) if self._statuses else Status.NOT_FOUND
        return Finding(
            source=self._name,
            target_value=target.value,
            status=status,
            confidence=Confidence.HIGH,
        )


def test_calibration_store_round_trip(tmp_path: Path) -> None:
    store = CalibrationStore(path=tmp_path / "cal.json")
    entries = {
        "foo": CalibrationEntry(
            source="foo",
            reliable=True,
            impossible_status="not_found",
            impossible_elapsed_ms=100,
            calibrated_at="2026-06-08T12:00:00Z",
        ),
        "bar": CalibrationEntry(
            source="bar",
            reliable=False,
            impossible_status="found",
            impossible_elapsed_ms=200,
            calibrated_at="2026-06-08T12:00:00Z",
        ),
    }
    store.save(entries)
    fresh = CalibrationStore(path=tmp_path / "cal.json")
    assert fresh.is_reliable("foo") is True
    assert fresh.is_reliable("bar") is False
    assert fresh.is_reliable("unknown") is None


def test_calibration_store_age_days(tmp_path: Path) -> None:
    p = tmp_path / "cal.json"
    store = CalibrationStore(path=p)
    assert store.age_days() == float("inf")
    store.save({})
    assert store.age_days() < 0.01  # just saved


@pytest.mark.asyncio
async def test_majority_vote_unreliable_when_mostly_found() -> None:
    """A source that returns FOUND on 2 of 3 rounds is unreliable."""
    mod = _StubMod("flaky", [Status.FOUND, Status.NOT_FOUND, Status.FOUND])
    results = await calibrate_modules([mod], impossible_handle=None, rounds=3)
    assert "flaky" in results
    assert results["flaky"].reliable is False
    assert results["flaky"].impossible_status == "found"


@pytest.mark.asyncio
async def test_majority_vote_reliable_when_mostly_not_found() -> None:
    """A source that returns FOUND on only 1 of 3 rounds is still reliable."""
    mod = _StubMod("solid", [Status.NOT_FOUND, Status.FOUND, Status.NOT_FOUND])
    results = await calibrate_modules([mod], impossible_handle=None, rounds=3)
    assert results["solid"].reliable is True


@pytest.mark.asyncio
async def test_majority_vote_reliable_when_all_not_found() -> None:
    mod = _StubMod("clean", [Status.NOT_FOUND, Status.NOT_FOUND, Status.NOT_FOUND])
    results = await calibrate_modules([mod], impossible_handle=None, rounds=3)
    assert results["clean"].reliable is True


@pytest.mark.asyncio
async def test_single_round_when_handle_provided() -> None:
    """If a specific impossible_handle is supplied, we only run 1 round."""
    mod = _StubMod("once", [Status.FOUND])
    results = await calibrate_modules([mod], impossible_handle="aaa-fixed-handle")
    assert results["once"].reliable is False
