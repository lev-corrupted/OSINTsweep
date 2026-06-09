"""Tests for the async dispatcher — fan-out, mode-gating, error isolation."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from osint_toolkit.core.dispatcher import Dispatcher
from osint_toolkit.core.models import Confidence, Finding, Status, Target, TargetKind
from osint_toolkit.core.module import BaseModule


class _StubModule(BaseModule):
    """Test double — returns a configured Finding without hitting the network."""

    def __init__(
        self,
        name: str,
        category: str = "email",
        modes_allowed: set[str] | None = None,
        raises: Exception | None = None,
        delay_s: float = 0.0,
        status: Status = Status.FOUND,
    ) -> None:
        self._name = name
        self._category = category
        self._modes_allowed = modes_allowed or {"prospect", "selfcheck", "pentest"}
        self._raises = raises
        self._delay_s = delay_s
        self._status = status
        self.calls = 0

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> str:
        return self._category

    @property
    def modes_allowed(self) -> set[str]:
        return self._modes_allowed

    @property
    def host(self) -> str:
        return f"{self._name}.example"

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        self.calls += 1
        if self._delay_s:
            await asyncio.sleep(self._delay_s)
        if self._raises:
            raise self._raises
        return Finding(
            source=self._name,
            target_value=target.value,
            status=self._status,
            confidence=Confidence.HIGH,
        )


@pytest.mark.asyncio
async def test_dispatcher_runs_all_modules_in_parallel() -> None:
    modules = [_StubModule(f"m{i}", delay_s=0.05) for i in range(5)]
    d = Dispatcher(modules=modules, mode="prospect", cache=None)
    target = Target(kind=TargetKind.EMAIL, value="alice@example.com")

    started = asyncio.get_event_loop().time()
    report = await d.run(target)
    elapsed = asyncio.get_event_loop().time() - started

    # If sequential, this would take 0.25s; in parallel it's near 0.05s.
    assert elapsed < 0.20, f"Dispatcher should run modules in parallel, took {elapsed}s"
    assert len(report.findings) == 5
    assert all(m.calls == 1 for m in modules)


@pytest.mark.asyncio
async def test_dispatcher_filters_by_mode() -> None:
    only_self = _StubModule("hibp", modes_allowed={"selfcheck"})
    public = _StubModule("gravatar", modes_allowed={"prospect", "selfcheck"})
    d = Dispatcher(modules=[only_self, public], mode="prospect", cache=None)
    target = Target(kind=TargetKind.EMAIL, value="x@x.com")
    report = await d.run(target)

    assert only_self.calls == 0, "selfcheck-only module should not run in prospect mode"
    assert public.calls == 1
    assert len(report.findings) == 1
    assert report.findings[0].source == "gravatar"


@pytest.mark.asyncio
async def test_dispatcher_isolates_errors() -> None:
    good = _StubModule("good")
    bad = _StubModule("bad", raises=RuntimeError("boom"))
    d = Dispatcher(modules=[good, bad], mode="prospect", cache=None)
    target = Target(kind=TargetKind.EMAIL, value="x@x.com")
    report = await d.run(target)

    assert len(report.findings) == 2
    good_finding = next(f for f in report.findings if f.source == "good")
    bad_finding = next(f for f in report.findings if f.source == "bad")
    assert good_finding.status == Status.FOUND
    assert bad_finding.status == Status.ERROR
    assert bad_finding.error is not None
    assert "boom" in bad_finding.error


@pytest.mark.asyncio
async def test_dispatcher_respects_global_timeout() -> None:
    slow = _StubModule("slow", delay_s=2.0)
    d = Dispatcher(modules=[slow], mode="prospect", cache=None, global_timeout_s=0.1)
    target = Target(kind=TargetKind.EMAIL, value="x@x.com")
    report = await d.run(target)

    finding = report.findings[0]
    assert finding.status == Status.ERROR
    assert finding.error is not None
    assert "timeout" in finding.error.lower()


@pytest.mark.asyncio
async def test_dispatcher_only_runs_modules_for_target_category() -> None:
    email_mod = _StubModule("gravatar", category="email")
    username_mod = _StubModule("github", category="username")
    d = Dispatcher(modules=[email_mod, username_mod], mode="prospect", cache=None)
    target = Target(kind=TargetKind.EMAIL, value="x@x.com")
    report = await d.run(target)

    assert email_mod.calls == 1
    assert username_mod.calls == 0
    assert len(report.findings) == 1
