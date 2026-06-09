"""Tests for the cross-source correlator."""

from __future__ import annotations

from osint_toolkit.core.correlator import derive_targets
from osint_toolkit.core.models import Confidence, Finding, Report, Status, Target, TargetKind


def test_gravatar_preferred_username_derives_username_target() -> None:
    target = Target(kind=TargetKind.EMAIL, value="alice@example.com")
    findings = [
        Finding(
            source="gravatar",
            target_value="alice@example.com",
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            data={"preferred_username": "alice", "accounts": ["twitter", "github"]},
        )
    ]
    report = Report(target=target, findings=findings, mode="prospect")
    derived = derive_targets(report)
    values = {d.value for d in derived}
    kinds = {d.kind for d in derived}
    assert "alice" in values
    assert TargetKind.USERNAME in kinds


def test_self_referential_not_derived() -> None:
    """A finding pointing back at the original target should not generate a duplicate."""
    target = Target(kind=TargetKind.USERNAME, value="alice")
    findings = [
        Finding(
            source="gravatar_profile",
            target_value="alice",
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            data={"preferred_username": "alice"},
        )
    ]
    report = Report(target=target, findings=findings, mode="prospect")
    derived = derive_targets(report)
    # The only candidate would be (USERNAME, "alice") — same as input, so should be filtered.
    assert all(d.value != "alice" or d.kind != TargetKind.USERNAME for d in derived)


def test_no_derivations_when_no_findings() -> None:
    target = Target(kind=TargetKind.EMAIL, value="ghost@example.com")
    findings = [
        Finding(
            source="gravatar",
            target_value="ghost@example.com",
            status=Status.NOT_FOUND,
            confidence=Confidence.HIGH,
        )
    ]
    report = Report(target=target, findings=findings, mode="prospect")
    assert derive_targets(report) == []
