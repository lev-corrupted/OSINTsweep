"""Tests for core Pydantic models — schema must be stable and serialize cleanly."""

from __future__ import annotations

import json
from datetime import datetime

import pytest
from pydantic import ValidationError

from osint_toolkit.core.models import Confidence, Finding, Report, Status, Target, TargetKind


class TestTarget:
    def test_email_target_lowercases(self) -> None:
        t = Target(kind=TargetKind.EMAIL, value="ALICE@Example.COM")
        assert t.value == "alice@example.com"

    def test_username_target_strips(self) -> None:
        t = Target(kind=TargetKind.USERNAME, value="  octocat  ")
        assert t.value == "octocat"

    def test_invalid_email_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target(kind=TargetKind.EMAIL, value="not-an-email")

    def test_empty_value_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Target(kind=TargetKind.USERNAME, value="")


class TestFinding:
    def test_basic_finding(self) -> None:
        f = Finding(
            source="gravatar",
            target_value="alice@example.com",
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            data={"display_name": "Alice"},
        )
        assert f.source == "gravatar"
        assert f.status == Status.FOUND
        assert f.confidence == Confidence.HIGH

    def test_finding_json_round_trip(self) -> None:
        f = Finding(
            source="github",
            target_value="octocat",
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            data={"url": "https://github.com/octocat"},
        )
        as_json = f.model_dump_json()
        round = Finding.model_validate_json(as_json)
        assert round == f

    def test_finding_has_timestamp(self) -> None:
        f = Finding(
            source="x",
            target_value="y",
            status=Status.NOT_FOUND,
            confidence=Confidence.LOW,
        )
        assert isinstance(f.observed_at, datetime)
        assert f.observed_at.tzinfo is not None

    def test_finding_with_error(self) -> None:
        f = Finding(
            source="someapi",
            target_value="x",
            status=Status.ERROR,
            confidence=Confidence.LOW,
            error="connection refused",
        )
        assert f.status == Status.ERROR
        assert f.error == "connection refused"


class TestReport:
    def test_report_aggregates_findings(self) -> None:
        target = Target(kind=TargetKind.USERNAME, value="octocat")
        findings = [
            Finding(
                source="github",
                target_value="octocat",
                status=Status.FOUND,
                confidence=Confidence.HIGH,
            ),
            Finding(
                source="twitter",
                target_value="octocat",
                status=Status.NOT_FOUND,
                confidence=Confidence.HIGH,
            ),
            Finding(
                source="reddit",
                target_value="octocat",
                status=Status.FOUND,
                confidence=Confidence.MEDIUM,
            ),
        ]
        r = Report(target=target, findings=findings, mode="prospect")
        assert r.found_count == 2
        assert r.not_found_count == 1
        assert r.error_count == 0
        assert len(r.findings) == 3

    def test_report_serializes_to_json(self) -> None:
        target = Target(kind=TargetKind.USERNAME, value="octocat")
        r = Report(target=target, findings=[], mode="prospect")
        data = json.loads(r.model_dump_json())
        assert data["target"]["value"] == "octocat"
        assert data["mode"] == "prospect"
        assert data["found_count"] == 0

    def test_report_only_found(self) -> None:
        target = Target(kind=TargetKind.USERNAME, value="octocat")
        findings = [
            Finding(source="a", target_value="octocat", status=Status.FOUND, confidence=Confidence.HIGH),
            Finding(
                source="b",
                target_value="octocat",
                status=Status.NOT_FOUND,
                confidence=Confidence.HIGH,
            ),
        ]
        r = Report(target=target, findings=findings, mode="prospect")
        found = list(r.only_found())
        assert len(found) == 1
        assert found[0].source == "a"
