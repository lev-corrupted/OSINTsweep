"""Core Pydantic schemas — the wire format every module produces and every renderer consumes."""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class TargetKind(StrEnum):
    EMAIL = "email"
    USERNAME = "username"
    NAME = "name"
    DOMAIN = "domain"


class Status(StrEnum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    ERROR = "error"
    SKIPPED = "skipped"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Target(BaseModel):
    """A normalized lookup target. Validation + normalization happens here so modules can trust the input."""

    model_config = ConfigDict(frozen=True)

    kind: TargetKind
    value: str

    @field_validator("value")
    @classmethod
    def _normalize(cls, v: str, info: Any) -> str:  # noqa: ANN401
        kind = info.data.get("kind")
        v = v.strip()
        if not v:
            raise ValueError("target value cannot be empty")
        if kind == TargetKind.EMAIL:
            v = v.lower()
            if not _EMAIL_RE.match(v):
                raise ValueError(f"invalid email: {v!r}")
        elif kind == TargetKind.USERNAME:
            # Usernames are case-preserved (some sites are case-sensitive); just strip.
            pass
        elif kind == TargetKind.DOMAIN:
            v = v.lower()
        return v


class Finding(BaseModel):
    """One source's verdict on one target. The atom of every Report."""

    model_config = ConfigDict(populate_by_name=True)

    source: str = Field(description="module name, e.g. 'gravatar', 'github_username'")
    target_value: str
    status: Status
    confidence: Confidence
    data: dict[str, Any] = Field(default_factory=dict)
    url: str | None = None
    error: str | None = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    elapsed_ms: int | None = None


class Source(BaseModel):
    """Static metadata about a source — surfaced in --help and documentation."""

    name: str
    category: str
    host: str
    requires_api_key: bool = False
    modes_allowed: set[str]
    rate_limit_per_min: int = 60


class Report(BaseModel):
    """Aggregated findings for one target lookup. The output unit."""

    target: Target
    findings: list[Finding]
    mode: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def found_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.FOUND)

    @property
    def not_found_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.NOT_FOUND)

    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.ERROR)

    def only_found(self) -> Iterator[Finding]:
        return (f for f in self.findings if f.status == Status.FOUND)

    def model_dump_json(self, **kwargs: Any) -> str:  # noqa: ANN401
        # Include the count properties so JSON output includes them
        kwargs.setdefault("exclude_none", False)
        base = super().model_dump_json(**kwargs)
        import json

        as_dict = json.loads(base)
        as_dict["found_count"] = self.found_count
        as_dict["not_found_count"] = self.not_found_count
        as_dict["error_count"] = self.error_count
        return json.dumps(as_dict)
