"""Pentest-mode audit log writer.

In --mode pentest, every Report (input + all findings) gets appended to a JSONL
audit file. Filename: pentest_audit_YYYYMMDD_HHMMSS.jsonl in the current dir
unless OSINT_AUDIT_PATH is set.

Goal: when a client asks "what queries did your tool make against my surface area
during the engagement?", you produce this file.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from osint_toolkit.core.models import Report


def audit_path() -> Path:
    if env := os.environ.get("OSINT_AUDIT_PATH"):
        return Path(env)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path.cwd() / f"pentest_audit_{stamp}.jsonl"


def write(report: Report, path: Path | None = None) -> Path:
    p = path or audit_path()
    with p.open("a", encoding="utf-8") as f:
        f.write(report.model_dump_json() + "\n")
    return p
