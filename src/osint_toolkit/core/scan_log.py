"""Persistent scan log — every run saves results for review and tool improvement.

Logs go to {project_root}/logs/scans_{YYYY-MM}.jsonl, one JSON object per scan.
Each entry captures: target, mode, all findings (found/not_found/error), timing,
and a summary block with error patterns useful for identifying broken sources.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from osint_toolkit.core.models import Report, Status


def _log_dir() -> Path:
    d = Path(__file__).resolve().parents[3] / "logs"
    d.mkdir(exist_ok=True)
    return d


def write_scan_log(report: Report) -> Path:
    now = datetime.now(UTC)
    path = _log_dir() / f"scans_{now.strftime('%Y-%m')}.jsonl"

    errors = []
    for f in report.findings:
        if f.status == Status.ERROR:
            errors.append({
                "source": f.source,
                "error": f.error,
                "elapsed_ms": f.elapsed_ms,
            })

    found_sources = [f.source for f in report.findings if f.status == Status.FOUND]
    not_found_sources = [f.source for f in report.findings if f.status == Status.NOT_FOUND]

    entry = {
        "ts": now.isoformat(),
        "target_kind": report.target.kind.value,
        "target_value": report.target.value,
        "mode": report.mode,
        "sources_checked": len(report.findings),
        "found": len(found_sources),
        "not_found": len(not_found_sources),
        "errors": len(errors),
        "found_sources": found_sources,
        "error_details": errors,
        "timings": {
            f.source: f.elapsed_ms
            for f in report.findings
            if f.elapsed_ms is not None
        },
    }

    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

    return path
