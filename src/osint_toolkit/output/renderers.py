"""Report renderers: Rich table (default), JSON, CSV, Markdown."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from osint_toolkit.core.models import Confidence, Report, Status

_STATUS_STYLES = {
    Status.FOUND: "[bold green]FOUND[/bold green]",
    Status.NOT_FOUND: "[dim]not found[/dim]",
    Status.ERROR: "[red]error[/red]",
    Status.SKIPPED: "[yellow]skipped[/yellow]",
}

# Found with low confidence = source false-positives on impossible handles
_LOW_CONF_FOUND = "[yellow]FOUND[?][/yellow]"


def _status_label(f) -> str:  # noqa: ANN001
    if f.status == Status.FOUND and f.confidence == Confidence.LOW:
        return _LOW_CONF_FOUND
    return _STATUS_STYLES.get(f.status, str(f.status))


def render_table(report: Report, console: Console | None = None) -> None:
    console = console or Console()

    # Count high-confidence vs low-confidence FOUND
    high_found = sum(1 for f in report.findings if f.status == Status.FOUND and f.confidence != Confidence.LOW)
    low_found = sum(1 for f in report.findings if f.status == Status.FOUND and f.confidence == Confidence.LOW)

    header = (
        f"[bold]{report.target.kind.value}[/bold] = "
        f"[bold cyan]{report.target.value}[/bold cyan]  "
        f"·  mode=[magenta]{report.mode}[/magenta]  "
        f"·  [green]{high_found} FOUND[/green]"
    )
    if low_found:
        header += f" + [yellow]{low_found} weak[?][/yellow]"
    header += f" / [dim]{report.not_found_count} not[/dim] / [red]{report.error_count} err[/red]"
    console.print(header)

    t = Table(show_header=True, header_style="bold", expand=True)
    t.add_column("Source", style="cyan", no_wrap=True)
    t.add_column("Status", no_wrap=True)
    t.add_column("URL / Detail", overflow="fold")
    t.add_column("ms", justify="right", style="dim")

    # Sort: high-conf found first, then low-conf found, then not_found, then error
    def sort_key(f) -> tuple[int, str]:  # noqa: ANN001
        if f.status == Status.FOUND and f.confidence != Confidence.LOW:
            return (0, f.source)
        if f.status == Status.FOUND:
            return (1, f.source)
        if f.status == Status.NOT_FOUND:
            return (2, f.source)
        if f.status == Status.SKIPPED:
            return (3, f.source)
        return (4, f.source)

    findings = sorted(report.findings, key=sort_key)

    for f in findings:
        detail = f.url or ""
        if f.status == Status.ERROR and f.error:
            detail = f"[red]{f.error}[/red]"
        elif f.data:
            interesting = []
            for k, v in f.data.items():
                if v is None or v == [] or v == "" or k in {"site", "host"}:
                    continue
                if k == "calibration_warning":
                    interesting.append(f"[yellow]⚠ {v}[/yellow]")
                    continue
                if isinstance(v, list):
                    interesting.append(f"{k}={', '.join(str(x) for x in v[:3])}")
                else:
                    interesting.append(f"{k}={v}")
                if len(interesting) >= 3:
                    break
            if interesting:
                detail = (detail + "  " + " · ".join(interesting)).strip()
        t.add_row(f.source, _status_label(f), detail, str(f.elapsed_ms or ""))

    console.print(t)
    if low_found:
        console.print(
            f"[dim italic]{low_found} weak finds[?] = source flagged by calibration "
            f"as false-positive on impossible handles. Use --strict to hide them.[/dim italic]"
        )


def render_json(report: Report) -> str:
    return report.model_dump_json()


def render_csv(report: Report) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["source", "status", "confidence", "url", "elapsed_ms", "error", "data"])
    for f in report.findings:
        w.writerow(
            [
                f.source,
                f.status.value,
                f.confidence.value,
                f.url or "",
                f.elapsed_ms or "",
                f.error or "",
                json.dumps(f.data, separators=(",", ":")) if f.data else "",
            ]
        )
    return buf.getvalue()


def render_markdown(report: Report) -> str:
    lines = [
        f"# OSINT Report — `{report.target.kind.value}` = `{report.target.value}`",
        "",
        f"- **Mode:** `{report.mode}`",
        f"- **Generated:** {report.generated_at.isoformat()}",
        f"- **Summary:** {report.found_count} found · {report.not_found_count} not found · {report.error_count} errors",
        "",
        "## Found",
        "",
    ]
    if report.found_count == 0:
        lines.append("_(none)_")
    else:
        lines.append("| Source | URL | Detail |")
        lines.append("|---|---|---|")
        for f in report.only_found():
            detail = json.dumps(f.data, separators=(",", ":")) if f.data else ""
            lines.append(f"| `{f.source}` | {f.url or ''} | `{detail}` |")
    lines.extend(["", "## Not found / errors", ""])
    lines.append("| Source | Status | Note |")
    lines.append("|---|---|---|")
    for f in report.findings:
        if f.status == Status.FOUND:
            continue
        note = f.error or ""
        lines.append(f"| `{f.source}` | {f.status.value} | {note} |")
    return "\n".join(lines) + "\n"


def write_to(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
