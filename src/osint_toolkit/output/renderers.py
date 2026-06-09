"""Report renderers: Rich table (default), JSON, CSV, Markdown."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from osint_toolkit.core.models import Report, Status

_STATUS_STYLES = {
    Status.FOUND: "[bold green]FOUND[/bold green]",
    Status.NOT_FOUND: "[dim]not found[/dim]",
    Status.ERROR: "[red]error[/red]",
    Status.SKIPPED: "[yellow]skipped[/yellow]",
}


def render_table(report: Report, console: Console | None = None) -> None:
    console = console or Console()
    header = (
        f"[bold]{report.target.kind.value}[/bold] = "
        f"[bold cyan]{report.target.value}[/bold cyan]  "
        f"·  mode=[magenta]{report.mode}[/magenta]  "
        f"·  [green]{report.found_count} found[/green] / "
        f"[dim]{report.not_found_count} not[/dim] / "
        f"[red]{report.error_count} err[/red]"
    )
    console.print(header)

    t = Table(show_header=True, header_style="bold", expand=True)
    t.add_column("Source", style="cyan", no_wrap=True)
    t.add_column("Status", no_wrap=True)
    t.add_column("URL / Detail", overflow="fold")
    t.add_column("ms", justify="right", style="dim")

    # Sort: found first, then not_found, then error, alpha by source
    order = {Status.FOUND: 0, Status.NOT_FOUND: 1, Status.SKIPPED: 2, Status.ERROR: 3}
    findings = sorted(report.findings, key=lambda f: (order.get(f.status, 9), f.source))

    for f in findings:
        detail = f.url or ""
        if f.status == Status.ERROR and f.error:
            detail = f"[red]{f.error}[/red]"
        elif f.data:
            interesting = []
            for k, v in f.data.items():
                if v is None or v == [] or v == "" or k in {"site", "host"}:
                    continue
                if isinstance(v, list):
                    interesting.append(f"{k}={', '.join(str(x) for x in v[:3])}")
                else:
                    interesting.append(f"{k}={v}")
                if len(interesting) >= 3:
                    break
            if interesting:
                detail = (detail + "  " + " · ".join(interesting)).strip()
        t.add_row(
            f.source, _STATUS_STYLES.get(f.status, str(f.status)), detail, str(f.elapsed_ms or "")
        )

    console.print(t)


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
