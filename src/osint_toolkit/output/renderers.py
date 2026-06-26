"""Report renderers: Rich table (default), JSON, CSV, Markdown."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from osint_toolkit.core.models import Confidence, Report, Status

_STATUS_STYLES = {
    Status.FOUND: "[bold green]FOUND[/bold green]",
    Status.NOT_FOUND: "[dim]not found[/dim]",
    Status.ERROR: "[red]error[/red]",
    Status.SKIPPED: "[yellow]skipped[/yellow]",
}

_LOW_CONF_FOUND = "[yellow]FOUND[?][/yellow]"


def _status_label(f) -> str:  # noqa: ANN001
    if f.status == Status.FOUND and f.confidence == Confidence.LOW:
        return _LOW_CONF_FOUND
    return _STATUS_STYLES.get(f.status, str(f.status))


def _format_data_value(key: str, value: object) -> str | None:
    """Format a single data key-value pair for display. Returns None to skip."""
    if value is None or value == [] or value == "" or key in {"site", "host"}:
        return None
    if key == "calibration_warning":
        return "[yellow]calibration: may false-positive[/yellow]"
    if key == "records" and isinstance(value, list) and value and isinstance(value[0], dict) and "exchange" in value[0]:
        sorted_mx = sorted(value, key=lambda r: r.get("priority", 99))
        parts = [f"{r['exchange']} (pri {r['priority']})" for r in sorted_mx[:3]]
        if len(value) > 3:
            parts.append(f"+{len(value) - 3} more")
        return "MX: " + ", ".join(parts)
    if isinstance(value, bool):
        return f"{key}={'✓' if value else '✗'}"
    if isinstance(value, list):
        return f"{key}={', '.join(str(x) for x in value[:5])}"
    return f"{key}={value}"


def _format_finding_detail(f) -> str:  # noqa: ANN001
    """Build a display string for a finding's data."""
    detail = f.url or ""
    if f.data:
        interesting = [_format_data_value(k, v) for k, v in f.data.items()]
        interesting = [x for x in interesting if x is not None]
        if interesting:
            detail = " · ".join(interesting[:6])
    return detail


def _render_summary_panel(report: Report, console: Console) -> None:
    high_found = sum(1 for f in report.findings if f.status == Status.FOUND and f.confidence != Confidence.LOW)
    low_found = sum(1 for f in report.findings if f.status == Status.FOUND and f.confidence == Confidence.LOW)

    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(justify="right", style="bold")
    grid.add_column()

    grid.add_row("Target", f"[bold cyan]{report.target.value}[/bold cyan]")
    grid.add_row("Type", f"[magenta]{report.target.kind.value}[/magenta]")
    grid.add_row("Mode", f"[yellow]{report.mode}[/yellow]")
    grid.add_row("Sources checked", str(len(report.findings)))
    grid.add_row("Found", f"[bold green]{high_found}[/bold green]" + (f" + [yellow]{low_found} weak[/yellow]" if low_found else ""))
    grid.add_row("Not found", f"[dim]{report.not_found_count}[/dim]")
    if report.error_count:
        grid.add_row("Errors", f"[red]{report.error_count}[/red]")

    found_items = [f for f in report.findings if f.status == Status.FOUND and f.confidence != Confidence.LOW]
    if found_items:
        profiles = []
        breaches = []
        details = []
        for f in found_items:
            if f.url:
                profiles.append(f"[cyan]{f.source}[/cyan]")
            if f.data:
                if f.data.get("credentials_leaked") or f.data.get("data_breach"):
                    breaches.append(f.source)
                rep = f.data.get("reputation")
                if rep and rep != "none":
                    details.append(f"reputation: [bold]{rep}[/bold]")
                leaked_count = f.data.get("credentials_leaked_count")
                if leaked_count:
                    details.append(f"credentials leaked: [red bold]{leaked_count}x[/red bold]")
                social = f.data.get("social_profiles")
                if social:
                    details.append(f"social profiles: {', '.join(str(s) for s in social[:5])}")
                username = f.data.get("username")
                if username:
                    details.append(f"linked username: [bold]{username}[/bold]")
                profile_url = f.data.get("profile_url")
                if profile_url:
                    details.append(f"profile: {profile_url}")

        if profiles:
            grid.add_row("Accounts found", ", ".join(profiles[:10]))
        if breaches:
            grid.add_row("Breach exposure", f"[red]{'  '.join(breaches)}[/red]")
        if details:
            grid.add_row("Key intel", " · ".join(details[:5]))

    console.print(Panel(grid, title="[bold]Summary", border_style="bright_blue", padding=(1, 2)))
    console.print()


def render_table(report: Report, console: Console | None = None, show_weak: bool = False) -> None:
    console = console or Console()

    _render_summary_panel(report, console)

    high_found = sum(1 for f in report.findings if f.status == Status.FOUND and f.confidence != Confidence.LOW)

    t = Table(show_header=True, header_style="bold", expand=True, title="[bold]Detailed Findings")
    t.add_column("Source", style="cyan", no_wrap=True)
    t.add_column("Status", no_wrap=True)
    t.add_column("URL / Detail", overflow="fold")
    t.add_column("ms", justify="right", style="dim")

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

    not_found_names = []
    error_names = []
    weak_found_names = []

    for f in findings:
        if f.status == Status.NOT_FOUND:
            not_found_names.append(f.source)
            continue
        if f.status == Status.SKIPPED:
            continue
        if f.status == Status.FOUND and f.confidence == Confidence.LOW and not show_weak:
            weak_found_names.append(f.source)
            continue

        if f.status == Status.ERROR and f.error:
            error_names.append(f"{f.source} ({f.error})")
            continue
        detail = _format_finding_detail(f)
        t.add_row(f.source, _status_label(f), detail, str(f.elapsed_ms or ""))

    console.print(t)

    if not_found_names:
        console.print(
            f"[dim]Not found on {len(not_found_names)} sites: "
            f"{', '.join(not_found_names[:10])}"
            f"{'… +' + str(len(not_found_names) - 10) + ' more' if len(not_found_names) > 10 else ''}[/dim]"
        )
    if weak_found_names:
        console.print(
            f"[yellow dim]{len(weak_found_names)} weak[?] hidden: "
            f"{', '.join(weak_found_names[:8])}"
            f"{'… +' + str(len(weak_found_names) - 8) + ' more' if len(weak_found_names) > 8 else ''}"
            f" (use --show-weak to display)[/yellow dim]"
        )
    if error_names:
        console.print(f"[dim red]Errors ({len(error_names)}): {', '.join(error_names[:5])}[/dim red]")


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
