"""osint — the CLI entrypoint with interactive mode, ASCII banner, and live scan progress."""

from __future__ import annotations

import asyncio
import os
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from osint_toolkit.core import audit
from osint_toolkit.core.cache import Cache
from osint_toolkit.core.scan_log import write_scan_log
from osint_toolkit.core.calibration import CalibrationStore, calibrate_modules
from osint_toolkit.core.correlator import derive_targets
from osint_toolkit.core.dispatcher import Dispatcher
from osint_toolkit.core.models import Finding, Report, Status, Target, TargetKind
from osint_toolkit.core.proxy import ProxyManager
from osint_toolkit.modules.domain import all_domain_modules
from osint_toolkit.modules.email import all_email_modules
from osint_toolkit.modules.email.hibp import HibpBreaches
from osint_toolkit.modules.name import all_name_modules
from osint_toolkit.modules.username import all_username_modules
from osint_toolkit.output import render_csv, render_json, render_markdown, render_table, write_to
from osint_toolkit.output.renderers import _format_finding_detail
from osint_toolkit.output.banner import print_banner

app = typer.Typer(
    name="osint",
    help="Best-in-class OSINT toolkit. Pick a mode, hand it a target, get a Report.",
    no_args_is_help=False,
    invoke_without_command=True,
    rich_markup_mode="rich",
)

console = Console()


class Mode(StrEnum):
    prospect = "prospect"
    selfcheck = "selfcheck"
    pentest = "pentest"


class Output(StrEnum):
    table = "table"
    json = "json"
    csv = "csv"
    md = "md"


def _modules_for(kind: TargetKind, mode: str) -> list:
    if kind == TargetKind.EMAIL:
        mods = list(all_email_modules())
        if mode == "selfcheck":
            mods.append(HibpBreaches())
        return mods
    if kind == TargetKind.USERNAME:
        return list(all_username_modules())
    if kind == TargetKind.NAME:
        return list(all_name_modules())
    if kind == TargetKind.DOMAIN:
        return list(all_domain_modules())
    return []


def _resolve_owned(email: str) -> bool:
    p = Path.home() / ".osint-toolkit" / "owned_emails.txt"
    if not p.exists():
        return False
    return any(line.strip().lower() == email.lower() for line in p.read_text().splitlines())


async def _run(target: Target, mode: str, strict: bool = False, proxy_manager: ProxyManager | None = None) -> Report:
    cache = Cache(
        path=Path(os.environ.get("OSINT_CACHE_PATH", "osint_cache.db")),
        ttl_hours=int(os.environ.get("OSINT_CACHE_TTL_HOURS", "24")),
    )
    await cache.init()
    modules = _modules_for(target.kind, mode)
    calibration = CalibrationStore()
    if not calibration.exists() and target.kind == TargetKind.USERNAME:
        console.print(
            "[yellow]⚠ no calibration data found.[/yellow] Run `osint calibrate` once "
            "to fingerprint which sources false-positive. Continuing without confidence demotion."
        )

    completed = []
    total_count = len([m for m in modules if mode in m.modes_allowed and m.category == target.kind.value])

    progress = Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[dim]{task.fields[status]}[/dim]"),
        TimeElapsedColumn(),
        expand=True,
    )
    task_id = progress.add_task(
        f"Scanning {target.kind.value}: {target.value}",
        total=total_count,
        status="starting...",
    )

    results_table = Table(show_header=True, header_style="bold", expand=True, title="[bold]Live Results")
    results_table.add_column("Source", style="cyan", no_wrap=True)
    results_table.add_column("Status", no_wrap=True)
    results_table.add_column("Detail", overflow="fold")

    def layout():
        grid = Table.grid(padding=1)
        grid.add_row(Panel(progress, title="[bold cyan]Progress", border_style="cyan", padding=(0, 1)))
        if completed:
            grid.add_row(Panel(results_table, title="[bold green]Findings", border_style="green", padding=(0, 1)))
        return grid

    def on_progress(source_name: str, finding: Finding) -> None:
        completed.append(finding)
        progress.update(task_id, advance=1, status=f"checked {source_name}")
        if finding.status == Status.FOUND:
            detail = _format_finding_detail(finding)
            results_table.add_row(source_name, "[bold green]FOUND[/bold green]", detail)
        live.update(layout())

    dispatcher = Dispatcher(
        modules=modules,
        mode=mode,
        cache=cache,
        global_timeout_s=float(os.environ.get("OSINT_GLOBAL_TIMEOUT_S", "20")),
        per_host_concurrency=int(os.environ.get("OSINT_PER_HOST_CONCURRENCY", "4")),
        calibration=calibration,
        strict=strict,
        on_progress=on_progress,
        proxy_manager=proxy_manager,
    )

    live = Live(layout(), refresh_per_second=8, console=console)
    with live:
        report = await dispatcher.run(target)
        progress.update(task_id, completed=total_count, status="[bold green]done[/bold green]")
        live.update(layout())

    return report


def _emit(report: Report, output: Output, out_file: Path | None, show_weak: bool = False) -> None:
    if output == Output.table:
        render_table(report, console, show_weak=show_weak)
        return
    rendered = (
        render_json(report)
        if output == Output.json
        else render_csv(report)
        if output == Output.csv
        else render_markdown(report)
    )
    if out_file:
        write_to(out_file, rendered)
        console.print(f"[green]✓[/green] wrote {output.value} → {out_file}")
    else:
        console.print_json(rendered) if output == Output.json else console.print(rendered)


def _confirm_or_exit(target: Target, mode: str) -> None:
    if mode != "selfcheck" or target.kind != TargetKind.EMAIL:
        return
    if _resolve_owned(target.value):
        return
    confirm = typer.confirm(
        f"\n[!] {target.value} is not in ~/.osint-toolkit/owned_emails.txt.\n"
        f"    Selfcheck mode runs breach + registration-discovery against this email.\n"
        f"    Confirm this is YOUR email or one you have authorization to audit?",
        default=False,
    )
    if not confirm:
        console.print("[red]Aborted.[/red]")
        raise typer.Exit(code=1)


def _maybe_audit(report: Report, mode: str) -> None:
    write_scan_log(report)
    if mode == "pentest":
        path = audit.write(report)
        console.print(f"[dim]audit log → {path}[/dim]")


async def _run_with_correlation(
    target: Target, mode: str, auto_correlate: bool, strict: bool, proxy_manager: ProxyManager | None = None,
) -> list[Report]:
    primary = await _run(target, mode, strict=strict, proxy_manager=proxy_manager)
    reports = [primary]
    if not auto_correlate:
        return reports
    for derived in derive_targets(primary):
        if derived.kind != target.kind:
            console.print(f"\n[bold cyan]↳ Auto-correlate:[/bold cyan] {derived.kind.value} = [bold]{derived.value}[/bold]")
            sub = await _run(derived, mode, strict=strict, proxy_manager=proxy_manager)
            reports.append(sub)
    return reports


def _build_proxy_manager(
    proxy_file: Path | None = None, proxy_list: list[str] | None = None,
) -> ProxyManager | None:
    pm = ProxyManager(proxy_urls=proxy_list or [], proxy_file=proxy_file)
    if not pm.has_proxies:
        return None
    console.print(f"[bold cyan]Proxy rotation:[/bold cyan] {pm.count} proxies loaded")
    alive = asyncio.run(pm.health_check(
        on_result=lambda entry, ok, lat: console.print(
            f"  {'[green]OK[/green]' if ok else '[red]DEAD[/red]'} {entry.label}"
            + (f" ({lat:.0f}ms)" if ok else "")
        )
    ))
    console.print(f"  [bold]{alive}/{pm.count} alive[/bold]\n")
    if alive == 0:
        console.print("[yellow]All proxies failed health check — falling back to direct connection[/yellow]\n")
        return None
    return pm


def _common(
    target: Target,
    mode: Mode,
    output: Output,
    out_file: Path | None,
    auto_correlate: bool,
    strict: bool = False,
    show_weak: bool = False,
    skip_banner: bool = False,
    proxy_file: Path | None = None,
    proxy_list: list[str] | None = None,
) -> None:
    _confirm_or_exit(target, mode.value)
    if not skip_banner:
        print_banner(console)
    proxy_manager = _build_proxy_manager(proxy_file, proxy_list)
    reports = asyncio.run(_run_with_correlation(target, mode.value, auto_correlate, strict, proxy_manager=proxy_manager))
    console.print()
    for r in reports:
        _emit(r, output, out_file, show_weak=show_weak)
        _maybe_audit(r, mode.value)


@app.callback()
def main(ctx: typer.Context) -> None:
    """OSINT Toolkit — async recon across 70+ sources."""
    if ctx.invoked_subcommand is not None:
        return
    _interactive_menu()


def _interactive_menu() -> None:
    """Launch the interactive menu when no subcommand is given."""
    print_banner(console)

    try:
        from InquirerPy import inquirer
    except ImportError:
        console.print("[red]InquirerPy not installed.[/red] Run: uv add InquirerPy")
        raise typer.Exit(code=1)  # noqa: B904

    action = inquirer.select(
        message="What do you want to do?",
        choices=[
            {"name": "📧  Email Lookup", "value": "email"},
            {"name": "👤  Username Scan", "value": "username"},
            {"name": "🔤  Name Search", "value": "name"},
            {"name": "🌐  Domain Recon", "value": "domain"},
            {"name": "🔧  Calibrate Sources", "value": "calibrate"},
            {"name": "📋  List All Sources", "value": "list-sources"},
            {"name": "📊  View Scan Logs", "value": "logs"},
            {"name": "❌  Exit", "value": "exit"},
        ],
        default="email",
    ).execute()

    if action == "exit":
        console.print("[dim]Bye.[/dim]")
        raise typer.Exit()

    if action == "calibrate":
        calibrate(refresh=False)
        return

    if action == "list-sources":
        list_sources()
        return

    if action == "logs":
        view_logs()
        return

    target_value = inquirer.text(
        message=f"Enter {action} to look up:",
        validate=lambda val: len(val.strip()) >= 2,
        invalid_message="Target must be at least 2 characters.",
    ).execute()

    mode_choice = inquirer.select(
        message="Select mode:",
        choices=[
            {"name": "🔍  Prospect — safe, public-only recon", "value": "prospect"},
            {"name": "🔒  Selfcheck — full audit including breaches (your own accounts)", "value": "selfcheck"},
            {"name": "🔴  Pentest — everything + audit log (authorized testing)", "value": "pentest"},
        ],
        default="prospect",
    ).execute()

    output_choice = inquirer.select(
        message="Output format:",
        choices=[
            {"name": "📊  Rich Table (default)", "value": "table"},
            {"name": "📄  JSON", "value": "json"},
            {"name": "📑  CSV", "value": "csv"},
            {"name": "📝  Markdown", "value": "md"},
        ],
        default="table",
    ).execute()

    auto_correlate = True
    if action == "email":
        auto_correlate = inquirer.confirm(
            message="Auto-correlate? (derive username from email and scan platforms too)",
            default=True,
        ).execute()

    kind_map = {
        "email": TargetKind.EMAIL,
        "username": TargetKind.USERNAME,
        "name": TargetKind.NAME,
        "domain": TargetKind.DOMAIN,
    }

    try:
        t = Target(kind=kind_map[action], value=target_value.strip())
    except Exception as e:
        console.print(f"[red]Invalid target:[/red] {e}")
        raise typer.Exit(code=1)  # noqa: B904

    _common(
        t,
        Mode(mode_choice),
        Output(output_choice),
        out_file=None,
        auto_correlate=auto_correlate,
        skip_banner=True,
    )


@app.command()
def email(
    target: Annotated[str, typer.Argument(help="email address to look up")],
    mode: Annotated[Mode, typer.Option("--mode", "-m")] = Mode.prospect,
    output: Annotated[Output, typer.Option("--output", "-o")] = Output.table,
    out_file: Annotated[Path | None, typer.Option("--out")] = None,
    auto_correlate: Annotated[
        bool, typer.Option("--auto-correlate/--no-auto-correlate", help="derive username from email and scan platforms")
    ] = True,
    show_weak: Annotated[bool, typer.Option("--show-weak", help="show calibration-flagged weak finds in table")] = False,
    proxy_file: Annotated[Path | None, typer.Option("--proxy-file", help="file with proxy URLs, one per line")] = None,
    proxy: Annotated[list[str] | None, typer.Option("--proxy", "-p", help="proxy URL (repeatable)")] = None,
) -> None:
    """Lookup an email — registered sites, gravatar, MX records, reputation, breach exposure."""
    t = Target(kind=TargetKind.EMAIL, value=target)
    _common(t, mode, output, out_file, auto_correlate, show_weak=show_weak, proxy_file=proxy_file, proxy_list=proxy)


@app.command()
def username(
    target: Annotated[str, typer.Argument(help="username to enumerate across platforms")],
    mode: Annotated[Mode, typer.Option("--mode", "-m")] = Mode.prospect,
    output: Annotated[Output, typer.Option("--output", "-o")] = Output.table,
    out_file: Annotated[Path | None, typer.Option("--out")] = None,
    auto_correlate: Annotated[bool, typer.Option("--auto-correlate/--no-auto-correlate")] = False,
    strict: Annotated[bool, typer.Option("--strict", help="hide sources known to false-positive")] = False,
    show_weak: Annotated[bool, typer.Option("--show-weak", help="show calibration-flagged weak finds in table")] = False,
    proxy_file: Annotated[Path | None, typer.Option("--proxy-file", help="file with proxy URLs, one per line")] = None,
    proxy: Annotated[list[str] | None, typer.Option("--proxy", "-p", help="proxy URL (repeatable)")] = None,
) -> None:
    """Sherlock-style enumeration across 100+ platforms."""
    t = Target(kind=TargetKind.USERNAME, value=target)
    _common(t, mode, output, out_file, auto_correlate, strict=strict, show_weak=show_weak, proxy_file=proxy_file, proxy_list=proxy)


@app.command()
def calibrate(
    refresh: Annotated[bool, typer.Option("--refresh", "-r", help="re-run even if calibration is fresh")] = False,
) -> None:
    """Calibrate every username source against an impossible handle to detect false-positives."""
    store = CalibrationStore()
    if store.exists() and not refresh and store.age_days() < 30:
        console.print(
            f"[dim]calibration already exists at {store.path} "
            f"(age: {store.age_days():.1f}d). Use --refresh to re-run.[/dim]"
        )
        _print_calibration_summary(store)
        return

    modules = list(all_username_modules())
    console.print(f"[bold]calibrating {len(modules)} sources against impossible handle...[/bold]")
    entries = asyncio.run(calibrate_modules(modules))
    store.save(entries)
    console.print(f"[green]✓[/green] saved → {store.path}")
    _print_calibration_summary(store)


def _print_calibration_summary(store: CalibrationStore) -> None:
    entries = store.all_entries()
    unreliable = sorted([e for e in entries.values() if not e.reliable], key=lambda e: e.source)
    reliable = [e for e in entries.values() if e.reliable]
    console.print(
        f"\n[bold]calibration summary:[/bold] "
        f"[green]{len(reliable)} reliable[/green] · "
        f"[red]{len(unreliable)} false-positive[/red] / {len(entries)} total\n"
    )
    if unreliable:
        t = Table(title="Unreliable sources (false-positive on impossible handles)", header_style="red")
        t.add_column("Source", style="cyan")
        t.add_column("Status returned", style="red")
        t.add_column("Latency (ms)", justify="right")
        for e in unreliable:
            t.add_row(e.source, e.impossible_status, str(e.impossible_elapsed_ms))
        console.print(t)
        console.print(
            "[dim]In default mode, findings from these sources will be marked [low confidence] "
            "with a calibration_warning. Use --strict to filter them out entirely.[/dim]"
        )


@app.command()
def name(
    target: Annotated[str, typer.Argument(help='real name, e.g. "Linus Torvalds"')],
    mode: Annotated[Mode, typer.Option("--mode", "-m")] = Mode.prospect,
    output: Annotated[Output, typer.Option("--output", "-o")] = Output.table,
    out_file: Annotated[Path | None, typer.Option("--out")] = None,
    auto_correlate: Annotated[bool, typer.Option("--auto-correlate/--no-auto-correlate")] = False,
    hint: Annotated[
        str, typer.Option("--hint", help='narrow search, e.g. --hint "bangkok dentist"')
    ] = "",
    proxy_file: Annotated[Path | None, typer.Option("--proxy-file", help="file with proxy URLs, one per line")] = None,
    proxy: Annotated[list[str] | None, typer.Option("--proxy", "-p", help="proxy URL (repeatable)")] = None,
) -> None:
    """Look up a real name: Wikipedia + Wikidata + ORCID + CrossRef + OpenSanctions + GitHub."""
    if hint:
        os.environ["OSINT_HINT"] = hint
    t = Target(kind=TargetKind.NAME, value=target)
    _common(t, mode, output, out_file, auto_correlate, proxy_file=proxy_file, proxy_list=proxy)


@app.command()
def domain(
    target: Annotated[str, typer.Argument(help="domain to inspect, e.g. example.com")],
    mode: Annotated[Mode, typer.Option("--mode", "-m")] = Mode.prospect,
    output: Annotated[Output, typer.Option("--output", "-o")] = Output.table,
    out_file: Annotated[Path | None, typer.Option("--out")] = None,
    proxy_file: Annotated[Path | None, typer.Option("--proxy-file", help="file with proxy URLs, one per line")] = None,
    proxy: Annotated[list[str] | None, typer.Option("--proxy", "-p", help="proxy URL (repeatable)")] = None,
) -> None:
    """Domain recon: DNS records + RDAP/WHOIS."""
    t = Target(kind=TargetKind.DOMAIN, value=target)
    _common(t, mode, output, out_file, auto_correlate=False, proxy_file=proxy_file, proxy_list=proxy)


@app.command("proxy-check")
def proxy_check(
    proxy_file: Annotated[Path | None, typer.Option("--proxy-file", help="file with proxy URLs, one per line")] = None,
    proxy: Annotated[list[str] | None, typer.Option("--proxy", "-p", help="proxy URL (repeatable)")] = None,
) -> None:
    """Health-check proxies — test connectivity, measure latency, report alive/dead status."""
    pm = ProxyManager(proxy_urls=proxy or [], proxy_file=proxy_file)
    if not pm.has_proxies:
        console.print("[red]No proxies provided.[/red] Use --proxy-file or --proxy or set OSINT_PROXIES env var.")
        raise typer.Exit(code=1)

    console.print(f"[bold]Testing {pm.count} proxies...[/bold]\n")

    t = Table(title="Proxy Health Check", header_style="bold")
    t.add_column("Proxy", style="cyan")
    t.add_column("Status", no_wrap=True)
    t.add_column("Latency", justify="right")
    rows: list[tuple[str, str, str]] = []

    def on_result(entry, ok, latency):
        if ok:
            rows.append((entry.label, "[bold green]ALIVE[/bold green]", f"{latency:.0f}ms"))
        else:
            rows.append((entry.label, "[bold red]DEAD[/bold red]", "-"))

    alive = asyncio.run(pm.health_check(on_result=on_result))
    for row in rows:
        t.add_row(*row)
    console.print(t)
    console.print(f"\n[bold]{alive}/{pm.count} proxies alive[/bold]")


@app.command("list-sources")
def list_sources() -> None:
    """List all configured sources by category, mode, and host."""
    t = Table(title="osint-toolkit sources", header_style="bold")
    t.add_column("Category", style="cyan")
    t.add_column("Name", style="bold")
    t.add_column("Host")
    t.add_column("Modes", style="magenta")
    t.add_column("Key?", justify="center")
    for m in [
        *all_email_modules(),
        HibpBreaches(),
        *all_username_modules(),
        *all_name_modules(),
        *all_domain_modules(),
    ]:
        t.add_row(
            m.category,
            m.name,
            m.host,
            ",".join(sorted(m.modes_allowed)),
            "✓" if m.requires_api_key else "",
        )
    console.print(t)
    console.print(f"\n[bold]Total:[/bold] {t.row_count} sources")


@app.command("logs")
def view_logs(
    last: Annotated[int, typer.Option("--last", "-n", help="show last N scan entries")] = 20,
    errors_only: Annotated[bool, typer.Option("--errors", "-e", help="only show scans with errors")] = False,
) -> None:
    """Review scan logs — see past results, errors, and patterns for improving sources."""
    import json as _json

    log_dir = Path(__file__).resolve().parents[2] / "logs"
    if not log_dir.exists():
        console.print("[dim]No scan logs yet.[/dim]")
        return

    log_files = sorted(log_dir.glob("scans_*.jsonl"))
    if not log_files:
        console.print("[dim]No scan logs yet.[/dim]")
        return

    entries: list[dict] = []
    for lf in log_files:
        for line in lf.read_text().splitlines():
            if line.strip():
                try:
                    entries.append(_json.loads(line))
                except _json.JSONDecodeError:
                    pass

    if errors_only:
        entries = [e for e in entries if e.get("errors", 0) > 0]

    entries = entries[-last:]

    if not entries:
        console.print("[dim]No matching log entries.[/dim]")
        return

    t = Table(title=f"[bold]Scan History (last {len(entries)})", header_style="bold", expand=True)
    t.add_column("Time", style="dim", no_wrap=True)
    t.add_column("Type", style="cyan", no_wrap=True)
    t.add_column("Target", overflow="fold")
    t.add_column("Mode", style="magenta", no_wrap=True)
    t.add_column("Found", style="green", justify="right")
    t.add_column("Errors", style="red", justify="right")
    t.add_column("Error Sources", overflow="fold")

    for e in entries:
        ts = e.get("ts", "")[:19].replace("T", " ")
        err_sources = ", ".join(d["source"] for d in e.get("error_details", []))
        t.add_row(
            ts,
            e.get("target_kind", "?"),
            e.get("target_value", "?"),
            e.get("mode", "?"),
            str(e.get("found", 0)),
            str(e.get("errors", 0)),
            err_sources or "[dim]-[/dim]",
        )

    console.print(t)

    error_counts: dict[str, int] = {}
    error_msgs: dict[str, str] = {}
    for e in entries:
        for d in e.get("error_details", []):
            src = d["source"]
            error_counts[src] = error_counts.get(src, 0) + 1
            error_msgs[src] = d.get("error", "")

    if error_counts:
        console.print()
        et = Table(title="[bold red]Recurring Errors (sources to investigate)", header_style="red")
        et.add_column("Source", style="cyan")
        et.add_column("Count", justify="right", style="red bold")
        et.add_column("Last Error", overflow="fold")
        for src, count in sorted(error_counts.items(), key=lambda x: -x[1]):
            et.add_row(src, str(count), error_msgs.get(src, ""))
        console.print(et)

    console.print(f"\n[dim]Log files: {', '.join(str(f) for f in log_files)}[/dim]")


if __name__ == "__main__":
    app()
