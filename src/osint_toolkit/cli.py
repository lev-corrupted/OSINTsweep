"""osint — the CLI entrypoint."""

from __future__ import annotations

import asyncio
import os
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from osint_toolkit.core import audit
from osint_toolkit.core.cache import Cache
from osint_toolkit.core.calibration import CalibrationStore, calibrate_modules
from osint_toolkit.core.correlator import derive_targets
from osint_toolkit.core.dispatcher import Dispatcher
from osint_toolkit.core.models import Report, Target, TargetKind
from osint_toolkit.modules.domain import all_domain_modules
from osint_toolkit.modules.email import all_email_modules
from osint_toolkit.modules.email.hibp import HibpBreaches
from osint_toolkit.modules.name import all_name_modules
from osint_toolkit.modules.username import all_username_modules
from osint_toolkit.output import render_csv, render_json, render_markdown, render_table, write_to

app = typer.Typer(
    name="osint",
    help="Best-in-class OSINT toolkit. Pick a mode, hand it a target, get a Report.",
    no_args_is_help=True,
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


async def _run(target: Target, mode: str, strict: bool = False) -> Report:
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
    dispatcher = Dispatcher(
        modules=modules,
        mode=mode,
        cache=cache,
        global_timeout_s=float(os.environ.get("OSINT_GLOBAL_TIMEOUT_S", "10")),
        per_host_concurrency=int(os.environ.get("OSINT_PER_HOST_CONCURRENCY", "4")),
        calibration=calibration,
        strict=strict,
    )
    return await dispatcher.run(target)


def _emit(report: Report, output: Output, out_file: Path | None) -> None:
    if output == Output.table:
        render_table(report, console)
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
    if mode == "pentest":
        path = audit.write(report)
        console.print(f"[dim]audit log → {path}[/dim]")


async def _run_with_correlation(target: Target, mode: str, auto_correlate: bool, strict: bool) -> list[Report]:
    primary = await _run(target, mode, strict=strict)
    reports = [primary]
    if not auto_correlate:
        return reports
    for derived in derive_targets(primary):
        if derived.kind != target.kind:
            console.print(f"[dim]↳ correlated: {derived.kind.value} = {derived.value}[/dim]")
            sub = await _run(derived, mode, strict=strict)
            reports.append(sub)
    return reports


def _common(
    target: Target,
    mode: Mode,
    output: Output,
    out_file: Path | None,
    auto_correlate: bool,
    strict: bool = False,
) -> None:
    _confirm_or_exit(target, mode.value)
    reports = asyncio.run(_run_with_correlation(target, mode.value, auto_correlate, strict))
    for r in reports:
        _emit(r, output, out_file)
        _maybe_audit(r, mode.value)


@app.command()
def email(
    target: Annotated[str, typer.Argument(help="email address to look up")],
    mode: Annotated[Mode, typer.Option("--mode", "-m")] = Mode.prospect,
    output: Annotated[Output, typer.Option("--output", "-o")] = Output.table,
    out_file: Annotated[Path | None, typer.Option("--out")] = None,
    auto_correlate: Annotated[
        bool, typer.Option("--auto-correlate/--no-auto-correlate", help="follow leads from Gravatar etc.")
    ] = False,
) -> None:
    """Lookup an email — registered sites, gravatar, MX records, (selfcheck) breach exposure."""
    t = Target(kind=TargetKind.EMAIL, value=target)
    _common(t, mode, output, out_file, auto_correlate)


@app.command()
def username(
    target: Annotated[str, typer.Argument(help="username to enumerate across platforms")],
    mode: Annotated[Mode, typer.Option("--mode", "-m")] = Mode.prospect,
    output: Annotated[Output, typer.Option("--output", "-o")] = Output.table,
    out_file: Annotated[Path | None, typer.Option("--out")] = None,
    auto_correlate: Annotated[bool, typer.Option("--auto-correlate/--no-auto-correlate")] = False,
    strict: Annotated[bool, typer.Option("--strict", help="hide sources known to false-positive")] = False,
) -> None:
    """Sherlock-style enumeration across 80+ platforms."""
    t = Target(kind=TargetKind.USERNAME, value=target)
    _common(t, mode, output, out_file, auto_correlate, strict=strict)


@app.command()
def calibrate(
    refresh: Annotated[bool, typer.Option("--refresh", "-r", help="re-run even if calibration is fresh")] = False,
) -> None:
    """Calibrate every username source against an impossible handle to detect false-positives.

    Stored at ~/.osint-toolkit/calibration.json. Override path via OSINT_CALIBRATION_PATH.
    """
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
    from rich.table import Table

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
) -> None:
    """Look up a real name across public profile sources (GitHub, ...)."""
    t = Target(kind=TargetKind.NAME, value=target)
    _common(t, mode, output, out_file, auto_correlate)


@app.command()
def domain(
    target: Annotated[str, typer.Argument(help="domain to inspect, e.g. example.com")],
    mode: Annotated[Mode, typer.Option("--mode", "-m")] = Mode.prospect,
    output: Annotated[Output, typer.Option("--output", "-o")] = Output.table,
    out_file: Annotated[Path | None, typer.Option("--out")] = None,
) -> None:
    """Domain recon: DNS records (A/AAAA/MX/TXT/NS/SOA/CNAME/CAA) + RDAP/WHOIS."""
    t = Target(kind=TargetKind.DOMAIN, value=target)
    _common(t, mode, output, out_file, auto_correlate=False)


@app.command("list-sources")
def list_sources() -> None:
    """List all configured sources by category, mode, and host."""
    from rich.table import Table

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


if __name__ == "__main__":
    app()
