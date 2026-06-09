"""osint — the CLI entrypoint."""

from __future__ import annotations

import asyncio
import os
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from osint_toolkit.core.cache import Cache
from osint_toolkit.core.dispatcher import Dispatcher
from osint_toolkit.core.models import Report, Target, TargetKind
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
    return []


def _resolve_owned(email: str) -> bool:
    """For selfcheck mode: confirm target is in ~/.osint-toolkit/owned_emails.txt."""
    p = Path.home() / ".osint-toolkit" / "owned_emails.txt"
    if not p.exists():
        return False
    return any(line.strip().lower() == email.lower() for line in p.read_text().splitlines())


async def _run(target: Target, mode: str) -> Report:
    cache = Cache(
        path=Path(os.environ.get("OSINT_CACHE_PATH", "osint_cache.db")),
        ttl_hours=int(os.environ.get("OSINT_CACHE_TTL_HOURS", "24")),
    )
    await cache.init()
    modules = _modules_for(target.kind, mode)
    dispatcher = Dispatcher(
        modules=modules,
        mode=mode,
        cache=cache,
        global_timeout_s=float(os.environ.get("OSINT_GLOBAL_TIMEOUT_S", "10")),
        per_host_concurrency=int(os.environ.get("OSINT_PER_HOST_CONCURRENCY", "4")),
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
    """Selfcheck-mode confirmation for non-owned emails."""
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


@app.command()
def email(
    target: Annotated[str, typer.Argument(help="email address to look up")],
    mode: Annotated[
        Mode, typer.Option("--mode", "-m", help="prospect | selfcheck | pentest")
    ] = Mode.prospect,
    output: Annotated[Output, typer.Option("--output", "-o", help="output format")] = Output.table,
    out_file: Annotated[
        Path | None, typer.Option("--out", help="write to file instead of stdout")
    ] = None,
) -> None:
    """Lookup an email — registered sites, gravatar, MX records, (selfcheck) breach exposure."""
    t = Target(kind=TargetKind.EMAIL, value=target)
    _confirm_or_exit(t, mode.value)
    report = asyncio.run(_run(t, mode.value))
    _emit(report, output, out_file)


@app.command()
def username(
    target: Annotated[str, typer.Argument(help="username to enumerate across platforms")],
    mode: Annotated[Mode, typer.Option("--mode", "-m")] = Mode.prospect,
    output: Annotated[Output, typer.Option("--output", "-o")] = Output.table,
    out_file: Annotated[Path | None, typer.Option("--out")] = None,
) -> None:
    """Sherlock-style enumeration across 30+ platforms."""
    t = Target(kind=TargetKind.USERNAME, value=target)
    report = asyncio.run(_run(t, mode.value))
    _emit(report, output, out_file)


@app.command()
def name(
    target: Annotated[str, typer.Argument(help='real name, e.g. "Linus Torvalds"')],
    mode: Annotated[Mode, typer.Option("--mode", "-m")] = Mode.prospect,
    output: Annotated[Output, typer.Option("--output", "-o")] = Output.table,
    out_file: Annotated[Path | None, typer.Option("--out")] = None,
) -> None:
    """Look up a real name across public profile sources (GitHub, ...)."""
    t = Target(kind=TargetKind.NAME, value=target)
    report = asyncio.run(_run(t, mode.value))
    _emit(report, output, out_file)


@app.command()
def list_sources() -> None:
    """List all configured sources by category, mode, and host."""
    from rich.table import Table

    t = Table(title="osint-toolkit sources", header_style="bold")
    t.add_column("Category", style="cyan")
    t.add_column("Name", style="bold")
    t.add_column("Host")
    t.add_column("Modes", style="magenta")
    t.add_column("Key?", justify="center")
    for m in [*all_email_modules(), HibpBreaches(), *all_username_modules(), *all_name_modules()]:
        t.add_row(
            m.category,
            m.name,
            m.host,
            ",".join(sorted(m.modes_allowed)),
            "✓" if m.requires_api_key else "",
        )
    console.print(t)


if __name__ == "__main__":
    app()
