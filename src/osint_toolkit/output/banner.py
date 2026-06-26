"""ASCII art banner with gradient coloring via Rich."""

from __future__ import annotations

import shutil

import pyfiglet
from rich.console import Console
from rich.text import Text


def print_banner(console: Console | None = None) -> None:
    console = console or Console()
    terminal_width = shutil.get_terminal_size((80, 20)).columns

    ascii_art = pyfiglet.figlet_format("OSINTsweep", font="ansi_shadow", width=terminal_width)
    lines = [line for line in ascii_art.splitlines() if line.strip()]

    if not lines:
        console.print("[bold cyan]OSINTsweep[/bold cyan]")
        return

    color_start = (0, 255, 200)
    color_end = (0, 100, 255)
    banner = Text()
    num_lines = len(lines)

    for i, line in enumerate(lines):
        ratio = i / max(num_lines - 1, 1)
        r = int(color_start[0] + (color_end[0] - color_start[0]) * ratio)
        g = int(color_start[1] + (color_end[1] - color_start[1]) * ratio)
        b = int(color_start[2] + (color_end[2] - color_start[2]) * ratio)
        color_hex = f"#{r:02x}{g:02x}{b:02x}"
        banner.append(line + "\n", style=f"bold {color_hex}")

    console.print(banner, end="")
    console.print(
        "  [bold cyan]OSINTsweep[/bold cyan] [dim]|[/dim] "
        "[yellow]v0.5.0[/yellow] [dim]|[/dim] "
        "[green]by Levtheswag[/green]"
    )
    console.print("  [dim]Async OSINT recon across 130+ sources — email, username, name, domain[/dim]")
    console.print()
