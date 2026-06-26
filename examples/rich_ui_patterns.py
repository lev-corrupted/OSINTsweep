#!/usr/bin/env python3
"""
Rich Library Advanced Examples — OSINT / Intelligence Gathering Tool Patterns
=============================================================================
Each section is a standalone, runnable snippet demonstrating a Rich feature
in the context of an OSINT tool that displays user profiles, breach data,
scan progress, linked accounts, etc.

Requirements:  pip install rich
Tested with:   Rich 13.x / 14.x  (Python 3.9+)
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1.  PANELS — borders, titles, nested content
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def demo_panels():
    """Display a user profile card using nested Panels."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich import box

    console = Console()

    # Inner panel: social links
    social_links = (
        ":globe_with_meridians: [link=https://github.com/jdoe]github.com/jdoe[/link]\n"
        ":bird: [link=https://twitter.com/jdoe]@jdoe[/link]\n"
        ":briefcase: [link=https://linkedin.com/in/jdoe]linkedin.com/in/jdoe[/link]"
    )
    social_panel = Panel(
        social_links,
        title="[bold cyan]Social Profiles",
        border_style="cyan",
        box=box.ROUNDED,
        expand=False,
    )

    # Outer panel: full profile card
    profile_text = (
        "[bold white]Name:[/]        John Doe\n"
        "[bold white]Email:[/]       johndoe@example.com\n"
        "[bold white]Phone:[/]       +1-555-0199\n"
        "[bold white]Location:[/]    San Francisco, CA\n"
        "[bold white]Risk Score:[/]  [bold red]HIGH (87/100)[/]\n"
    )

    # Combine text + nested panel into one renderable via Group
    from rich.console import Group
    body = Group(profile_text, social_panel)

    profile_card = Panel(
        body,
        title="[bold yellow]:mag: Target Profile",
        subtitle="[dim]Source: aggregated OSINT",
        subtitle_align="right",
        border_style="yellow",
        box=box.DOUBLE,
        padding=(1, 2),
    )

    console.print(profile_card)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2.  LAYOUT — columns, rows, full-screen dashboard
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def demo_layout():
    """Build a multi-pane OSINT dashboard layout."""
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    console = Console()

    layout = Layout()

    # Top banner + two bottom columns
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=2),
    )

    # Header
    layout["header"].update(
        Panel("[bold white on blue] OSINT Dashboard  ::  Target: johndoe@example.com ", style="on blue")
    )

    # Left pane — quick stats
    stats = Table(box=box.SIMPLE, show_header=False, expand=True)
    stats.add_column("Key", style="bold cyan")
    stats.add_column("Value")
    stats.add_row("Breaches", "[red]4 found")
    stats.add_row("Pastes", "[yellow]12 found")
    stats.add_row("Social", "[green]7 linked")
    stats.add_row("Domains", "2 owned")
    layout["left"].update(Panel(stats, title="Quick Stats", border_style="green"))

    # Right pane — recent breaches table
    breaches = Table(title="Recent Breaches", box=box.ROUNDED, expand=True)
    breaches.add_column("Date", style="cyan", no_wrap=True)
    breaches.add_column("Source", style="magenta")
    breaches.add_column("Data Exposed", style="red")
    breaches.add_row("2024-11-02", "ExampleDB", "email, password hash")
    breaches.add_row("2024-06-15", "LeakedForum", "email, IP address")
    breaches.add_row("2023-01-20", "SocialDump", "email, phone, DOB")
    layout["right"].update(Panel(breaches, title="Breach Intel", border_style="red"))

    console.print(layout)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3.  TREE — hierarchical linked-accounts view
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def demo_tree():
    """Render a linked-accounts tree for a target identity."""
    from rich.console import Console
    from rich.tree import Tree
    from rich.panel import Panel
    from rich.text import Text

    console = Console()

    tree = Tree(
        ":bust_in_silhouette: [bold yellow]johndoe@example.com",
        guide_style="bold bright_blue",
    )

    # -- Email cluster --
    emails = tree.add(":e-mail: [bold]Email Addresses", guide_style="cyan")
    emails.add("[green]johndoe@example.com[/]  [dim](primary)")
    emails.add("[green]j.doe@workmail.com[/]   [dim](corporate)")
    emails.add("[yellow]jd_throwaway@proton.me[/] [dim](disposable)")

    # -- Social accounts --
    social = tree.add(":globe_with_meridians: [bold]Social Accounts", guide_style="magenta")
    gh = social.add(":laptop: GitHub — [cyan]jdoe")
    gh.add("52 public repos")
    gh.add("Joined 2018")
    tw = social.add(":bird: Twitter — [cyan]@johndoe")
    tw.add("3.2k followers")
    li = social.add(":briefcase: LinkedIn — [cyan]John Doe")
    li.add("Software Engineer at Acme Corp")

    # -- Breach exposure --
    breaches = tree.add(":warning: [bold red]Breach Exposure", guide_style="red")
    b1 = breaches.add("[red]ExampleDB (2024)[/]")
    b1.add("Leaked: email, bcrypt hash")
    b2 = breaches.add("[red]SocialDump (2023)[/]")
    b2.add("Leaked: email, phone, DOB")

    # -- Domain ownership --
    domains = tree.add(":globe_showing_Americas: [bold]Domains Owned", guide_style="green")
    domains.add("johndoe.dev  [dim](Registrar: Namecheap, Exp: 2026)")
    domains.add("doe-family.org [dim](Registrar: GoDaddy, Exp: 2025)")

    console.print(Panel(tree, title="[bold]Linked Accounts Graph", border_style="bright_blue"))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 4.  LIVE DISPLAY — real-time updating dashboard
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def demo_live():
    """Simulate a live-updating OSINT scan results table."""
    import time
    import random
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    console = Console()

    sources = [
        ("HaveIBeenPwned", "breach"),
        ("Dehashed", "breach"),
        ("Hunter.io", "email"),
        ("Sherlock", "username"),
        ("Holehe", "email"),
        ("GitHub API", "code"),
        ("DNS Records", "domain"),
        ("Shodan", "infra"),
    ]

    results: list[dict] = []

    def build_table() -> Panel:
        table = Table(
            title="Scan Results",
            box=box.ROUNDED,
            expand=True,
            row_styles=["", "dim"],
        )
        table.add_column("Source", style="cyan", no_wrap=True)
        table.add_column("Type", style="magenta")
        table.add_column("Findings", justify="right", style="green")
        table.add_column("Status", justify="center")

        for r in results:
            status = "[bold green]DONE :heavy_check_mark:" if r["done"] else "[yellow]SCANNING :hourglass_flowing_sand:"
            table.add_row(r["source"], r["type"], str(r["findings"]), status)

        return Panel(
            table,
            title=f"[bold white]:satellite: Live OSINT Scan  ({len([r for r in results if r['done']])}/{len(sources)} complete)",
            border_style="bright_blue",
        )

    with Live(build_table(), refresh_per_second=4, console=console) as live:
        for source, stype in sources:
            results.append({"source": source, "type": stype, "findings": 0, "done": False})
            live.update(build_table())
            # Simulate scanning with incremental findings
            for _ in range(random.randint(3, 8)):
                time.sleep(0.2)
                results[-1]["findings"] += random.randint(0, 5)
                live.update(build_table())
            results[-1]["done"] = True
            live.update(build_table())

    console.print("[bold green]Scan complete!")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5.  PROGRESS BARS — multiple concurrent tasks with custom columns
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def demo_progress():
    """Show concurrent OSINT data-source scans with custom progress columns."""
    import time
    import random
    from rich.console import Console
    from rich.progress import (
        Progress,
        SpinnerColumn,
        BarColumn,
        TextColumn,
        TimeElapsedColumn,
        TimeRemainingColumn,
        MofNCompleteColumn,
        TaskProgressColumn,
    )
    from rich.table import Column
    from rich.panel import Panel

    console = Console()

    # Custom column layout:
    #   [spinner] [description ......] [bar] [M/N] [percentage] [elapsed] [ETA]
    progress = Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold blue]{task.description}", table_column=Column(ratio=1)),
        BarColumn(bar_width=None, table_column=Column(ratio=2)),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        expand=True,
    )

    scan_sources = {
        "HIBP Breaches":    150,
        "Dehashed Leaks":   300,
        "Sherlock Usernames": 80,
        "Hunter.io Emails": 200,
        "DNS Enumeration":  120,
        "Shodan Hosts":      60,
    }

    with progress:
        tasks = {}
        for name, total in scan_sources.items():
            tasks[name] = progress.add_task(name, total=total)

        # Simulate concurrent scanning: advance each source by a random amount
        while not progress.finished:
            for name in scan_sources:
                advance = random.uniform(0.5, 3.0)
                progress.update(tasks[name], advance=advance)
            time.sleep(0.03)

    console.print("[bold green]:heavy_check_mark: All sources scanned successfully.")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 6.  TABLES — nested data, styling, row styles, grid
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def demo_tables():
    """Display breach details with nested tables and rich styling."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box

    console = Console()

    # ── Main breach summary table ──
    main = Table(
        title=":warning: Breach Report for johndoe@example.com",
        box=box.DOUBLE_EDGE,
        show_lines=True,
        title_style="bold red",
        border_style="red",
        row_styles=["", "on grey11"],   # zebra stripes
        expand=True,
    )
    main.add_column("Breach", style="bold magenta", no_wrap=True)
    main.add_column("Date", style="cyan", justify="center")
    main.add_column("Severity", justify="center")
    main.add_column("Exposed Fields", ratio=2)

    # Row 1: simple
    main.add_row(
        "ExampleDB",
        "2024-11-02",
        "[bold red]CRITICAL",
        "email, password (SHA-1), security Q&A",
    )

    # Row 2: with a nested table showing leaked credential details
    cred_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
    cred_table.add_column("Field", style="bold")
    cred_table.add_column("Value")
    cred_table.add_row("Hash", "[red]5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
    cred_table.add_row("Type", "SHA-1 (unsalted)")
    cred_table.add_row("Cracked?", "[bold red]YES — 'password123'")

    main.add_row(
        "LeakedForum",
        "2024-06-15",
        "[bold yellow]HIGH",
        cred_table,   # <-- nested renderable in a cell
    )

    # Row 3
    main.add_row(
        "SocialDump",
        "2023-01-20",
        "[yellow]MEDIUM",
        "email, IP (192.168.x.x), user-agent string",
    )

    console.print(main)
    console.print()

    # ── Grid layout for key-value metadata ──
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(justify="right", style="bold cyan")
    grid.add_column()
    grid.add_row("Total Breaches", "[red]3")
    grid.add_row("Unique Passwords Exposed", "[red]2")
    grid.add_row("Earliest Breach", "2023-01-20")
    grid.add_row("Recommended Action", "[bold yellow]Force password reset + enable MFA")

    console.print(Panel(grid, title="Summary", border_style="cyan", expand=False))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 7.  CONSOLE MARKUP — colors, bold, italic, emoji, links
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def demo_markup():
    """Demonstrate Rich console markup for styled OSINT output."""
    from rich.console import Console
    from rich.markup import escape
    from rich.text import Text

    console = Console()

    # Basic styles
    console.print("[bold]Bold text[/bold], [italic]italic[/italic], [underline]underline[/underline]")
    console.print("[bold red]CRITICAL[/] | [bold yellow]WARNING[/] | [bold green]OK[/] | [dim]INFO[/dim]")
    console.print()

    # Colors — named, hex, rgb
    console.print("[red]Named red[/], [#ff8800]Hex orange[/], [rgb(100,200,255)]RGB sky blue[/]")
    console.print("[bold white on red] ALERT [/] [bold white on green] SAFE [/]")   # background colors
    console.print()

    # Emoji codes
    console.print(":mag: Searching...  :white_check_mark: Found  :warning: Caution  :x: Failed")
    console.print(":bust_in_silhouette: User   :e-mail: Email   :locked: Encrypted   :unlocked: Exposed")
    console.print()

    # Hyperlinks (clickable in supported terminals)
    console.print("Profile: [link=https://github.com/jdoe]:globe_with_meridians: github.com/jdoe[/link]")
    console.print()

    # Overlapping / nesting styles
    console.print("[bold]Breach found in [red]ExampleDB[/red] — [yellow]4 fields[/yellow] exposed[/bold]")
    console.print()

    # Safe escaping of user-supplied data (prevents markup injection)
    untrusted_username = "[blink]hacker[/blink]"
    console.print(f"Scanned user: {escape(untrusted_username)}")   # renders literally


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 8.  RULE / DIVIDER LINES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def demo_rules():
    """Show Rule dividers to separate sections of OSINT output."""
    from rich.console import Console
    from rich.rule import Rule

    console = Console()

    console.print(Rule("[bold cyan]OSINT Scan Report"))
    console.print("Target: johndoe@example.com")
    console.print()

    console.print(Rule("[bold red]:warning: Breach Data", style="red"))
    console.print("[red]4 breaches found across 3 data sources.[/]")
    console.print()

    console.print(Rule("[bold green]:heavy_check_mark: Social Profiles", style="green"))
    console.print("[green]7 linked accounts identified.[/]")
    console.print()

    # Minimal / aligned variants
    console.print(Rule(style="dim"))                           # plain dim line
    console.print(Rule("Left-aligned", align="left"))          # left
    console.print(Rule("Right-aligned", align="right"))        # right
    console.print(Rule(characters="=", style="bright_yellow")) # custom char


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 9.  SYNTAX HIGHLIGHTING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def demo_syntax():
    """Render syntax-highlighted code found during OSINT reconnaissance."""
    from rich.console import Console
    from rich.syntax import Syntax
    from rich.panel import Panel

    console = Console()

    # Example: a leaked API config found in a public repo
    leaked_code = '''\
# config.py  (found in public GitHub repo jdoe/my-app)
DATABASE_URL = "postgresql://admin:s3cretP@ss@db.example.com:5432/prod"
API_KEY      = "sk-live-4e2b8f...redacted"
DEBUG        = True   # left on in production!

def connect():
    """Establish DB connection with leaked credentials."""
    import psycopg2
    return psycopg2.connect(DATABASE_URL)
'''

    syntax = Syntax(
        leaked_code,
        "python",
        theme="monokai",
        line_numbers=True,
        highlight_lines={2, 3},   # draw attention to secrets
        word_wrap=True,
    )

    console.print(Panel(
        syntax,
        title="[bold red]:warning: Leaked Source Code",
        subtitle="[dim]repo: github.com/jdoe/my-app  |  commit: a3f8c1d",
        border_style="red",
    ))

    # JSON data (e.g., API response from a breach source)
    json_data = '''\
{
  "email": "johndoe@example.com",
  "breaches": [
    {"name": "ExampleDB", "date": "2024-11-02", "severity": "critical"},
    {"name": "LeakedForum", "date": "2024-06-15", "severity": "high"}
  ],
  "paste_count": 12
}
'''
    json_syntax = Syntax(json_data, "json", theme="ansi_dark", line_numbers=True)
    console.print(Panel(json_syntax, title="[bold cyan]API Response", border_style="cyan"))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 10.  MARKDOWN RENDERING
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def demo_markdown():
    """Render a Markdown-formatted OSINT report in the terminal."""
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel

    console = Console()

    report = """\
# OSINT Report: johndoe@example.com

## Summary

Target was found in **4 data breaches** and **12 paste sites**.
Risk level: **HIGH**

## Breaches

| Source      | Date       | Severity |
|-------------|------------|----------|
| ExampleDB   | 2024-11-02 | Critical |
| LeakedForum | 2024-06-15 | High     |
| SocialDump  | 2023-01-20 | Medium   |

## Linked Accounts

- **GitHub**: [jdoe](https://github.com/jdoe) — 52 public repos
- **Twitter**: [@johndoe](https://twitter.com/johndoe) — 3.2k followers
- **LinkedIn**: John Doe — Software Engineer at Acme Corp

## Recommendations

1. Force **password reset** on all exposed accounts
2. Enable **MFA** everywhere
3. Monitor for new breaches via `haveibeenpwned.com`

> *This report was generated automatically. Verify findings before action.*

---

```python
# Quick check script
import requests
resp = requests.get("https://api.example.com/breach-check",
                     params={"email": "johndoe@example.com"})
print(resp.json())
```
"""

    md = Markdown(report)
    console.print(Panel(md, title="[bold]:page_facing_up: OSINT Report", border_style="bright_blue", padding=(1, 2)))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN — Run all demos sequentially
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    from rich.console import Console
    from rich.rule import Rule

    console = Console()
    demos = [
        ("1. Panels", demo_panels),
        ("2. Layout", demo_layout),
        ("3. Tree", demo_tree),
        ("4. Live Display", demo_live),
        ("5. Progress Bars", demo_progress),
        ("6. Tables", demo_tables),
        ("7. Console Markup", demo_markup),
        ("8. Rules / Dividers", demo_rules),
        ("9. Syntax Highlighting", demo_syntax),
        ("10. Markdown Rendering", demo_markdown),
    ]

    for title, fn in demos:
        console.print()
        console.print(Rule(f"[bold bright_white] DEMO: {title} ", style="bright_blue", characters="━"))
        console.print()
        fn()
        console.print()
