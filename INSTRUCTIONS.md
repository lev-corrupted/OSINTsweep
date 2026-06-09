# INSTRUCTIONS — osint-toolkit

Standing engineering rules for this project. Future-you (and any agent) must follow these.

## Purpose

A general-purpose OSINT (Open Source Intelligence) toolkit that runs against **three explicit use-cases**, gated at runtime by `--mode`:

| Mode | Use case | Guardrails |
|---|---|---|
| `prospect` | B2B prospect research — find decision-makers, email patterns, public profiles | No HIBP breach lookups. No password-reset abuse modules. Polite rate limits. |
| `selfcheck` | Personal digital footprint audit | All modules unlocked, including HIBP. Confirmation prompt if target email is not in `~/.osint-toolkit/owned_emails.txt`. |
| `pentest` | Authorized security recon (engagement letter required) | All modules unlocked. Logs every query to `pentest_audit_<timestamp>.jsonl` for client reporting. |

The runtime mode is required (`--mode prospect|selfcheck|pentest`). There is no default. This is deliberate — a tool that can be used for stalking with a default mode is a tool that gets used for stalking. Force the choice.

## Hard rules

1. **No login-walled scraping.** LinkedIn, Facebook timelines, Instagram private profiles — out of scope. Only public endpoints.
2. **No automated breach data lookups against arbitrary third-party targets.** HIBP is gated to `selfcheck` mode + confirmation.
3. **Respect rate limits + ToS.** Every module declares its rate budget; the dispatcher enforces it. If a site says `Retry-After`, honor it.
4. **No face recognition. No phone → identity lookups.** Both are jurisdiction-loaded and high-harm.
5. **Cache aggressively.** A re-query within 24h hits SQLite cache, not the network. Saves money + politeness.
6. **TDD per Lev's project SOP.** Write the test first, run it red, then implement, then run it green. No exceptions.
7. **No PII in commit messages, logs, or test fixtures.** Use `acme.example`, `octocat`, `torvalds` as test handles — never a real client target.

## Architecture

```
src/osint_toolkit/
├── core/
│   ├── models.py         # Pydantic schemas: Target, Source, Finding, Report
│   ├── dispatcher.py     # Async fan-out: runs N modules in parallel with rate-limit + cache
│   ├── cache.py          # SQLite (aiosqlite) with TTL + invalidation
│   ├── ratelimit.py      # Per-host async semaphore + token-bucket
│   ├── module.py         # BaseModule ABC — every source implements .run(target) -> Finding
│   └── http.py           # Shared httpx.AsyncClient with retries, user-agent, timeout
├── modules/
│   ├── email/            # email → ... (where registered, valid, breached, gravatar, etc.)
│   ├── username/         # username → which platforms (data-driven from data/username_sites.json)
│   └── name/             # name → public profiles + search-engine matches
├── output/               # JSON, CSV, Markdown, Rich table renderers
├── data/
│   └── username_sites.json  # Sherlock-style site DB — URL templates + presence detection
└── cli.py                # Typer entry point
```

## Adding a new source module

1. Subclass `BaseModule` in `core/module.py`.
2. Declare: `name`, `category` (email/username/name/domain), `requires_api_key`, `rate_limit_per_min`, `modes_allowed`.
3. Implement `async def run(self, target: str, client: httpx.AsyncClient) -> Finding`.
4. **Write the test first** in `tests/modules/<category>/test_<name>.py` using `respx` to mock HTTP.
5. Register in `modules/<category>/__init__.py` `REGISTRY` list.

## Testing

```bash
uv run pytest                    # full suite
uv run pytest -k email           # email modules only
uv run pytest --cov              # with coverage
uv run pytest tests/core         # core only
```

A module without a passing test does not ship. Tests use `respx` to mock HTTP; no test makes a real network call (slow + flaky + unfriendly to source sites).

## Running the tool

```bash
uv run osint --mode prospect email someone@clinic.com
uv run osint --mode prospect username vishesh_bhatia
uv run osint --mode prospect name "Vishesh Bhatia" --hint bangkok
uv run osint --mode selfcheck email you@example.com  # HIBP unlocked, prompts confirmation
uv run osint --mode pentest domain target.example          # audit-logged
```

Outputs default to a Rich terminal table. `--json` / `--csv` / `--md report.md` flags switch format.

## Versioning + changelog

- **v0.x.x** = pre-1.0. Breaking changes allowed; documented in CHANGELOG.md.
- Bump version in `pyproject.toml` for any user-visible change.
- CHANGELOG entry required for every commit that ships a feature/fix.

## Ethics + the line I will not cross

This tool exists because OSINT is a normal part of sales prospecting, self-defense (knowing your own footprint), and authorized security work. It also exists because tooling that doesn't exist openly gets built privately for worse purposes.

I will not add: stalker-ware features (continuous location monitoring), automated deanonymization of pseudonymous accounts, mass-PII aggregation for sale, facial recognition, ID-document harvesting, or anything that targets specific individuals for harassment.

If a feature request feels like it crosses the line, it does. Default to no.

## Daily ops

- `uv sync` after pulling — installs deps
- `uv run pytest` before every commit
- `uv run ruff check src tests` for lint
- `uv run ruff format src tests` for format
- Update CHANGELOG.md for every commit that changes behavior
