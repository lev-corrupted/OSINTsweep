# Changelog

All notable changes to osint-toolkit. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning per semver.

## [Unreleased]

## [0.1.0] — 2026-06-08

### Added — initial release

- **Scaffold:** `pyproject.toml`, `uv`-managed Python 3.13 project, MIT licence, Hatchling build backend.
- **Docs:** `INSTRUCTIONS.md` (engineering rules + 3-mode use-case framing), `README.md`, `.env.example`.
- **Core architecture:**
  - `core/models.py` — Pydantic schemas: `Target`, `Finding`, `Report`, `Source`.
  - `core/module.py` — `BaseModule` ABC; mode-gating built in.
  - `core/dispatcher.py` — async fan-out runner with per-host concurrency limit + global timeout.
  - `core/cache.py` — `aiosqlite` cache with 24h default TTL.
  - `core/ratelimit.py` — per-host async semaphore + token-bucket.
  - `core/http.py` — shared `httpx.AsyncClient` factory with retries via `tenacity`, custom user-agent, timeout config.
- **Email modules:**
  - `email/gravatar.py` — Gravatar profile lookup by email hash.
  - `email/dns_mx.py` — DNS MX record validation (deliverability signal without sending mail).
  - `email/hunter_pattern.py` — Hunter.io domain-pattern lookup (optional, requires `HUNTER_API_KEY`).
  - `email/holehe_check.py` — registration-discovery across 15+ sites (password-reset / signup-collision flows).
- **Username modules:**
  - `username/sherlock_style.py` — data-driven 30+ site username search loaded from `data/username_sites.json`.
- **HIBP integration:** `email/hibp.py` — gated to `--mode selfcheck` only, requires confirmation.
- **CLI:** `osint` command via Typer with subcommands `email`, `username`, `name`, `domain` + `--mode {prospect,selfcheck,pentest}` global flag.
- **Output formatters:** Rich table (default), JSON, CSV, Markdown report.
- **Tests:** Pytest + pytest-asyncio + respx for HTTP mocking. Core tests + module tests, all using mocked HTTP (no real network calls in CI).
- **Three explicit use-case modes** with runtime guardrails:
  - `prospect` — B2B research; HIBP + breach modules disabled.
  - `selfcheck` — personal footprint audit; full modules; confirmation prompt for non-owned emails.
  - `pentest` — authorized recon; full modules + audit log JSONL per session.

### Hard ethics line documented in INSTRUCTIONS.md

- No login-walled scraping (LinkedIn, FB timelines, IG private — out).
- No face recognition, no phone-→-identity lookups.
- No mass-PII aggregation for resale.
- HIBP/breach lookups never run in `prospect` mode.

[Unreleased]: https://github.com/levtheswag/osint-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/levtheswag/osint-toolkit/releases/tag/v0.1.0
