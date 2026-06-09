# Changelog

All notable changes to osint-toolkit. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning per semver.

## [Unreleased]

## [0.2.0] — 2026-06-08

### Added

- **Domain target kind + 2 new modules:**
  - `domain/dns_records.py` — parallel A/AAAA/MX/TXT/NS/SOA/CNAME/CAA resolution with SPF detection + summary flags.
  - `domain/whois_lookup.py` — RDAP-based registrar/dates/nameservers/status lookup via `rdap.org` (no extra deps).
  - New CLI subcommand: `osint domain <name> --mode <...>`.
- **Cross-source correlator** (`core/correlator.py`):
  - After a primary report, derives downstream `Target`s from finding data (e.g., Gravatar's `preferred_username` → automatic username pipeline run).
  - New `--auto-correlate` flag on `email`/`username`/`name` subcommands.
- **Pentest-mode audit log** (`core/audit.py`):
  - In `--mode pentest`, every Report is appended to `pentest_audit_<timestamp>.jsonl`. Override path via `OSINT_AUDIT_PATH` env var.
- **`request_with_retry` helper** in `core/http.py`: retry-on-429/5xx with exponential backoff + jitter + `Retry-After` honoring. Wired into all Sherlock-style + holehe-style modules.
- **Hunter.io module** (`email/hunter_pattern.py`): company email-pattern lookup for custom-domain emails. Auto-skips for free providers (gmail/outlook/yahoo/icloud/hotmail/proton). Requires `HUNTER_API_KEY`.
- **41 new username sources** for a total of **80**:
  - Bluesky, Mastodon, Threads, Telegram, Discord vanity invites, Roblox, Chess.com, Lichess, Codeforces, LeetCode, Replit, CodePen, MyAnimeList, AniList, npm, PyPI, RubyGems, crates.io, DockerHub, ko-fi, Trello, Mixcloud, Bandcamp, Genius, Untappd, Strava, Snapchat handle, Venmo, CashApp, Spotify user, Gravatar profile, Linktr.ee, Bento, About.me, Wellfound (AngelList), Pastebin, Ghost.org, IndieHackers, Fiverr, Upwork, GitHub API.
- **Realistic Chrome 121 User-Agent** as default — fixes "auto-blocked by Cloudflare" cases that hit v0.1.

### Changed

- Many Sherlock-style fingerprints rewritten for higher accuracy (Reddit, GitLab, Keybase, Steam, TikTok, Stack Overflow, HackerNews, etc. now use site-specific APIs or stronger body markers).
- `core/http.py` default headers tightened: dropped `br` Accept-Encoding (was causing decode errors without brotli installed).

### Fixed

- v0.1 had 7 error cases on `torvalds` smoke test; v0.2 has 6 errors out of 80 sources (the remaining are Cloudflare-protected sites that need browser cookies — flagged for v0.3).
- v0.1 wall-clock vs v0.2: 39 sites in ~5s → **80 sites in ~7s** (per-host concurrency cap still 4).

### Smoke-test improvement (target: `torvalds`)

| | v0.1.0 | **v0.2.0** | Δ |
|---|---|---|---|
| Sources checked | 39 | **80** | +105% |
| FOUND | 23 | **52** | +126% |
| Errors | 7 | **6** | -1 (despite 2× sources) |

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
