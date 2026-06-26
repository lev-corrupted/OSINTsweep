# Changelog

All notable changes to osint-toolkit. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning per semver.

## [Unreleased]

## [0.4.0] — 2026-06-08

### Added — name pipeline expansion (1 → 7 modules)

Name search was 1 module (GitHub) in v0.3. v0.4 adds 6 more, plus a username
permutator that pivots name results into the 80-source username pipeline.

- **`wikipedia.py`** — full-text Wikipedia search via MediaWiki API. Returns top 5 article matches with snippets (HTML stripped) + total hit count.
- **`wikidata.py`** — Wikidata entity search. Returns Q-ids with labels, descriptions, and direct Wikidata URLs. Includes person-filter heuristic (descriptions matching `person|scientist|engineer|doctor|...`) to surface humans over places/works.
- **`orcid.py`** — ORCID academic-author lookup via `pub.orcid.org/v3.0/expanded-search/`. Returns ORCID iDs + affiliations. The standard ID for academic researchers worldwide.
- **`crossref.py`** — CrossRef paper search (~140M DOI records). Returns top 5 papers with DOI, title, venue, year, co-authors. Essential for vetting academic KOLs.
- **`opensanctions.py`** — sanctions/PEP/watchlist screening. Gated to `OPENSANCTIONS_API_KEY` (free tier at opensanctions.org/api/). For business OSINT: vet contacts before signing.
- **`permutator.py`** — given "Vishesh Bhatia", generates `vishesh.bhatia`, `vbhatia`, `bhatia.vishesh`, `v.bhatia`, etc. (~10-15 plausible handles). Strips honorifics (Dr/Mr/Prof). Supports `--hint "bkk"` for location-suffixed variants.
- **Correlator pivot:** the permutator's output is consumed by `core/correlator.py` — name lookup with `--auto-correlate` automatically runs the top 6 username permutations through the 80-source username pipeline.

### Added — CLI `--hint` flag

`osint name "Atthachai Homhuan" --hint "tilleke healthcare law"` passes the hint via `OSINT_HINT` env var to Wikipedia search (and to the permutator for location suffixes). Helps disambiguate common names — e.g., the lawyer Atthachai Homhuan from the pharmacologist Atthachai Homhuan, both Thai academics with papers on CrossRef.

### Smoke verification

- `Linus Torvalds` → Wikipedia 361 hits, Wikidata Q34253, GitHub 321 matches, 11 username perms. The expected gold-standard.
- `Atthachai Homhuan` → CrossRef 60 papers (pharmacology), 14 username perms, no Wikipedia/Wikidata. Demonstrates **name disambiguation challenge**: the academic surfaced isn't the Tilleke lawyer Lev needs.
- `Acrotol Kanyo` → all not-found. Honest empty result.

### Honest framing

Name OSINT is fundamentally weaker than email or username:
- Names aren't unique (10K "John Smith" matches).
- Most platforms don't expose "search by name" via public API.
- Disambiguation requires hints (location, profession, employer).

The v0.4 module set fits this reality:
- **For notable people** (executives, academics, public figures): Wikipedia + Wikidata + ORCID + CrossRef.
- **For business compliance**: OpenSanctions.
- **For pivoting to richer signals**: permutator → username pipeline.

### Tests

67 passing (12 new in `test_name_modules.py`). Full HTTP mocking via respx.

## [0.3.1] — 2026-06-08

### Fixed — Holehe email-discovery modules

Empirical test on a real Gmail revealed every Holehe
module returned "inconclusive" — all v0.1-v0.3 password-reset fingerprints
were stale or broken. Rewrote the module + the site spec:

- **Method bugs:** Twitter requires `GET` (was `POST`), URL needed `{email}` substitution.
- **`json_body` support** in HolehSite for endpoints that expect JSON (Microsoft, etc.).
- **New working endpoints** verified empirically:
  - `twitter` — `api.twitter.com/i/users/email_available.json?email=...` returns `taken:true|false`.
  - `microsoft` — `login.live.com/GetCredentialType.srf` JSON POST returns `IfExistsResult:0|1` or `ErrorHR:80046703`.
  - `spotify` — `spclient.wg.spotify.com/signup/public/v1/account?email=...` returns `status:20` if taken, `status:1` if free.
  - `github_email` — public search API `/search/users?q={email}+in:email` (fixed regex to allow whitespace in `"total_count": 0`).
  - `pinterest`, `instagram`, `gitlab` — fingerprints updated; pinterest/gitlab/instagram still need CSRF token handling (v0.4).
- **Removed `lastpass`** — endpoint returns the same default iteration count (`600000`) for any email; cannot distinguish registered from free.

### Smoke result on real Gmail

Test email → 2 confirmed registrations (Spotify, Twitter/X), 3 confirmed
not-registered (Microsoft, Gravatar, GitHub public), 3 inconclusive (GitLab,
Instagram, Pinterest — need CSRF token rotation in v0.4).

## [0.3.0] — 2026-06-08

### Added — calibration system + truth in reporting

- **`osint calibrate` command** (`core/calibration.py`):
  - Runs every username source against **3 randomized impossible handles** (`zzimpossible<hex>xx` — alphanumeric to match real handle rules).
  - Majority vote: a source is `unreliable` if it returns FOUND on ≥2 of 3 rounds. Single-shot was too flaky.
  - Persists to `~/.osint-toolkit/calibration.json` (path override via `OSINT_CALIBRATION_PATH`).
  - Auto-suggests `osint calibrate` on first username lookup if no calibration data exists.
- **Confidence demotion in Dispatcher:** findings from sources flagged as unreliable get `confidence=low` + `calibration_warning` in their data dict. They're rendered as `FOUND[?]` in yellow.
- **`--strict` flag** on `username` subcommand: filter out unreliable sources entirely (the recommended mode once calibrated).
- **Rich output rewrite** to split high-confidence FOUND from weak FOUND[?] in the summary line + sort order + per-row coloring.

### Changed — fingerprint quality pass

The acrotolkanyo smoke test (a name that doesn't appear to be a real person) was reporting 25 FOUND in v0.2 — almost all false positives. v0.3 fingerprints were rewritten where possible:
- **Twitter / X:** now use `cdn.syndication.twimg.com/timeline/profile` endpoint with JSON marker matching.
- **Instagram / Threads:** body-marker check for `"username":"{username}"` substring.
- **TikTok:** stricter `"uniqueId":"{username}"` substring (was just `uniqueId`).
- **Medium:** now hits `/feed/@{username}` RSS endpoint — much more reliable than HTML page.
- **Snapchat / Bento / Venmo / CashApp:** body markers instead of status code.
- **Discord vanity:** now uses `/api/v10/invites/{code}` endpoint (was the public invite page).
- **Pastebin:** status code (was URL-echo substring bug that always matched).
- **Facebook:** removed entirely — anti-bot too aggressive for any reliable detection.

For sites that can't be fingerprinted reliably (SPA-shell sites that return 200 for any URL), calibration catches them automatically. v0.3 catches 18 such sources in default calibration:
`anilist, bandcamp, codeforces, crates_io, duolingo, ebay, hackthebox, hashnode, indiehackers, ko_fi, mixcloud, pypi, replit, snapchat, spotify_user, trello, tryhackme, wordpress`.

Once calibrated, default mode shows them as `FOUND[?]` (with a ⚠ calibration_warning). `--strict` hides them.

### Smoke-test improvement (truth, not vanity numbers)

| | v0.2 | **v0.3 (default)** | **v0.3 (--strict)** |
|---|---|---|---|
| `torvalds` FOUND | 52 | **28 high-conf + 18 weak[?]** | 28 high-conf |
| `acrotolkanyo` FOUND | 25 *(mostly false positive)* | **0 high-conf + 18 weak[?]** | **0 (correct)** |

v0.3 reports 0 high-confidence finds for a person who isn't actually online. v0.2 reported 25. That's the win — honesty over the vanity number.

### Tests

55 passing (6 new in `test_calibration.py`). All HTTP mocked via respx, no real network in CI.

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
