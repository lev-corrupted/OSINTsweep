# OSINTsweep

> Async OSINT recon across 145+ sources — email registration discovery, username enumeration, name lookup, and domain intel. One command, one schema, all results. Built for prospect research, personal footprint audits, and authorized pentesting.

```bash
# B2B prospect research mode — defaults that won't cause harm
osint email founder@acme.example --mode prospect
osint username octocat --mode prospect
osint name "Linus Torvalds" --mode prospect --hint github

# Personal footprint audit — unlocks HIBP, prompts to confirm ownership
osint email me@mydomain.example --mode selfcheck

# Authorized pentest recon — audit-logged for client reporting
osint domain target.example --mode pentest
```

## Why this exists

Existing OSINT tools force you to chain 6 CLIs (sherlock + holehe + gravatar-check + curl + jq + grep) to answer the simplest question: *"is this email registered on Twitter, GitHub, and Strava — and is the username taken?"* OSINTsweep answers that in **one async fan-out** with **one schema** across all sources.

## Install

```bash
git clone https://github.com/lev-corrupted/OSINTsweep
cd OSINTsweep
uv sync                          # installs deps incl. dev
uv run osint --help
```

Python 3.13+. Zero mandatory API keys — optional `HUNTER_API_KEY`, `HIBP_API_KEY`, `EMAILREP_API_KEY`, `GITHUB_TOKEN` unlock higher-quality lookups.

## Three modes — gated at runtime

| Mode | What's on | What's off |
|---|---|---|
| `prospect` | Public profiles, gravatar, DNS MX, Hunter.io pattern, Sherlock-style username search | HIBP breach lookup, password-reset registration discovery against non-owned emails |
| `selfcheck` | Everything, including HIBP | Confirmation required for emails not in `~/.osint-toolkit/owned_emails.txt` |
| `pentest` | Everything + audit log | (Tool will refuse to run in `pentest` without `--engagement <id>`) |

There is no default mode. The flag is required. Read [INSTRUCTIONS.md](INSTRUCTIONS.md) for the why.

## Source coverage (v0.5)

| Category | Count | Sources |
|---|---|---|
| Email — registration check | 29 | Twitter/X, Microsoft, GitHub, Spotify, Instagram, Firefox, Duolingo, Adobe, Chess.com, Atlassian, devRant, Replit, HubSpot, Freelancer, HackerRank, MyFitnessPal, Neocities, Notion, Disney/ESPN, Stremio, HuggingFace, Nextdoor, Coursera, Plurk, Any.do, Etsy, WordPress, Kommo, Insightly |
| Email — metadata | 4 | Gravatar, DNS MX, Hunter.io pattern, EmailRep, HIBP (selfcheck/pentest) |
| Username — presence | 105 | GitHub, GitLab, Reddit, Twitter/X, YouTube, Steam, Twitch, Keybase, HackerNews, Mastodon, Bluesky, Stack Overflow, Chess.com, Lichess, LeetCode, CodeWars, HackerRank, HuggingFace, Behance, Dribbble, Medium, DEV.to, Substack, Pinterest, Snapchat, Telegram, Spotify, npm, Docker Hub, Last.fm, Redbubble, FurAffinity, 9GAG, BuzzFeed, Bandcamp, Reverbnation, JustGiving, e621, Coderwall, and 60+ more |
| Name — public profiles | 7 | Wikipedia, Wikidata, ORCID, Crossref, OpenSanctions, GitHub search, username permutator |

All sites are defined declaratively in JSON — add a source by appending one object to `holehe_sites.json` or `username_sites.json`. No code changes needed.

## Known issues

These are the current bugs and limitations that need fixing or help:

- **Instagram** — IP-level rate limiting kicks in fast; needs proxy rotation or smarter backoff
- **WordPress** — Aggressive throttling (`login_auth_options_throttled`), 30-min IP bans after a few queries
- **Chess.com** — Cloudflare blocks automated requests aggressively; low success rate in concurrent scans
- **EmailRep** — Free tier rate limit is very low; set `EMAILREP_API_KEY` for reliable results
- **Cloudflare-protected username sites** — Some sites (Substack, CodePen, Kickstarter, Depop, etc.) intermittently return CF challenges during concurrent bursts
- **Adobe** — Intermittent fingerprint mismatches during high-volume scans (works fine in isolation)
- **No proxy support yet** — All requests go through the same IP, which triggers rate limits fast during repeated scans

## Architecture (60-second tour)

```
target → dispatcher → [N modules in parallel, rate-limited, cached]
                    ↓
              normalize to Finding schema
                    ↓
              Report → JSON / CSV / Markdown / Rich table
```

- All HTTP via one shared `httpx.AsyncClient`.
- Per-host concurrency cap (default 4) — won't hammer a single source.
- 24h SQLite cache — re-querying the same target is free.
- Retries with exponential backoff + Retry-After honor.
- Cloudflare challenge detection with automatic retry.
- Modules declare `modes_allowed = {"prospect", "selfcheck", "pentest"}` — dispatcher filters before running.
- JSONL scan logging with monthly rotation for audit trails.

## Test + run

```bash
uv run pytest                    # full suite (no real network calls — all mocked via respx)
uv run pytest --cov              # with coverage
uv run ruff check src tests      # lint
```

## Credits & inspiration

This project builds on the techniques and research from:

- **[Holehe](https://github.com/megadose/holehe)** — email registration discovery via signup/login/password-reset endpoint fingerprinting. Our holehe-style module uses the same core idea with a declarative JSON config.
- **[Sherlock](https://github.com/sherlock-project/sherlock)** — username enumeration across social networks. Our sherlock-style module follows the same pattern with status code, body marker, and JSON field detection.
- **[Maigret](https://github.com/soxoj/maigret)** — advanced username checking with site-specific parsing. Inspired our metadata extraction approach.
- **[EmailRep](https://emailrep.io/)** — email reputation API used as a module for risk scoring.
- **[Hunter.io](https://hunter.io/)** — email pattern discovery API integrated as an optional module.
- **[HIBP](https://haveibeenpwned.com/)** — Troy Hunt's breach database, integrated for selfcheck/pentest modes.
- **[httpx](https://www.python-httpx.org/)** — async HTTP client powering all requests.
- **[Rich](https://github.com/Textualize/rich)** — terminal UI rendering.

## License

MIT. See LICENSE.

## Ethics line

This tool will not add: stalkerware, mass-PII aggregation for sale, facial recognition, ID-document harvesting, or anything that targets a specific individual for harassment. Pull requests in those directions will be rejected. See [INSTRUCTIONS.md](INSTRUCTIONS.md) "Ethics + the line I will not cross".
