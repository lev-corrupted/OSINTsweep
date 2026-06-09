# osint-toolkit

> Best-in-class OSINT for the three real use-cases — sales prospect research, personal footprint audit, and authorized security recon. Fast, async, 30+ sources at v0.1, sherlock-style + holehe-style + gravatar + HIBP (gated) + DNS MX + hunter.io pattern.

```bash
# B2B prospect research mode — defaults that won't cause harm
osint --mode prospect email founder@acme.example
osint --mode prospect username octocat
osint --mode prospect name "Linus Torvalds" --hint github

# Personal footprint audit — unlocks HIBP, prompts to confirm ownership
osint --mode selfcheck email me@mydomain.example

# Authorized pentest recon — audit-logged for client reporting
osint --mode pentest domain target.example
```

## Why this exists

Existing OSINT tools force you to chain 6 CLIs (sherlock + holehe + gravatar-check + curl + jq + grep) to answer the simplest question: *"is this email registered on Twitter, GitHub, and Strava — and is the username taken?"* osint-toolkit answers that in **one async fan-out** with **one schema** across all sources.

## Install

```bash
git clone https://github.com/levtheswag/osint-toolkit
cd osint-toolkit
uv sync                          # installs deps incl. dev
uv run osint --help
```

Python 3.13+. Zero mandatory API keys — optional `HUNTER_API_KEY`, `HIBP_API_KEY`, `GITHUB_TOKEN` unlock higher-quality lookups.

## Three modes — gated at runtime

| Mode | What's on | What's off |
|---|---|---|
| `prospect` | Public profiles, gravatar, DNS MX, Hunter.io pattern, Sherlock-style username search | HIBP breach lookup, password-reset registration discovery against non-owned emails |
| `selfcheck` | Everything, including HIBP | Confirmation required for emails not in `~/.osint-toolkit/owned_emails.txt` |
| `pentest` | Everything + audit log | (Tool will refuse to run in `pentest` without `--engagement <id>`) |

There is no default mode. The flag is required. Read [INSTRUCTIONS.md](INSTRUCTIONS.md) for the why.

## Source coverage at v0.1

| Category | Sources |
|---|---|
| Email — where registered | 15+ Holehe-style (Twitter, Instagram, Pinterest, Spotify, Strava, GitHub, GitLab, Reddit, Imgur, Quora, Patreon, Rumble, Vimeo, etc.) |
| Email — metadata | Gravatar, DNS MX, Hunter.io domain pattern, HIBP (selfcheck only) |
| Username — presence | 30+ Sherlock-style (GitHub, GitLab, Reddit, Twitter/X, Instagram, TikTok, YouTube, Steam, Twitch, Keybase, HackerNews, Lobsters, Behance, Dribbble, Medium, DEV.to, Stack Overflow, Last.fm, Letterboxd, Goodreads, Wikipedia, etc.) |
| Name — public profiles | Google Scholar, GitHub search, ORCID, Crossref |

See `src/osint_toolkit/data/username_sites.json` for the full Sherlock-style site list. Add a site by appending one JSON object — no code change required.

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
- Retries via `tenacity` with exponential backoff.
- Modules declare `modes_allowed = {"prospect", "selfcheck", "pentest"}` — dispatcher filters before running.

## Test + run

```bash
uv run pytest                    # full suite (no real network calls — all mocked via respx)
uv run pytest --cov              # with coverage
uv run ruff check src tests      # lint
```

## License

MIT. See LICENSE.

## Ethics line

This tool will not add: stalkerware, mass-PII aggregation for sale, facial recognition, ID-document harvesting, or anything that targets a specific individual for harassment. Pull requests in those directions will be rejected. See [INSTRUCTIONS.md](INSTRUCTIONS.md) "Ethics + the line I will not cross".
