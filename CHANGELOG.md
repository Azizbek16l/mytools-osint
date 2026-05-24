# Changelog

All notable changes to this project. Format: Keep-a-Changelog · Semver.

## [0.2.0] - 2026-05-24  —  red-team boost

### Added — new OSINT modules (all free, no paid keys)
- **internetdb** — Shodan InternetDB (no key): ports + CVEs + tags per IP, auto-resolves domain → IPs
- **threat_intel** — URLhaus + ThreatFox (abuse.ch, free key via `ABUSE_CH_API_KEY`) + PhishTank (no key) for malware/phishing IOCs
- **takeover** — subdomain-takeover detector with 20 service fingerprints (S3, Vercel, Heroku, Netlify, Azure, Wordpress, …) over crt.sh subdomain list
- **web_recon** — three checks rolled into one module:
  - JS secret scanner — fetches homepage + scripts, greps for 15 high-confidence secret patterns (AWS, GitHub, Stripe, Slack, JWT, …)
  - Wayback goldmine — pulls historical URLs from CDX, surfaces `.env` / `.git` / `/admin` / backup leaks
  - favicon mmh3 — pure-Python MurmurHash3 for Shodan favicon pivoting
- **email_security** — SPF + DMARC + DKIM (16 common selectors) + MTA-STS, A-F grading for each
- **typosquat** — generates qwerty / homoglyph / bitsquat / TLD-swap / prepend-append candidates and live-DNS-checks them (caps at 160)
- **pgp_keys** — keys.openpgp.org + keyserver.ubuntu.com lookups for an email
- **tor_check** — onionoo API → is this IP a Tor relay / exit node?

### Added — UI/UX
- **`--profile`** presets: `quick` · `deep` · `person` · `domain-recon` · `red-team` · `blue-team` · `ioc`
- **`--list-profiles`** to inspect them
- **`--bulk FILE`** + `--bulk-format` for sequential target lists (jsonl by default — pipe-friendly)
- **`--jsonl`** streaming output (one Hit per line)
- **`--min-severity`** filter (`info` / `low` / `medium` / `high` / `critical`)
- **`--enable MOD` / `--disable MOD`** per-query module toggle
- **`--html FILE`** — self-contained dark HTML report with KPI tiles, severity stripe, SVG pivot graph, inline extras (no CDN)
- **`--tui`** — live Textual dashboard (modules pane + findings stream + hotkeys: `q` quit, `s` save jsonl, `h` save html, `p` pause, `f` found-only)
- Severity badges in plain output (`[CRITICAL]` / `[HIGH]` / `[MED]`)

### Added — OPSEC
- **`--opsec`** mode: routes all HTTP via SOCKS5 (`TOR_SOCKS` env, default `127.0.0.1:9050`), forces `socks5h://` to prevent DNS leaks, rotates UA per request, adds 200-800ms jitter

### Added — data
- **`scripts/sync_maigret.py`** — pulls Maigret's 3000+ site signatures, merges deduped into `data/sites.json`

### Changed
- `requirements.txt` — added `textual>=0.50.0` (TUI) + `httpx-socks>=0.9.0` (OPSEC)
- module count: **16 → 24** (+8 new)

### Test
- 193 tests pass (172 existing + 21 new for the red-team modules; all offline via httpx.MockTransport)


## [Unreleased]

### Added
- feat(agent): use Claude Code subscription via claude-agent-sdk (no extra cost) (`119e040`)
- feat: Bluetm Agent â€” autonomous daily maintenance daemon (zero recurring cost) (`ffadf91`)

### Changed
- ui: wire menu actions to real functionality (not just labels) (`21e1e90`)
- ui: fix streaming dashboard flicker (whole TUI flashing on every frame) (`c7220d9`)
- ui: fix Hero duplicate subtitle + spaced divider + lookup placeholder overlap (`9454e8f`)
- ui: match Hero menu to mockup pixel-for-pixel (screens-a.jsx SCREEN 1) (`7677349`)
- ui: apply CLI redesign from cli.zip handoff (9 screens) (`5425ac7`)
- smart upgrade: outage classification + TaskGroup + retry policy + confidence dots (`72ce850`)
- domain: rewrite subdomain enum with 8 free passive sources (`ec4eddc`)

### Fixed
- fix(scripts): install_local_agent.ps1 â€” ASCII-only + Interactive logon (`ab8699c`)
- fix: IPv4/IPv6 â†’ QueryKind.IP (was silently routed to USERNAME) (`b3e50f5`)

### Chores
- chore: gitignore nuitka-crash-report.xml + remove from history (`869a5d1`)


## [0.1.0] - 2026-05-23

### Added
- Initial release: CLI (`osint`) + GUI (`mytools-osint`) on Windows.
- 9 OSINT modules: username (1,008 sites · Sherlock + WhatsMyName), email
  (XposedOrNot / Hudson Rock / ProxyNova · all free), phone (libphonenumber +
  Telegram MTProto), Telegram (Telethon), WhatsApp, IP, domain (crt.sh + DNS +
  HackerTarget + urlscan.io), discovery (Wayback + GitHub + Google Dorks),
  patterns (variations + email guesses).
- Interactive shell with arrow-key menus (questionary), rich live tables,
  single-prompt input with kind inference, rounded boxes, BLUETM.UZ banner.
- Standalone EXE builds via Nuitka (~30 MB CLI, ~45 MB GUI).

### Security
- Free APIs only — no paid services. No telemetry. All data stays local under
  `%LOCALAPPDATA%\mytools-osint\`.
