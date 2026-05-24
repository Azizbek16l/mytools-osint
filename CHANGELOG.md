# Changelog

All notable changes to this project. Format: Keep-a-Changelog · Semver.

## [0.3.1] - 2026-05-25  —  passive_dns + interactive bug-fixes

### Added
- **`passive_dns`** module — historical resolution data via HackerTarget
  (reverse-DNS), AlienVault OTX, and CIRCL pDNS. For DOMAIN + IP kinds.
  Brings module count to **32**.

### Fixed
- `interactive` shell — selecting "settings" raised
  `RuntimeError: asyncio.run() cannot be called from a running event loop`
  (cmd_wizard is sync but internally calls asyncio.run for the Telegram
  status probe). Now off-loaded with `asyncio.to_thread`. Fix applied at
  both call-sites in `app/ui/interactive.py`.
- `interactive` history menu — selecting "← back" raised
  `ValueError: invalid literal for int() with base 10: '← back'` because
  some questionary versions return the label when `value=None`. Now guarded
  with `isinstance(qid, int)` check.
- `app/ui/web.py:275` — unused f-string (ruff F541).


## [0.3.0] - 2026-05-24  —  cyber-pro: web dashboard + 7 modules + self-update

### Added — new OSINT modules (free; key-optional)
- **github_leaks** — GitHub code+commit+user search for domain/email. Finds
  leaked configs, employee side-projects, public org mentions. Optional
  `GITHUB_PAT` for higher rate.
- **cloud_buckets** — S3 + Azure Blob + GCS + Backblaze B2 + DO Spaces enum
  across 25 name permutations × 6 clouds (~150 probes). Anonymous-list
  hits become CRITICAL.
- **hibp_passwords** — Pwned-Passwords k-anonymity check (`--kind password`);
  only first 5 SHA-1 hex chars leave the host.
- **malware_bazaar** — abuse.ch hash IOC lookup (`--kind hash`); md5/sha1/sha256.
- **web_hardening** — CORS misconfig + cookie security audit + robots/sitemap
  interesting-path scan + HTTP-methods (OPTIONS) probe. All passive.
- **well_known** — `/.well-known/*` discovery (security.txt · openid-config ·
  oauth-AS · webfinger · aasa · assetlinks · matrix · saml · ai.txt · 24 paths).
- **subdomain_brute** — passive DNS brute on ~280 curated subdomain names
  (admin · api · vpn · gitlab · grafana · s3 · …). No traffic to webserver.

### Added — query kinds
- `password` (HIBP k-anon)
- `hash` (md5/sha1/sha256 IOC lookups)
- `infer_kind()` detects 32/40/64/128-hex inputs as HASH automatically

### Added — UI / UX
- **`osint serve`** — local web dashboard at http://127.0.0.1:8765 (stdlib
  asyncio, zero extra deps). Live findings stream via SSE; dark theme;
  profile + kind dropdowns; severity-coloured rows.
- **`--md FILE`** — Markdown report (GitHub-issue / Notion ready). KPI table
  + top-findings table + per-module sections.
- 2 new profile presets: **`creds`** and **`leak-hunt`**.

### Added — DevOps
- **`osint self-update`** — pulls latest release binary, verifies SHA-256,
  swaps in place. Detects pipx / brew / scoop installs and routes the user
  to the right package manager. `--check` for non-mutating check.
- **`scripts/install.sh`** — `curl | bash` installer (PATH-friendly).
- **`scripts/mac-autoupdate.sh`** — launchd weekly auto-update for macOS.

### Fixed
- `pyproject.toml`: cli.py + main.py were installed as data files, not
  importable modules → `osint` entry point failed. Now via hatch
  `force-include` so they land at the wheel root.

### Module count: 24 → **31** (+7)
### Test count:   193 → **204** (+11 offline tests via httpx.MockTransport)


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
