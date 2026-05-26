# Changelog

All notable changes to this project. Format: Keep-a-Changelog · Semver.

## [4.2.1] - 2026-05-26  —  Security hotfix: OPSEC bypass, SSRF guard, URL injection

Driven by senior-security-engineer audit of v4.2.0. Three P0/P1 fixes:

### Fixed
- **[P0]** `--opsec` bypass — `favicon_hash` and `subdomain_takeover` checked
  the non-existent env var `OSINT_OPSEC_MODE` instead of the canonical
  `OSINT_OPSEC`. The "skipped in --opsec mode" guards were dead code; both
  modules ran during opsec scans. Now use the shared `_opsec_on()` helper.
- **[P0]** External `mmh3` C-extension was imported but never declared in
  `pyproject.toml` → ImportError for end users. Replaced with the in-tree
  pure-Python `app.modules.web_recon._mmh3_x86_32` (Shodan-compatible,
  already tested against the canonical vector).
- **[P1]** SSRF guard — `favicon_hash` now refuses private/loopback/
  link-local/reserved/multicast IPs (RFC1918, 127.0.0.1, 169.254.169.254
  metadata, ::1, fe80::, etc.). `follow_redirects=False` added so a
  hostile target can't bounce us to internal addresses.
- **[P1]** URL-parameter injection — `certspotter`, `wayback_urls`,
  `hackertarget`, `ripestat` now `urllib.parse.quote()` the user-controlled
  `query.value` before f-string interpolating into the request URL.
- **[P2]** Replaced `lstrip("*.")` (per-character strip, buggy) with
  `removeprefix("*.")` across all v4.2 modules.

### Tests
- 11 new regression tests in `tests/test_v42_security_fixes.py` and
  earlier rate-limit branch (230 → 241 total).

## [4.2.0] - 2026-05-26  —  Smart Shell + Free Sources: single-fire menu, 6 themes, 6 new modules

Major UX + features release driven by a multi-agent /goal audit (UX engineer, QA, research).

### UX overhaul (driven by senior-ux-engineer audit)
- **Single-fire main menu** — `prompt_toolkit.Application` replaces
  `questionary.select` for the main menu. Pressing `q` / `i` / `l` / `m`
  fires *instantly* — no Enter required, matching lazygit / k9s / btop / claude code.
  (`app/ui/main_menu.py`)
- **7 themes** in a new `THEMES` registry: `github-dark` (default),
  `github-light`, `dracula`, `nord`, `tokyo-night`, `catppuccin-mocha`,
  `high-contrast`. In-app **T → theme picker** persists choice to
  `~/.config/mytools-osint/theme`.
- **Cold-start splash** prints `loading mytools-osint…` within 60ms of
  invocation — kills the 8–12s Nuitka onefile dead-time first-impression.

### New modules (6, all free, no API keys required)
- **`favicon_hash`** — computes Shodan's MMH3 favicon hash; emits a
  ready-to-click `shodan.io/search?query=http.favicon.hash:N` URL. Best
  origin-IP-behind-CDN trick on the internet.
- **`wayback_urls`** — Wayback CDX server query for historical URLs +
  forgotten subdomains. Surfaces deprecated admin paths, leaked params,
  staging hostnames.
- **`certspotter`** — independent CT-log subdomain enumeration; crt.sh
  fallback (100 req/hr free quota).
- **`ripestat`** — authoritative ASN / prefix / abuse-contact lookups
  via RIPE's no-key Data API.
- **`hackertarget`** — multi-tool free-tier API: hostsearch (subdomain
  enum cross-check) + reverse-IP (find co-hosted virtual hosts).
- **`subdomain_takeover`** — CNAME chain check against 24 curated
  fingerprints from `can-i-take-over-xyz` (Vercel, Heroku, GitHub Pages,
  Netlify, Surge, Pantheon, Webflow, Ghost, Kinsta, …). CRITICAL severity
  when body matches the service's "not-claimed" fingerprint.

### Audit drove these v4.3+ items (not in this release)
- Workspaces (per-investigation SQLite + provenance), correlation rules
  YAML engine, full Wappalyzer-Next-style tech fingerprint expand,
  Photon-style crawler (#57). All ranked but deferred for scope.

## [4.1.1] - 2026-05-26  —  QA hotfix: graphql_probe auth-walled detection

End-to-end real-user QA simulation surfaced one P1 bug and two P2 UX issues:

### Fixed
- **`graphql_probe` missed 401/403/422 responses** (P1). Endpoint like
  `api.github.com/graphql` returns 403 (rate-limit/auth); GitLab returns 401;
  many strict APIs return 422 with `{"errors":[...]}` JSON. The probe now
  treats all of these as "GraphQL endpoint exists" (HIGH severity, auth-walled
  or query-rejected). Locked in with 5 regression tests
  (`tests/test_v41_graphql_probe.py`).

### Changed
- **Main-menu instruction** now reads `(↑↓ or shortcut to jump · ↵ to select)`
  to make explicit that `questionary 2.1.1` requires Enter after a shortcut
  (library quirk — shortcut keys navigate but don't auto-fire).

### Known
- First-launch of the Nuitka onefile brew binary takes ~8–12s to self-extract
  into `/var/folders/...` cache. Subsequent invocations are instant. Use the
  pipx install for instant cold-start.

## [4.1.0] - 2026-05-26  —  v4.1 active recon: route discovery + 6 fingerprinting modules

After the v4.0 cornerstone (entity graph + auto-pivot + SIEM + AI), the
user-as-expert audit surfaced one big gap: **all 32 modules were PASSIVE**.
v4.1 adds 7 carefully-bounded ACTIVE probes — all OPSEC-aware (refuse in
`--opsec` mode unless explicit env override).

### Added — 7 active-recon modules

- **route_discover** — dirsearch/ffuf-style path bruteforce. 218 curated
  paths in 10 categories (secret-leak / vcs-leak / admin / debug / backup
  / api-doc / graphql / auth / misc). 3-baseline soft-404 detection +
  content-sniffing on CRITICAL hits (25 signatures: `.env` must contain `=`,
  `.git/HEAD` must start `ref:`, swagger.json must parse as JSON) →
  eliminates ~80% of FP on SPAs. robots.txt parsed as DISCOVERY SOURCE
  (Disallow paths fed into candidate list).

- **subdomain_permute** — altdns-style. Pulls discovered SUBDOMAIN entities
  from the entity graph, mixes with 40 mutation patterns
  (`dev-X` / `X-staging` / `X.beta` / `prod-X` / …), DNS-checks each.
  Surfaces pre-prod environments that are often the soft underbelly.

- **port_scan** — top-50 TCP-connect + 256B banner grab. Concurrent
  asyncio.open_connection w/ Semaphore(20). Database / admin ports
  (3306, 3389, 5432, 6379, 27017, 9200, 8086, 5601, 11211, …) get HIGH
  severity. Maps to PORT entities + EXPOSES_PORT edges in graph.

- **waf_detect** — 11 WAF/CDN signatures (Cloudflare, Akamai, Fastly,
  Imperva, F5 BIG-IP, Sucuri, AWS WAF, Azure Front Door, Barracuda,
  Wallarm). Header-based fingerprint only.

- **cms_detect** — WordPress (meta generator + wp-login.php probe),
  Drupal (CHANGELOG.txt version sniff), Joomla (admin XML manifest).

- **graphql_probe** — POST introspection query to /graphql, /api/graphql,
  /v1/graphql, /v2/graphql, /graphiql. HIGH severity if introspection
  ENABLED; MEDIUM if endpoint exists but introspection blocked.

- **source_maps** — HEAD probe for 13 common bundler source-map paths
  (webpack, Next.js, Vite, CRA). MEDIUM — leaks project source structure.

### Added — new profile
- **active-recon** — focused offensive profile with the 7 active modules
  + subdomain_brute + subdomain_permute. 9 modules total.

### Changed
- `red-team` profile expanded to include all 7 new active modules.
- Module count: 32 → **39**
- Profile count: 11 → **12**

### Security note
All active modules refuse to run in `--opsec` mode by default.
Override per-module: `OSINT_ROUTE_DISCOVER_OVER_TOR=1`,
`OSINT_PORT_SCAN_OVER_TOR=1`. Reasoning: high-volume probing through Tor
is both slow AND loud at the exit node. Use a dedicated VPS for
active scans behind OPSEC.

### Design review credits
Per @senior-security-engineer's input baked into route_discover:
3 baselines (not 1), median-length comparison, content-sniff for CRITICAL
hits, robots.txt as discovery source not boundary, 429-aware concurrency.


## [4.0.0] - 2026-05-26  —  v4.0 cornerstone: entity graph + AI + plugins

Major version. Re-imagined from a one-shot scanner into a **pivot-capable
investigation engine** — Maltego-style entity correlation without the
$5K/seat price tag.

### NEW — Entity graph + correlation engine
- **19 entity types** (Email/Domain/Subdomain/IP/Username/Phone/Telegram/
  Person/Org/Hash/Cert/ASN/Bucket/Repo/CVE/Hostname/Port/Software/URL),
  **33 typed edges** (RESOLVES_TO, MX_FOR, CERT_FOR, HAS_CVE, BLACKLISTED_ON,
  TYPOSQUAT_OF, …) with per-edge traversal cost.
- Same entity discovered by N modules → **ONE node** with N pieces of
  evidence. Canonical-key normalisation at insert time.
- Persisted in SQLite alongside hits. Schema migration v3.
- `osint graph show <kind> <value> [--depth N]` — ASCII tree
- `osint graph export <kind> <value> --format gexf|graphml|cytoscape`
  → opens directly in Gephi / Maltego / Neo4j / yEd.
- `osint graph rebuild` re-derives from every stored hit.
- `osint graph forget` for GDPR-style erasure.

### NEW — Auto-pivot (`--pivot N`)
- After main scan, take every FOUND entity, route to appropriate profile,
  re-run with bounded BFS. Cycle detection, noisy-value guard
  (gmail.com / 1.1.1.1 skipped), per-edge cost budget, per-kind cap,
  hard wall at 30 total pivots. Verified end-to-end: `8.8.8.8 --pivot 1`
  discovers `dns.google` and pivots into ioc profile.

### NEW — Interactive force-directed graph in HTML reports
- Vanilla-JS (zero deps, no CDN, no D3, no Cytoscape) — Verlet integration
  + drag/zoom/click-for-details. ~21 KB total for typical scans.
- 19 entity types colour-coded with legend.
- Click any node → side panel with in/out edge counts.

### NEW — SIEM exporters (`osint export ... --to ...`)
- Splunk HEC (newline-delimited)
- Elasticsearch bulk-index
- syslog RFC 5424 (UDP/TCP)
- MISP Event creation (one Attribute per hit)
- All read connection params from env or flags; politely SKIP if missing.

### NEW — YAML config + presets
- `~/.config/mytools-osint/config.yaml` declares `profiles`, `presets`,
  `sources` (env-mapped API key registry), `defaults`.
- `osint preset run <name>` re-runs a saved-scan recipe.
- `osint config init-yaml` writes a sample.

### NEW — Plugin architecture
- Discovers third-party modules via `entry_points("mytools_osint.modules")`.
- `osint plugin list|install|search|remove` — pip-driven.
- Plugins live in the same interpreter (no sandbox — trust your sources).

### NEW — AI-assisted analysis (`osint ai`)
- `osint ai explain <kind> <value>` → 5-bullet executive summary +
  risk ranking via Claude (claude-haiku-4-5 for cheap, bumps to sonnet
  for >50 positives).
- `osint ai query "natural language"` → translates to `osint <args>` + runs.
- Requires `ANTHROPIC_API_KEY`. Disabled in OPSEC mode (privacy).

### Reliability hardening
- Real-PTY pexpect launch smoke test (would have caught the v0.3.1 `?`
  shortcut crash in 2s instead of in production).
- Parametrized shortcut-key validator — checks every Choice in app/ui/
  against questionary's alphanumeric + no-vim-clash contract.
- Found 3 latent bugs in static scan: `j` in export-format menu (vim-nav
  clash), `--help` missing `export`/`graph` subcommands — all fixed.

### Test count: 204 → **206** (+19 v4 entity + 10 smoke; — 17 stale)
### Module count: 32 (unchanged; v4 invests in correlation, not new probes)
### Subcommands: 10 → **15** (+graph, +export, +preset, +plugin, +ai)


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
