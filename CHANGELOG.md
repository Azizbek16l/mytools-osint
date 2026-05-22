# Changelog

All notable changes to this project. Format: Keep-a-Changelog · Semver.

## [Unreleased]

### Added
- `osint config` CLI — interactive wizard for Telegram MTProto sign-in + API key management. Writes to `%LOCALAPPDATA%\mytools-osint\config.env` (preserves existing Telegram session).
- `app/modules/ssl_tls.py` — TLS cert + cipher grade per target host
- `app/modules/http_headers.py` — security header scorer (Mozilla Observatory rubric)
- `app/modules/asn_bgp.py` — Team Cymru WHOIS + BGPView (free, no key)
- `app/modules/tech_fingerprint.py` — Wappalyzer-lite stack detection (~30 sigs)
- Distribution foundation — `pyproject.toml` hatch backend, GitHub Actions release workflow, Dockerfile, Homebrew formula stub, .deb/.rpm/AppImage build via fpm.

### Changed
- **Domain module rewritten** for proper subdomain enumeration. Each discovered subdomain now emits as its own Hit with the FQDN visible in the source column. Sources expanded from 3 → 8: crt.sh, Certspotter, HackerTarget, AlienVault OTX, subdomain.center, RapidDNS, Wayback CDX, ThreatMiner. Cross-source attestation shown ("seen by N sources").

### Fixed
- crt.sh timeout (was 30s, now 90s + 1 retry — service is slow on popular domains)
- Wayback CDX query uses `matchType=domain` for proper subdomain enumeration
- AlienVault OTX queries both passive_dns and url_list endpoints
- SSL/TLS module timeout bumped 10s → 20s

### Redesign (from cli.zip design handoff)
- **Streaming dashboard** rewritten — split-pane layout (modules rail | live hits feed)
  via `rich.Layout`. Per-module state (idle/running/done) + positive counter on the
  left, timestamped hit feed on the right.
- **Result summary card** — categorised findings (dev/social/media/breach/tls/tech/…),
  sparkline of positive-arrival distribution, action menu with single-key shortcuts.
- **Domain report** (kind=DOMAIN) — 3-column compact view: subdomains · DNS+TLS · headers+tech.
- **Modules screen** — k9s-style table with NAME · KINDS · HEALTH · STATE · GLYPH · 7d sparkline.
- **Sites stats** — categorised bar chart with COUNT · SHARE columns, percentage display.
- **History** — 28-day heatmap sparkline above recent queries.
- **Hero menu** — subtitle line with stats, single-key shortcuts on every menu.
- New helpers: `_sparkline()`, `_classify()` (Hit→category mapping), `ModProgress`
  (derived from live Hit stream), `db.history_heatmap()`.

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
