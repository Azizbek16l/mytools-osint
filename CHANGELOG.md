# Changelog

All notable changes to this project. Format: Keep-a-Changelog · Semver.

## [Unreleased]

### Added
- `osint config` CLI — interactive wizard for Telegram MTProto sign-in + API key management. Writes to `%LOCALAPPDATA%\mytools-osint\config.env` (preserves existing Telegram session).
- `app/modules/ssl_tls.py` — TLS cert + cipher grade per target host
- `app/modules/http_headers.py` — security header scorer (Mozilla Observatory rubric)
- `app/modules/asn_bgp.py` — Team Cymru WHOIS + BGPView (free, no key)
- `app/modules/tech_fingerprint.py` — Wappalyzer-lite stack detection (~30 sigs)
- Distribution foundation — `pyproject.toml` hatch backend, GitHub Actions release workflow, Dockerfile, Homebrew formula stub.

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
