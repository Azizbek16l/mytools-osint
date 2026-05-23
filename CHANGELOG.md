# Changelog

All notable changes to this project. Format: Keep-a-Changelog · Semver.

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
