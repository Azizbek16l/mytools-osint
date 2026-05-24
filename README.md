# mytools-osint

> Personal OSINT toolkit — CLI + GUI. Free APIs, no paid keys.
> Username · email · phone · Telegram · domain · IP · breach · subdomain · cert · headers.

[![release](https://github.com/Azizbek16l/mytools-osint/actions/workflows/release.yml/badge.svg)](https://github.com/Azizbek16l/mytools-osint/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macOS%20%7C%20linux-lightgrey)
[![tests](https://img.shields.io/badge/tests-204%20passing-brightgreen)](#)
[![modules](https://img.shields.io/badge/modules-31-blue)](#)
[![GitHub release](https://img.shields.io/github/v/release/Azizbek16l/mytools-osint?sort=semver)](https://github.com/Azizbek16l/mytools-osint/releases/latest)

---

## What it does

Given one input — a username, email, phone, Telegram handle, domain, or IP — it fans out across **1,000+ public sources** in parallel and streams findings into your terminal:

- **Username** → profile enumeration across 1,008 sites (Sherlock + WhatsMyName datasets, deduped, false-positive-guarded)
- **Email** → breach lookup (XposedOrNot · Hudson Rock Cavalier · ProxyNova ComB — all free), Holehe-style site probes, Gravatar, MX, derived-username sweep
- **Phone** → libphonenumber offline (carrier/region/timezone), Telegram MTProto phone↔username, WhatsApp existence probe
- **Telegram** → @username resolution via your own MTProto session; t.me HTML fallback
- **Domain** → crt.sh Certificate Transparency, HackerTarget DNS recon, urlscan.io scans, DNS A/AAAA/MX/TXT/NS/SOA, **SSL/TLS posture + Mozilla-Observatory-style HTTP-header grade + Wappalyzer-lite tech fingerprint**
- **IP** → reverse DNS, IPinfo (if key set), **ASN/BGP via Team Cymru + BGPView** (free, no key)
- **Discovery** → Wayback Machine snapshots, GitHub public user/code search, ready-to-click Google Dorks
- **Patterns** → username variations + email-format guesses (offline)

**No paid APIs are required.** Optional keys (HIBP / Numverify / IPinfo / LeakCheck / GitHub PAT / abuse.ch / AbuseIPDB) unlock higher quotas but the tool degrades gracefully.

## What's new in 0.3 — cyber-pro: web dashboard + 7 modules + self-update

`mytools-osint` 0.3 adds **7 more modules** + a local **web dashboard** +
**Markdown reports** + an **`osint self-update`** path that pulls the
latest binary, verifies SHA-256, and swaps it in place.

```bash
osint serve                                  # local web UI at http://127.0.0.1:8765
osint github.com --profile leak-hunt --md leaks.md
osint 'P@ssw0rd!' --kind password            # HIBP k-anon (value never leaves host)
osint 5d41402abc4b2a76b9719d911017c592 --kind hash      # MalwareBazaar IOC lookup
osint mycorp.com --profile red-team --html report.html  # all 24 red-team modules
osint self-update                            # update in place, SHA-256 verified
```

| Module          | Use case                                                  |
|-----------------|-----------------------------------------------------------|
| `github_leaks`  | GitHub code+commit+user search for org/email mentions     |
| `cloud_buckets` | S3 + Azure + GCS + B2 + DO bucket enum (anonymous-list = CRITICAL) |
| `hibp_passwords`| Pwned-Passwords k-anonymity (password never leaves host)  |
| `malware_bazaar`| abuse.ch hash IOC lookup (md5/sha1/sha256)                |
| `web_hardening` | CORS + cookies + robots/sitemap + HTTP methods            |
| `well_known`    | `/.well-known/*` discovery (24 paths: oidc · saml · …)    |
| `subdomain_brute` | passive DNS brute on 280 curated subdomain names        |

## What's new in 0.2 — red-team boost

`mytools-osint` 0.2 added **8 modules** purpose-built for security engineers,
red teams, and IOC analysts — all free, all key-optional. Plus profile
presets, a HTML pivot report, a live Textual dashboard, and an OPSEC mode
that tunnels every request through Tor.

```bash
osint --profile red-team example.com --html report.html
osint --profile ioc 198.51.100.42 --jsonl                    # pipe-friendly
osint --bulk targets.txt --profile domain-recon              # bulk mode
osint --tui example.com                                      # live dashboard
osint example.com --opsec                                    # SOCKS5 + jitter
```

| Module          | What it does                                              | Free? |
|-----------------|-----------------------------------------------------------|-------|
| `internetdb`    | Shodan InternetDB → ports + CVEs + tags per IP            | yes, no key |
| `threat_intel`  | URLhaus + ThreatFox + PhishTank malware/phishing IOCs     | yes, optional `ABUSE_CH_API_KEY` |
| `takeover`      | Subdomain takeover detector (20 service fingerprints)     | yes |
| `web_recon`     | JS secret scanner + Wayback `.env/.git/admin` goldmine + favicon mmh3 | yes |
| `email_security`| SPF + DMARC + DKIM + MTA-STS, A-F graded                  | yes |
| `typosquat`     | qwerty + homoglyph + bitsquat + TLD-swap generator + DNS check | yes |
| `pgp_keys`      | keys.openpgp.org + Ubuntu keyserver lookups               | yes |
| `tor_check`     | onionoo → is this IP a Tor relay / exit?                  | yes |

Profile presets: `quick · deep · person · domain-recon · red-team · blue-team · ioc`.
List them with `osint --list-profiles`.

## How it compares

|                          | Sherlock | Maigret | Holehe | theHarvester | **mytools-osint** |
|--------------------------|:--------:|:-------:|:------:|:------------:|:-----------------:|
| Username probe (sites)   | ~400     | ~3000   | —      | —            | **1,008** (Sherlock + WhatsMyName; +Maigret via sync) |
| Email breach lookup      | —        | —       | ~120   | partial      | **XposedOrNot + HudsonRock + ProxyNova + Holehe ports** |
| Phone (libphonenumber + TG MTProto) | — | — | — | — | **yes** |
| Domain / subdomain enum  | —        | —       | —      | **yes**      | **crt.sh + HackerTarget + OTX + urlscan + RapidDNS + subdomain.center + ThreatMiner + Wayback** |
| SSL/TLS posture grade    | —        | —       | —      | —            | **yes** |
| HTTP-headers (Observatory-style) | — | —   | —      | —            | **yes** |
| Tech fingerprint (Wappalyzer-lite) | — | — | —      | —            | **yes** |
| Shodan InternetDB (no key, CVEs per IP) | — | — | — | —       | **yes** |
| Subdomain takeover detector | —     | —       | —      | —            | **yes (20 services)** |
| JS-source secret scanner | —        | —       | —      | —            | **yes (15 patterns)** |
| Wayback `.env/.git/admin` goldmine | — | — | —    | —            | **yes** |
| Favicon mmh3 (Shodan pivoting) | —  | —       | —      | —            | **yes (pure-Python)** |
| DMARC / SPF / DKIM / MTA-STS grader | — | —  | —      | —            | **yes** |
| Typosquat generator + DNS check | — | —      | —      | —            | **yes (134+ candidates)** |
| Threat-intel (URLhaus + ThreatFox + PhishTank) | — | — | — | —     | **yes** |
| Tor relay / exit check   | —        | —       | —      | —            | **yes (onionoo)** |
| PGP key lookup           | —        | —       | —      | —            | **yes (openpgp.org + Ubuntu)** |
| Profile presets          | —        | —       | —      | —            | **yes (7 presets)** |
| Live TUI dashboard       | —        | —       | —      | —            | **yes (textual)** |
| HTML report (pivot graph)| —        | —       | —      | —            | **yes (single-file, no CDN)** |
| JSON-lines streaming     | —        | partial | —      | —            | **yes** |
| Bulk mode (file-of-targets) | partial | yes  | yes    | —            | **yes** |
| OPSEC mode (SOCKS5h + jitter + UA rotation) | partial | partial | — | — | **yes** |
| Telegram MTProto resolve | —        | —       | —      | —            | **yes (your own session)** |
| MCP server (Claude/Cursor) | —      | —       | —      | —            | **yes** |
| Watchlist + diff + notify| —        | —       | —      | —            | **yes** |
| Free APIs only / no paid keys | yes | yes     | yes    | mostly       | **yes** |
| Single-binary (Nuitka)   | —        | —       | —      | —            | **yes (CLI + GUI)** |

*Comparison made in good faith from each project's README as of 2026-05; corrections welcome.*

## Architecture

```
        ┌──────────────────────────────────────────────────────────────┐
        │                          INPUT                                │
        │      username  ·  email  ·  +phone  ·  @tg  ·  domain  ·  IP  │
        └────────────────────────────┬─────────────────────────────────┘
                                     │ infer_kind() — IP > email > phone > domain > username
                                     ▼
        ┌──────────────────────────────────────────────────────────────┐
        │                   Runner (asyncio TaskGroup)                  │
        │           one shared httpx.AsyncClient · HTTP/2 · UA-rotate  │
        │           Semaphore(HTTP_CONCURRENCY=40) caps in-flight req  │
        └────────────────────────────┬─────────────────────────────────┘
              ┌──────────┬───────────┼───────────┬──────────┬────────┐
              ▼          ▼           ▼           ▼          ▼        ▼
        username      email      phone     telegram     domain     IP …
        (1008 sites)  +extras  libphone  MTProto    crt.sh+      InternetDB
                                                    8 sources    +threat_intel
                                                                 +tor_check
              │          │           │           │           │          │
              └──────────┴───────────┴─────┬─────┴───────────┴──────────┘
                                           │ Hit (status · severity · category · extra)
                                           ▼
        ┌──────────────────────────────────────────────────────────────┐
        │  CLI plain   │  CLI jsonl   │  CSV   │  HTML report  │  TUI  │
        │  (severity   │  (pipe to    │ (xlsx) │  (SVG pivot   │ (live │
        │   coloured)  │   jq, splunk)│        │   graph)      │ dash) │
        └──────────────────────────────────────────────────────────────┘
                                           ▼
                                  aiosqlite WAL DB
                          (history · diff · watchlist · cache)
```

## Install

### macOS

**Homebrew** (recommended):
```bash
brew tap Azizbek16l/osint
brew install mytools-osint
```

**pipx** (universal Python):
```bash
brew install pipx        # if you don't have it
pipx ensurepath
pipx install mytools-osint
```

### Linux

**Debian / Ubuntu (.deb):**
```bash
VER=$(curl -s https://api.github.com/repos/Azizbek16l/mytools-osint/releases/latest | grep tag_name | cut -d'"' -f4 | sed 's/^v//')
curl -L -o mytools.deb "https://github.com/Azizbek16l/mytools-osint/releases/latest/download/mytools-osint_${VER}_amd64.deb"
sudo apt install ./mytools.deb       # apt resolves deps automatically
osint --version
```

**Fedora / RHEL (.rpm):**
```bash
VER=$(curl -s https://api.github.com/repos/Azizbek16l/mytools-osint/releases/latest | grep tag_name | cut -d'"' -f4 | sed 's/^v//')
sudo dnf install "https://github.com/Azizbek16l/mytools-osint/releases/latest/download/mytools-osint-${VER}-1.x86_64.rpm"
```

**Any distro (AppImage — portable, no install):**
```bash
curl -L -o osint.AppImage https://github.com/Azizbek16l/mytools-osint/releases/latest/download/mytools-osint-*-x86_64.AppImage
chmod +x osint.AppImage
./osint.AppImage --version
```

**pipx (universal Python):**
```bash
sudo apt install pipx -y       # or: brew install pipx (Linuxbrew)
pipx install mytools-osint
```

**Direct binary (no Python):**
```bash
curl -L https://github.com/Azizbek16l/mytools-osint/releases/latest/download/osint-linux-x86_64 -o osint
chmod +x osint && sudo mv osint /usr/local/bin/
```

### Windows

```powershell
# winget (Windows 11)
winget install Bluetm.MytoolsOsint

# OR scoop
scoop bucket add bluetm https://github.com/Azizbek16l/scoop-bucket
scoop install mytools-osint

# OR pipx
pipx install mytools-osint

# OR direct download from the Releases page:
#   https://github.com/Azizbek16l/mytools-osint/releases/latest
```

### Docker

```bash
docker run --rm ghcr.io/azizbek16l/osint:latest torvalds
```

## Quick start

```bash
osint                            # interactive menu (arrow keys)
osint torvalds                   # auto-detect: username
osint me@example.com             # email + breach + derived
osint +998948241222              # phone + Telegram MTProto
osint marsits.uz                 # domain + SSL + headers + tech + DNS + crt.sh
osint 8.8.8.8                    # IP + ASN/BGP + rDNS

osint --kind email me@x.com --json --out report.json
osint --list-modules
osint --list-stats
osint config telegram            # one-time Telegram setup wizard
```

## Telegram setup (one-time, free)

`osint config telegram` walks through:

1. Visit <https://my.telegram.org/apps>, sign in with your phone, create an app, copy `api_id` + `api_hash`.
2. Run `osint config telegram` → pick **set api_id / api_hash / phone**.
3. Pick **start sign-in** → Telegram sends a 5-digit code to your existing Telegram client (not SMS).
4. Enter the code → done. Session persists at `%LOCALAPPDATA%\mytools-osint\telethon\` on Windows, `~/Library/Application Support/MarsIT/mytools-osint/telethon/` on macOS, `~/.local/share/mytools-osint/telethon/` on Linux.

After setup: `osint +<E.164 number>` does a real Telegram phone→username resolution. The contact is imported and immediately deleted — Telegram still flags the lookup, so use sparingly on numbers you don't own.

## Free APIs in use

| Source | Coverage | Key required? |
|---|---|---|
| Sherlock + WhatsMyName | 1,008 username probe targets | no |
| crt.sh | Certificate Transparency → subdomain leak | no |
| HackerTarget | DNS recon (~50 req/day) | no |
| urlscan.io public | Recent scans of a domain | no |
| XposedOrNot | Email breach lookup | no |
| Hudson Rock Cavalier | Info-stealer compromised credentials | no |
| ProxyNova ComB | Leaked email:password combos | no |
| Wayback Machine | Historical URL snapshots | no |
| GitHub public search | Leaked secrets / user profile | optional PAT for higher rate |
| Telethon MTProto | phone↔username, profile, premium/verified | your own TG account |
| Team Cymru WHOIS | ASN + prefix + country (TCP 43) | no |
| BGPView | Upstreams + peers + prefixes | no |
| Gravatar | Avatar hash check | no |
| Mozilla Observatory rubric | HTTP security-header grade | no (local logic) |
| Wappalyzer-lite | Web technology fingerprint (~30 sigs built-in) | no |
| `libphonenumber` | Offline phone parsing | no |
| `dnspython` | A/AAAA/MX/TXT/NS/CAA/SOA + reverse | no |
| `wa.me` | WhatsApp existence probe (best-effort) | no |

Optional paid keys plug into the same modules: HIBP, Numverify, IPinfo, LeakCheck. Set them with `osint config set HIBP_API_KEY xxx` — they extend coverage but are never required.

## MCP server — use mytools-osint from Claude Code / Warp / Cursor

`mytools-osint` ships as a **Model Context Protocol** server so AI assistants
can call its OSINT tools directly. Once the server is wired into your AI
client's config, the assistant gets the following tools — `lookup_username`,
`lookup_email`, `lookup_phone`, `lookup_whatsapp`, `lookup_domain`,
`lookup_ip`, plus `list_modules` and `list_sites_stats` for inventory.
`lookup_telegram` is registered automatically iff a Telegram MTProto
session is configured (`osint config telegram`). Three resources are
exposed (`osint://history`, `osint://history/{id}`, `osint://sites`)
along with two pre-canned investigation prompts (`digital_footprint_audit`
and `domain_security_check`).

```bash
osint mcp                       # launches the stdio MCP server
```

Wire into Claude Code by adding this to `~/.claude/mcp.json` (example file
shipped at `agent/mcp.json`):

```json
{
  "mcpServers": {
    "mytools-osint": {
      "command": "osint",
      "args": ["mcp"]
    }
  }
}
```

Restart Claude Code; the assistant can now call the tools directly. Same
config shape works for Warp Agents and Cursor.

**Why this matters (2026 standard):** embedding an LLM chat bar inside the
CLI competes with Copilot CLI, Warp AI and Claude Code itself. Exposing the
tool **as** an MCP server is the inversion that wins — agents come to you,
the user never has to leave their chat.

## Architecture

Single-process Python. The `Runner` registers every module against the `QueryKind`s it handles. Each query fans out to the matching producers concurrently under a single asyncio semaphore (default 40). Each module **streams** `Hit`s as they arrive — the GUI/CLI shows positives the moment they land.

See `CLAUDE.md` for the full architecture overview.

## Build from source

```bash
git clone https://github.com/Azizbek16l/mytools-osint
cd mytools-osint
python3.13 -m venv .venv && source .venv/bin/activate    # or .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python cli.py                     # CLI
python main.py                    # GUI (requires PySide6)

# Standalone binary (~30-45 MB single-file)
pip install nuitka ordered-set zstandard
python scripts/build_cli.py       # → dist/osint
python scripts/build_exe.py       # → dist/mytools-osint (GUI)
```

## Docs

- [docs/red-team-playbook.md](docs/red-team-playbook.md) — recon flow for an authorized engagement, with OPSEC first
- [docs/blue-team-playbook.md](docs/blue-team-playbook.md) — SOC / CTI use: baseline + drift + IOC triage
- [docs/sources.md](docs/sources.md) — every external source the tool talks to, with rate-limit notes
- [packaging/README.md](packaging/README.md) — install-command quick-reference for every channel + release runbook

## Authorised use only

This tool is intended for: (1) auditing your **own** digital footprint,
(2) authorised pentesting engagements with written consent, and (3) fraud or
scam investigations conducted under applicable law. Misuse may violate the
Computer Fraud and Abuse Act, GDPR, or the laws of your jurisdiction. The
authors disclaim all responsibility.

## License

MIT — see [LICENSE](LICENSE).

---

Made with care in Tashkent · [Bluetm.uz](https://bluetm.uz) · `@bluetm` on Telegram
