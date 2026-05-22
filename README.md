# mytools-osint

> Personal OSINT toolkit — CLI + GUI. Free APIs, no paid keys.
> Username · email · phone · Telegram · domain · IP · breach · subdomain · cert · headers.

[![CI](https://github.com/Azizbek16l/mytools-osint/actions/workflows/release.yml/badge.svg)](https://github.com/Azizbek16l/mytools-osint/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20macOS%20%7C%20linux-lightgrey)

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

**No paid APIs are required.** Optional keys (HIBP / Numverify / IPinfo / LeakCheck / GitHub PAT) unlock higher quotas but the tool degrades gracefully.

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
winget install Azizbek16l.MytoolsOsint

# OR scoop
scoop bucket add Azizbek16l https://github.com/Azizbek16l/scoop-bucket
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
