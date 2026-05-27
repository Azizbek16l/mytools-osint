# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`mytools-osint` — a single-process Windows desktop OSINT tool. The user feeds it a **username**, **email**, **phone number**, **Telegram handle**, or **IP/domain**; the tool fans out to 100+ public sources concurrently and streams the findings (`Hit`s) back into the UI as each probe finishes.

Personal-use tool for Mars IT. Use case: auditing the user's own digital footprint and authorised pentesting recon. No mass-harvesting, no cloud sync, no detection-evasion features.

## Stack

| Layer | Tech | Why |
|---|---|---|
| UI | PySide6 (Qt 6.11) | native desktop widgets, single-window dark theme |
| Event loop | qasync | unifies the Qt event loop and asyncio so awaiting in slots is safe |
| HTTP | httpx + HTTP/2 | one shared `AsyncClient` with connection pooling and random UA |
| Telegram | Telethon (MTProto userbot) | only way to resolve phone→username; logs in as the user |
| Phone parsing | google-libphonenumber (python port) | offline carrier / region / line-type / timezone |
| Persistence | aiosqlite (WAL) | history + per-probe HTTP cache, lives under `%LOCALAPPDATA%\mytools-osint\` |
| Packaging | Nuitka one-file | ships as a single ~75–95 MB `.exe`, no Python install needed |

Why not Tauri / Electron: the OSINT ecosystem (Sherlock, Holehe, Telethon, libphonenumber, dns.asyncresolver) is overwhelmingly Python. Single-process Python with asyncio is the path of least friction *and* the fastest to first hit — no IPC overhead between a Rust/Node UI and a Python sidecar.

## Architecture in one paragraph

`main.py` builds the QApplication, creates a `qasync.QEventLoop`, connects the SQLite `Database`, registers all OSINT modules with the global `Runner`, and shows the `MainWindow`. When the user presses Enter, the window infers the `QueryKind` (`infer_kind`), builds a `Query`, and calls `Runner.run(query, on_hit=…)`. The Runner asks each registered module whose `kinds` set contains this `QueryKind` to produce hits, and runs all module producers concurrently under a single asyncio semaphore (`HTTP_CONCURRENCY`, default 40). Each `Hit` is appended to the result *and* forwarded via `on_hit` to the UI, which emits a `streamed` signal so the row is added to the table immediately — there's no batch-at-the-end. When all modules drain, the full `QueryResult` is persisted to SQLite and shows up in History.

## File map

```
main.py                       # GUI entry — Qt + qasync boot
cli.py                        # CLI entry — `osint` command (no Qt deps)
                              # No args + TTY → launches interactive shell.
app/
├── core/
│   ├── config.py             # Settings from .env, paths under %LOCALAPPDATA%
│   ├── db.py                 # aiosqlite — queries, hits, http_cache
│   ├── http.py               # shared httpx.AsyncClient (HTTP/2, random UA)
│   ├── runner.py             # ModuleEntry registry + concurrent dispatch
│   └── types.py              # Query, Hit, QueryResult (Pydantic)
├── modules/
│   ├── __init__.py           # registers all modules with the Runner
│   ├── base.py               # probe_site(), stream_probes(), input cleaners
│   ├── username.py           # uses data/sites.json (1000+ Sherlock+WhatsMyName)
│   ├── email.py              # format + MX + Gravatar + HIBP + XposedOrNot + HudsonRock + ProxyNova + Holehe + derived-username
│   ├── phone.py              # libphonenumber + Numverify + WA + delegates to telegram.lookup_phone
│   ├── telegram.py           # Telethon (preferred) + t.me fallback
│   ├── whatsapp.py           # wa.me deep-link probe (best-effort; WA has no public API)
│   ├── ip.py                 # IPinfo + reverse DNS + DNS records
│   ├── domain.py             # crt.sh + HackerTarget + urlscan.io + DNS — subdomain enum
│   ├── discovery.py          # Wayback Machine + GitHub user/code + Google Dorks
│   └── patterns.py           # username variations + email pattern guesser (no network)
├── ui/
│   ├── theme.py              # one source of truth for Qt colours; QSS string
│   ├── banner.py             # BLUETM.UZ ASCII banner shared by CLI + GUI
│   ├── interactive.py        # questionary + rich interactive shell (CLI)
│   └── main_window.py        # search bar, results table, history, settings, modules tabs (GUI)
data/
├── sites.json                # 1000+ probe targets (Sherlock 517 + WhatsMyName 491 deduped)
└── holehe_sites.json         # 11 email-existence signatures
scripts/
├── sync_sherlock.py          # pull canonical Sherlock data.json into data/sites.json
├── sync_whatsmyname.py       # pull WhatsMyName wmn-data.json into data/sites.json
├── telegram_login.py         # legacy single-call interactive sign-in
├── tg_send_code.py           # phase 1: request login code (non-interactive)
├── tg_sign_in.py             # phase 2: complete with code + optional --password
├── smoke_test.py             # boot the UI under QT_QPA_PLATFORM=offscreen
├── live_probe.py             # one-off network probe via the same Runner the GUI uses
├── build_exe.py              # Nuitka one-file build for the GUI (mytools-osint.exe)
└── build_cli.py              # Nuitka one-file build for the CLI (osint.exe, no Qt)
tests/                        # pytest, offline by default
```

## Common dev commands

```powershell
# bootstrap
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env

# run GUI
python main.py

# run CLI
python cli.py temur                 # auto-detect kind
python cli.py --kind email me@x.com
python cli.py --kind phone +998948241222 --json --out report.json

# tests (offline)
python -m pytest -q

# lint
python -m ruff check .

# headless UI smoke test
$env:QT_QPA_PLATFORM='offscreen'; python scripts/smoke_test.py

# live probe via the runner (one-off, network) — auto-detects kind
python scripts/live_probe.py temur
python scripts/live_probe.py me@example.com
python scripts/live_probe.py "+998948241222"

# sync external site datasets
python scripts/sync_sherlock.py        # +400 sites
python scripts/sync_whatsmyname.py     # +600 sites (deduped)

# Telegram MTProto sign-in (two-phase)
python scripts/tg_send_code.py         # phase 1 — TG sends code to your client
python scripts/tg_sign_in.py 12345     # phase 2 — pass the code
python scripts/tg_sign_in.py 12345 --password your2fapw   # if 2FA enabled

# build EXEs
pip install nuitka
python scripts/build_exe.py            # GUI → dist/mytools-osint.exe (~45 MB)
python scripts/build_cli.py            # CLI → dist/osint.exe (~25-40 MB, no Qt)
```

## How to add a new OSINT module

A module is any Python file under `app/modules/` that exposes:

```python
NAME = "mymodule"

async def run(query: Query) -> AsyncIterator[Hit]:
    yield Hit(module=NAME, source="...", status=HitStatus.FOUND, ...)

def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.USERNAME], run)
```

then add the module to `MODULES` in `app/modules/__init__.py`. The Runner will pick it up for the matching kinds. Modules should **stream** hits as they arrive, not collect-then-return — the UI shows positives the moment they land.

For HTTP work, use `app.core.http.get_client()` (the shared client) — never instantiate `httpx.AsyncClient` directly, that breaks pooling and the random-UA contract. For sites-list style probes, reuse `app.modules.base.stream_probes(...)` and define the site signature in JSON.

## Module registry and concurrency

- All modules registered eagerly at startup in `Runner.__init__`, fed from `app.modules.MODULES`.
- A single `asyncio.Semaphore(http_concurrency)` (default 40, override via `HTTP_CONCURRENCY` env) caps *all* in-flight HTTP requests across the whole app.
- Per-site retries are governed by `USERNAME_RETRY` (default 1). Timeouts by `HTTP_TIMEOUT_SEC` (default 10s).
- A module's exception never crashes the Runner — it becomes a single `Hit(status=ERROR, severity=LOW)` row in the result.

## Sites file format

```json
{
  "name": "GitHub",
  "url": "https://github.com/{}",
  "check": "status",                  // status | regex | url
  "good_status": [200],
  "bad_status": [404],
  "good_regex": "<title>...",         // optional, for check=regex
  "bad_regex": "user not found",      // optional, for check=regex
  "bad_url_contains": "/signin",      // optional, for check=url
  "valid_chars": "^[A-Za-z0-9_-]+$",  // optional pre-filter
  "transform": "md5_email",           // optional — md5 of input
  "category": "tech",
  "method": "GET"                     // default; POST also supported
}
```

`probe_site()` enforces this contract. Adding a site is a JSON edit; no code change required.

## Telethon session — what's on disk

`%LOCALAPPDATA%\mytools-osint\telethon\<TELEGRAM_SESSION_NAME>.session` is a SQLite file containing the auth-key for the user's Telegram account. **Treat it like a password.** Anyone with this file has full read access to that Telegram account.

The first sign-in is interactive (`scripts/telegram_login.py`). After that the UI re-uses the session silently. Phone-lookup briefly imports the target as a contact and deletes them again on the same call.

## Settings — where they live

- `.env` at repo root (gitignored). `app.core.config.load_settings()` searches CWD first, then repo root.
- Local data: `%LOCALAPPDATA%\mytools-osint\` — DB, telethon session, http cache, exports.
- No registry, no roaming, no cloud sync. Everything stays on this machine.

## Test conventions

- `pytest` + `pytest-asyncio` (auto mode). Network is *never* required for tests in `tests/`. Anything that hits the network goes under `scripts/` (smoke_test, live_probe) so CI can run `pytest -q` offline.
- `tests/conftest.py` puts repo root on `sys.path` so `import app` works without an editable install.
- `test_sites.py` enforces a minimal schema for `data/sites.json` and `data/holehe_sites.json` — add new sites and the schema test catches typos.

## Free vs. paid sources

The tool is designed to deliver value with **zero paid API keys**. Free integrations:

| Source | Module | Key? | Use |
|---|---|---|---|
| Sherlock + WhatsMyName (1000+ sites) | username | no | profile enum |
| crt.sh | domain | no | Cert Transparency → subdomain leak |
| HackerTarget | domain | no (50/day) | DNS recon |
| urlscan.io public | domain | no | recent scans of a domain |
| XposedOrNot | email | no | email breach lookup |
| Hudson Rock Cavalier | email | no | info-stealer compromised credentials |
| ProxyNova ComB | email | no | leaked email:password combos |
| Wayback Machine CDX | discovery | no | historical URL snapshots |
| GitHub public search | discovery | optional (PAT) | leaked secrets / user profile (60/min vs 10/min) |
| Telegram MTProto (Telethon) | telegram, phone | no (user account) | phone↔username, profile, premium/verified flag |
| t.me HTML | telegram | no | fallback when Telethon not signed in |
| Gravatar | email | no | avatar hash check |
| DNS (dnspython) | ip, domain | no | A/AAAA/MX/TXT/NS/CAA + PTR |
| libphonenumber | phone | no (offline) | carrier/region/timezone |
| wa.me | whatsapp | no | invalid-vs-reachable existence probe |

Optional paid: **HIBP** (HIBP_API_KEY, $3.95/mo), **Numverify** (free 100/mo), **IPinfo** (free 50k/mo), **LeakCheck**.

## False-positive reduction (`app/modules/base.py`)

Many sites return HTTP 200 + content for non-existent profiles (SPA soft-404s).
A naive status-code check classifies these as FOUND. We apply two guards:

1. **Status-code dominates** — in the regex branch, if HTTP is in `bad_status` OR
   it's any 4xx not explicitly listed as `good_status`, we set NOT_FOUND even if
   a generic `good_regex` like `<title>` matches.
2. **For HTTP 200, FOUND must be backed by content**:
   - If `<title>` / `og:title` / `og:description` contains an error marker
     (`error`, `404`, `not found`, `doesn't exist`, `does not exist`, etc.) →
     NOT_FOUND
   - Otherwise the target string must appear in `og:title`, `og:description`,
     or `<title>` (we intentionally ignore `og:url` because SPAs reflect the
     request URL there even on soft-404). If absent → UNCERTAIN.

Diagnostic: `python scripts/diag_fp.py` probes a known set of FP-suspects and
prints the per-site result so you can verify regressions.

## Known limitations / non-goals

- **WhatsApp**: no public API for "is this number registered" — the wa.me probe can only tell you `invalid` vs. `reachable`. Anything deeper needs a logged-in WhatsApp Web session and is out of scope.
- **Snapchat/TikTok/Instagram status-code probes** are noisy — those sites serve 200 + JS shell for non-existent profiles. We mitigate via regex checks where possible.
- **No captcha-bypass, no detection-evasion, no parallel proxy rotation.** This is a personal-use tool, not a scraper farm.
- **Cloudflare-protected sites** (Truecaller, etc.) often return 403/429 — the runner classifies those as `RATELIMITED` rather than `NOT_FOUND` so the user can re-run later.

## When extending

- Don't add features behind a "should we do it?" gate without checking the README's authorised-use note first.
- Don't expand to mobile / cloud / multi-user. This is a Windows-only personal desktop tool; keep it that way.
- Keep modules independent — no shared state outside `app.core.*`. Two modules should never talk to each other directly (the `phone.py` → `telegram.lookup_phone` call is a deliberate exception and the only one).
- Stream `Hit`s; never batch them. The UI's value-add over a CLI is that it shows positives the instant they arrive.

## Build / packaging

`scripts/build_exe.py` invokes Nuitka with `--onefile --standalone --enable-plugin=pyside6`. First build is slow (5–10 min cold compile of C extensions); subsequent builds reuse Nuitka's cache. Output: `dist/mytools-osint.exe`. The Telethon session is **not** bundled — first run on a new machine requires `scripts/telegram_login.py`.
