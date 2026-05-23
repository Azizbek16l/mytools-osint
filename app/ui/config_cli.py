"""`osint config` — in-CLI settings management.

Writes to %LOCALAPPDATA%\\mytools-osint\\config.env (NOT the project-root .env)
so packaged installs work out of the box. Telegram session files in
%LOCALAPPDATA%\\mytools-osint\\telethon\\ are LEFT ALONE — this command never
deletes them.

Subcommands:
  osint config                — interactive wizard
  osint config show           — print current settings (secrets masked)
  osint config set KEY VAL    — set a single value
  osint config unset KEY      — clear a value
  osint config edit           — open config.env in $EDITOR
  osint config telegram       — wizard for Telegram MTProto (api_id/hash/phone)
                                + optional sign-in (preserves existing session)
"""
from __future__ import annotations

import asyncio
import os
import re
import subprocess
import sys
from pathlib import Path

import questionary
from prompt_toolkit.styles import Style as PStyle
from rich.console import Console
from rich.table import Table

from app.core.config import load_settings, settings, user_config_path
from app.ui import tokens
from app.ui.banner import BRAND

console = Console(highlight=False)

# Public knobs the wizard can set (key, label, secret?)
KNOBS: list[tuple[str, str, bool]] = [
    ("TELEGRAM_API_ID",    "Telegram api_id (from my.telegram.org/apps)",   False),
    ("TELEGRAM_API_HASH",  "Telegram api_hash",                              True),
    ("TELEGRAM_PHONE",     "Telegram phone (E.164, e.g. +14155550143)",      False),
    ("HIBP_API_KEY",       "HaveIBeenPwned API key (paid — optional)",       True),
    ("NUMVERIFY_API_KEY",  "Numverify API key (free 100/mo — optional)",     True),
    ("IPINFO_API_TOKEN",   "IPinfo API token (free 50k/mo — optional)",      True),
    ("LEAKCHECK_API_KEY",  "LeakCheck API key (optional)",                   True),
    ("GITHUB_TOKEN",       "GitHub PAT (free; raises rate limit 10→30/min)", True),
    ("HTTP_TIMEOUT_SEC",   "HTTP timeout seconds (default 10)",              False),
    ("HTTP_CONCURRENCY",   "concurrent in-flight requests (default 40)",     False),
]

QSTYLE = PStyle([
    ("qmark", f"fg:{tokens.ACCENT} bold"),
    ("question", "bold"),
    ("answer", f"fg:{tokens.OK} bold"),
    ("pointer", f"fg:{tokens.ACCENT} bold"),
    ("highlighted", f"fg:{tokens.ACCENT} bold"),
    ("selected", f"fg:{tokens.OK}"),
    ("instruction", f"fg:{tokens.DIM}"),
])


# ---------------------------------------------------------------------------
# .env file IO — preserve order, comments, blank lines
# ---------------------------------------------------------------------------

_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _read_kv() -> dict[str, str]:
    p = user_config_path()
    if not p.exists():
        return {}
    out: dict[str, str] = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        m = _LINE_RE.match(line)
        if m and not line.lstrip().startswith("#"):
            out[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return out


def _write_kv(kv: dict[str, str]) -> Path:
    p = user_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# mytools-osint — user config (written by `osint config`)",
        f"# Path: {p}",
        "# Edit by hand or use `osint config set KEY VAL`.",
        "# Secrets here are read by the tool at runtime — never commit this file.",
        "",
    ]
    for k, _label, _secret in KNOBS:
        v = kv.get(k, "")
        if v:
            lines.append(f"{k}={v}")
    # any extra keys we don't know about — preserve them at the end
    extras = [k for k in kv if k not in {k_ for k_, _, _ in KNOBS}]
    if extras:
        lines.append("")
        lines.append("# extra keys")
        for k in extras:
            lines.append(f"{k}={kv[k]}")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _mask(value: str, secret: bool) -> str:
    if not value:
        return f"[{tokens.DIM}]<not set>[/]"
    if not secret:
        return value
    if len(value) <= 6:
        return "•" * len(value)
    return value[:3] + "•" * (len(value) - 6) + value[-3:]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_show() -> int:
    load_settings()
    s = settings()
    kv = _read_kv()
    t = Table(title=f"[bold]config — by {BRAND}[/]", expand=False,
              border_style=tokens.DIM, header_style=f"bold {tokens.ACCENT}")
    t.add_column("key")
    t.add_column("value")
    t.add_column("source", style=tokens.DIM)
    for k, _label, secret in KNOBS:
        env_val = os.environ.get(k, "")
        cfg_val = kv.get(k, "")
        if env_val and env_val != cfg_val:
            value = _mask(env_val, secret)
            source = "shell env"
        elif cfg_val:
            value = _mask(cfg_val, secret)
            source = "config.env"
        else:
            value = _mask("", secret)
            source = "—"
        t.add_row(k, value, source)
    console.print(t)
    console.print(f"\n[{tokens.DIM}]config.env path: {user_config_path()}[/]")
    # Telegram session status
    sess = s.telethon_dir / f"{s.telegram_session_name}.session"
    if sess.exists():
        size = sess.stat().st_size
        console.print(f"[{tokens.OK}]✓ Telegram session present[/] "
                      f"[{tokens.DIM}]({sess}, {size:,} bytes)[/]")
    else:
        console.print(f"[{tokens.DIM}]Telegram session: not signed in yet[/]")
    return 0


def cmd_set(key: str, value: str) -> int:
    key = key.strip().upper()
    if key not in {k for k, _, _ in KNOBS}:
        console.print(f"[{tokens.WARN}]warn:[/] '{key}' is not a known key — "
                      f"it will still be stored but may not be used")
    kv = _read_kv()
    kv[key] = value.strip()
    p = _write_kv(kv)
    console.print(f"[{tokens.OK}]saved →[/] {p}  [{tokens.DIM}](key: {key})[/]")
    return 0


def cmd_unset(key: str) -> int:
    key = key.strip().upper()
    kv = _read_kv()
    if key not in kv:
        console.print(f"[{tokens.DIM}]not set — nothing to do[/]")
        return 0
    del kv[key]
    p = _write_kv(kv)
    console.print(f"[{tokens.OK}]removed →[/] {p}  [{tokens.DIM}](key: {key})[/]")
    return 0


def cmd_edit() -> int:
    p = user_config_path()
    if not p.exists():
        _write_kv(_read_kv())  # touch
    editor = os.environ.get("EDITOR") or os.environ.get("VISUAL") or ""
    if not editor:
        editor = "notepad" if sys.platform.startswith("win") else "vi"
    console.print(f"[{tokens.DIM}]opening {p} in {editor}…[/]")
    try:
        subprocess.run([editor, str(p)], check=False)
    except FileNotFoundError:
        console.print(f"[{tokens.BAD}]editor '{editor}' not found[/] — "
                      f"set $EDITOR or edit manually: {p}")
        return 2
    return 0


# --- Telegram wizard (does NOT touch the existing session) ----------------

async def _telegram_status() -> tuple[bool, str]:
    """Return (signed_in, label). NEVER mutates anything."""
    s = settings()
    if not s.has_telegram:
        return False, "TELEGRAM_API_ID/HASH/PHONE not set"
    try:
        from app.modules.telegram import telegram_session
        async with telegram_session() as c:
            if await c.is_user_authorized():
                me = await c.get_me()
                return True, (f"@{me.username or me.id} "
                              f"(+{me.phone or s.telegram_phone}, user_id={me.id})")
            return False, "creds set but session not signed in (run scripts/tg_send_code.py)"
    except Exception as e:
        return False, f"error checking session: {e}"


def cmd_telegram_status() -> int:
    load_settings()
    signed, label = asyncio.run(_telegram_status())
    if signed:
        console.print(f"[{tokens.OK}]✓ Telegram MTProto:[/] signed in as [bold]{label}[/]")
    else:
        console.print(f"[{tokens.WARN}]Telegram:[/] {label}")
    return 0


def cmd_telegram_wizard() -> int:
    """Edit TG creds + offer to (re)sign in. Existing session left alone unless user
    explicitly chooses 'reset'."""
    load_settings()
    console.print(f"\n[bold {tokens.ACCENT}]Telegram MTProto setup[/]")
    console.print(f"[{tokens.DIM}]session lives at %LOCALAPPDATA%\\mytools-osint\\telethon\\ "
                  f"and is preserved across this wizard.[/]\n")
    signed, label = asyncio.run(_telegram_status())
    if signed:
        console.print(f"[{tokens.OK}]✓ already signed in as[/] [bold]{label}[/]\n")
    else:
        console.print(f"[{tokens.WARN}]not signed in[/] — {label}\n")

    kv = _read_kv()
    api_id   = kv.get("TELEGRAM_API_ID")   or os.environ.get("TELEGRAM_API_ID", "")
    api_hash = kv.get("TELEGRAM_API_HASH") or os.environ.get("TELEGRAM_API_HASH", "")
    phone    = kv.get("TELEGRAM_PHONE")    or os.environ.get("TELEGRAM_PHONE", "")

    choice = questionary.select(
        "what now?",
        choices=[
            questionary.Choice("set / update api_id, api_hash, phone (does NOT touch existing session)",
                               value="edit"),
            questionary.Choice("start sign-in (sends code to your Telegram)",
                               value="signin", disabled=None if api_id and api_hash and phone else
                               "set api_id+api_hash+phone first"),
            questionary.Choice("show status",                                  value="status"),
            questionary.Choice("delete session (DANGER — requires re-sign-in)", value="reset"),
            questionary.Choice("back",                                          value="back"),
        ],
        style=QSTYLE, use_shortcuts=True,
    ).ask()

    if choice in (None, "back"):
        return 0
    if choice == "status":
        return cmd_telegram_status()
    if choice == "edit":
        new_id = questionary.text(
            "TELEGRAM_API_ID:", default=api_id or "",
            instruction=" (numeric, from my.telegram.org/apps)",
            style=QSTYLE,
            validate=lambda s: True if not s or s.strip().isdigit() else "must be numeric",
        ).ask() or api_id
        new_hash = questionary.password(
            "TELEGRAM_API_HASH:", style=QSTYLE,
        ).ask() or api_hash
        new_phone = questionary.text(
            "TELEGRAM_PHONE:", default=phone or "",
            instruction=" (E.164 — e.g. +14155550143)",
            style=QSTYLE,
        ).ask() or phone
        if new_id:
            kv["TELEGRAM_API_ID"] = new_id.strip()
        if new_hash:
            kv["TELEGRAM_API_HASH"] = new_hash.strip()
        if new_phone:
            kv["TELEGRAM_PHONE"] = new_phone.strip()
        p = _write_kv(kv)
        console.print(f"[{tokens.OK}]saved →[/] {p}")
        console.print(f"[{tokens.DIM}]session file untouched — "
                      f"sign-in still valid if previously authorised.[/]")
        return 0
    if choice == "signin":
        return _do_signin()
    if choice == "reset":
        confirm = questionary.confirm(
            "delete the existing Telegram session file? "
            "(you'll have to re-sign in, which sends a fresh code)",
            default=False, style=QSTYLE,
        ).ask()
        if not confirm:
            console.print(f"[{tokens.DIM}]cancelled[/]")
            return 0
        s = settings()
        sess = s.telethon_dir / f"{s.telegram_session_name}.session"
        for f in (sess, sess.with_suffix(".session-journal"),
                  s.telethon_dir / "_login_state.json"):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        console.print(f"[{tokens.OK}]session deleted[/] — re-run "
                      f"[bold]osint config telegram[/] and pick 'sign-in'")
        return 0
    return 0


def _do_signin() -> int:
    """Phase 1: send code. Phase 2: prompt for code (+ optional 2FA password)."""
    from app.modules.telegram import telegram_session

    async def phase1() -> str | None:
        async with telegram_session() as c:
            if await c.is_user_authorized():
                me = await c.get_me()
                console.print(f"[{tokens.OK}]already signed in as @{me.username or me.id}[/]")
                return "ALREADY"
            sent = await c.send_code_request(settings().telegram_phone)
            return sent.phone_code_hash

    try:
        hash_or_status = asyncio.run(phase1())
    except Exception as e:
        console.print(f"[{tokens.BAD}]failed to request code:[/] {e}")
        return 2
    if hash_or_status == "ALREADY":
        return 0
    console.print(f"[{tokens.OK}]Telegram sent a login code[/] to your account.")
    code = questionary.text(
        "enter the code from your Telegram app:", style=QSTYLE,
        validate=lambda s: True if s.strip() else "cannot be empty",
    ).ask()
    if not code:
        return 1
    password = questionary.password(
        "2FA password (leave empty if you don't use two-step verification):",
        style=QSTYLE,
    ).ask() or ""

    async def phase2() -> str:
        from telethon.errors import SessionPasswordNeededError
        async with telegram_session() as c:
            try:
                await c.sign_in(phone=settings().telegram_phone, code=code.strip(),
                                phone_code_hash=hash_or_status)
            except SessionPasswordNeededError:
                if not password:
                    return "PWNEEDED"
                await c.sign_in(password=password)
            except Exception as e:
                if password:
                    try:
                        await c.sign_in(password=password)
                    except Exception as e2:
                        return f"FAIL:{e2}"
                else:
                    return f"FAIL:{e}"
            if not await c.is_user_authorized() and password:
                await c.sign_in(password=password)
            if not await c.is_user_authorized():
                return "FAIL:not authorised after sign-in"
            me = await c.get_me()
            return f"OK:@{me.username or me.id} (+{me.phone or '?'}) user_id={me.id}"

    try:
        result = asyncio.run(phase2())
    except Exception as e:
        console.print(f"[{tokens.BAD}]sign-in failed:[/] {e}")
        return 2
    if result == "PWNEEDED":
        console.print(f"[{tokens.WARN}]2FA required[/] — re-run "
                      f"[bold]osint config telegram[/] → sign-in with a password")
        return 3
    if result.startswith("FAIL:"):
        console.print(f"[{tokens.BAD}]failed:[/] {result[5:]}")
        return 2
    console.print(f"[{tokens.OK}]signed in →[/] [bold]{result[3:]}[/]")
    return 0


# --- top-level wizard ------------------------------------------------------

def cmd_wizard() -> int:
    load_settings()
    console.print(f"\n[bold {tokens.ACCENT}]osint config[/] [{tokens.DIM}]· by {BRAND}[/]\n")
    while True:
        choice = questionary.select(
            "what would you like to do?",
            choices=[
                questionary.Choice("show current settings", value="show", shortcut_key="s"),
                questionary.Choice("Telegram MTProto wizard", value="telegram", shortcut_key="t"),
                questionary.Choice("set a value (key + value)", value="set", shortcut_key="e"),
                questionary.Choice("unset a value", value="unset", shortcut_key="u"),
                questionary.Choice("open config.env in $EDITOR", value="edit", shortcut_key="o"),
                questionary.Choice("done", value="done", shortcut_key="q"),
            ],
            style=QSTYLE, use_shortcuts=True,
        ).ask()
        if choice in (None, "done"):
            return 0
        if choice == "show":
            cmd_show()
        elif choice == "telegram":
            cmd_telegram_wizard()
        elif choice == "edit":
            cmd_edit()
        elif choice == "set":
            key = questionary.select(
                "which key?",
                choices=[questionary.Choice(f"{k}  — {label}", value=k)
                         for k, label, _ in KNOBS],
                style=QSTYLE,
            ).ask()
            if not key:
                continue
            secret = next((s for k, _, s in KNOBS if k == key), False)
            val = (questionary.password if secret else questionary.text)(
                f"new value for {key}:", style=QSTYLE,
            ).ask()
            if val is not None:
                cmd_set(key, val)
        elif choice == "unset":
            key = questionary.select(
                "which key to unset?",
                choices=[questionary.Choice(k, value=k) for k, _, _ in KNOBS],
                style=QSTYLE,
            ).ask()
            if key:
                cmd_unset(key)
