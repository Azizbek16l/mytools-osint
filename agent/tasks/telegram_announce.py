"""Post to the dedicated Telegram channel when a new release tag is detected.

Uses a SEPARATE bot token (TELEGRAM_AGENT_BOT_TOKEN) — has nothing to do with
the user's MTProto Telethon session under app/modules/telegram.py.

State is persisted in agent/data/last_announced_tag.txt so we never double-post.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "agent" / "data" / "last_announced_tag.txt"


def _latest_tag() -> str | None:
    try:
        r = subprocess.run(["git", "describe", "--tags", "--abbrev=0"],
                           cwd=ROOT, capture_output=True, text=True, check=True)
        return r.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def _release_notes(tag: str) -> str:
    """Pull the release notes for a tag from `gh release view`. Falls back to
    git log if the GH release doesn't exist yet."""
    try:
        r = subprocess.run(["gh", "release", "view", tag, "--json", "body", "-q", ".body"],
                           cwd=ROOT, capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    # fallback: short git log between tags
    try:
        prev = subprocess.run(["git", "describe", "--tags", "--abbrev=0", f"{tag}~"],
                              cwd=ROOT, capture_output=True, text=True, check=False)
        prev_tag = (prev.stdout or "").strip() or None
        rng = f"{prev_tag}..{tag}" if prev_tag else tag
        log = subprocess.run(["git", "log", rng, "--pretty=format:- %s"],
                             cwd=ROOT, capture_output=True, text=True, check=False)
        return (log.stdout or "")[:1500]
    except Exception:
        return ""


async def run() -> str:
    token = os.environ.get("TELEGRAM_AGENT_BOT_TOKEN", "").strip()
    channel = os.environ.get("TELEGRAM_AGENT_CHANNEL", "").strip()
    if not token or not channel:
        return "TELEGRAM_AGENT_BOT_TOKEN / CHANNEL not set — skipped"

    tag = _latest_tag()
    if not tag:
        return "no tags in repo — nothing to announce"
    if STATE.exists() and STATE.read_text(encoding="utf-8").strip() == tag:
        return f"already announced {tag}"

    notes = _release_notes(tag)
    msg_lines = [
        f"*mytools-osint {tag}* — by Bluetm.uz",
        "",
        f"📦  https://github.com/Azizbek16l/mytools-osint/releases/tag/{tag}",
    ]
    if notes:
        # truncate so we don't blow past Telegram's 4096-char limit
        msg_lines += ["", notes[:3500]]
    msg = "\n".join(msg_lines)

    try:
        r = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={
                "chat_id": channel,
                "text": msg,
                "parse_mode": "Markdown",
                "disable_web_page_preview": "false",
            },
            timeout=15,
        )
        if r.status_code != 200:
            return f"telegram error HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return f"telegram crash: {e}"

    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(tag, encoding="utf-8")
    return f"announced {tag} to {channel}"
