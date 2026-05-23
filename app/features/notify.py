"""Send notifications about new watchlist findings.

Primary channel: Telegram (Saved Messages, via the existing Telethon userbot
session — same one used by app.modules.telegram). Fallback channel: a JSON
log under the user data dir.

This module never raises. send_to_self returns True iff the message reached
Telegram; otherwise it returns False and logs the failure locally. The caller
records the outcome in the DB.

Tests must NEVER touch the network. The Telegram dependency is injected — the
default factory looks up the real Telethon client, but tests pass their own
factory that returns a fake.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from app.core.config import settings
from app.core.types import Hit

logger = logging.getLogger(__name__)

# ---- Protocols (injectable for tests) --------------------------------------


class TelegramLike(Protocol):
    """The slice of Telethon's TelegramClient we actually use."""

    async def get_me(self) -> Any: ...
    async def send_message(self, entity: Any, message: str, **kwargs: Any) -> Any: ...


# A factory returns a connected client (or None when Telegram is not available).
# Production wires this to app.modules.telegram._ensure_client; tests inject a fake.
ClientFactory = Callable[[], Awaitable[TelegramLike | None]]


async def _default_client_factory() -> TelegramLike | None:
    """Reuse the singleton Telethon client maintained by app.modules.telegram.

    Local import to avoid any chance of pulling Telethon into test runs that
    inject their own factory.
    """
    try:
        from app.modules import telegram as tg_mod
        return await tg_mod._ensure_client()
    except Exception as e:  # pragma: no cover — defensive
        logger.warning("telegram client unavailable: %s", e)
        return None


# ---- Public API ------------------------------------------------------------


async def send_to_self(
    message: str,
    *,
    client_factory: ClientFactory = _default_client_factory,
) -> bool:
    """Send a markdown-formatted message to the user's own Telegram (Saved Messages).

    Returns True on success. Logs and returns False on any failure — never raises.
    The fallback log is written regardless (so we always have a local record).
    """
    try:
        client = await client_factory()
    except Exception as e:
        logger.warning("notify: client_factory raised: %s", e)
        client = None

    if client is None:
        _write_fallback(message, reason="telegram_unavailable")
        return False

    try:
        me = await client.get_me()
        if me is None:
            _write_fallback(message, reason="get_me_returned_none")
            return False
        # Telethon: passing the user's own entity == Saved Messages.
        await client.send_message(me, message, parse_mode="md")
        return True
    except Exception as e:
        logger.warning("notify: send_message failed: %s", e)
        _write_fallback(message, reason=f"send_failed:{type(e).__name__}")
        return False


def format_watchlist_message(value: str, new_hits: list[Hit]) -> str:
    """Build the markdown body for a watchlist notification.

    Caps the bulleted list at 20 entries — past that we summarise. Telegram has
    a 4096-char message limit and these notifications go to the user's pocket;
    they should be skim-able, not a wall of text.
    """
    safe_value = _md_escape(value)
    head = f"\U0001f50d *mytools-osint* — new findings on *{safe_value}*\n"
    if not new_hits:
        return head + "\n(no new informative hits)"

    cap = 20
    lines: list[str] = []
    for h in new_hits[:cap]:
        label = h.title or h.source
        body = f"• {_md_escape(h.source)} — {_md_escape(label)}"
        if h.url:
            body += f" ({h.url})"
        lines.append(body)
    if len(new_hits) > cap:
        lines.append(f"… and {len(new_hits) - cap} more")

    tail = "\n\nRun `osint history` to see full results."
    return head + "\n" + "\n".join(lines) + tail


# ---- internals -------------------------------------------------------------


def _md_escape(s: str) -> str:
    """Escape the subset of MarkdownV1 we care about for safe interpolation."""
    return (
        s.replace("\\", "\\\\")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("`", "\\`")
        .replace("[", "\\[")
    )


def _fallback_log_path() -> Path:
    return settings().data_dir / "notifications.log"


def _write_fallback(message: str, *, reason: str) -> None:
    """Append a JSON line to the local fallback log. Best-effort — never raises."""
    try:
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "reason": reason,
            "message": message,
        }
        path = _fallback_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:  # pragma: no cover — defensive
        logger.warning("notify: fallback log write failed: %s", e)
