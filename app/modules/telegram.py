"""Telegram OSINT via Telethon (MTProto user-bot session) + t.me web probes.

The Telethon userbot logs in as YOUR personal Telegram account, so anything you
can see in your TG client (public usernames, joined channels) can be resolved.
For phone→username we use temporary contact import (auto-deleted) — Telegram
returns the linked user if the number is registered.

If TELEGRAM_API_ID / TELEGRAM_API_HASH / TELEGRAM_PHONE are not set, the module
gracefully degrades to t.me/@<username> HTML probes only.
"""
from __future__ import annotations

import asyncio
import random
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from telethon import TelegramClient, errors
from telethon.tl import functions, types

from app.core.config import settings
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

from .base import clean_phone, clean_username

NAME = "telegram"

_client_lock = asyncio.Lock()
_client: TelegramClient | None = None


async def _ensure_client() -> TelegramClient | None:
    """Return a started Telethon client, or None if not configured / not signed in.

    First-run sign-in must be done out-of-band: run scripts/telegram_login.py once.
    """
    global _client
    s = settings()
    if not s.has_telegram:
        return None
    async with _client_lock:
        if _client is not None and _client.is_connected():
            return _client
        session_path = str(s.telethon_dir / s.telegram_session_name)
        c = TelegramClient(session_path, s.telegram_api_id, s.telegram_api_hash)
        try:
            await c.connect()
        except Exception:
            return None
        if not await c.is_user_authorized():
            await c.disconnect()
            return None
        _client = c
        return _client


async def _tg_username_probe(username: str) -> AsyncIterator[Hit]:
    """Probe @username via Telethon if available, else fallback to t.me."""
    c = await _ensure_client()
    if c is not None:
        try:
            res = await c(functions.contacts.ResolveUsernameRequest(username=username))
            user = next(iter(res.users), None)
            chat = next(iter(res.chats), None)
            if user:
                yield Hit(
                    module=NAME, source="Telegram", category="messaging",
                    status=HitStatus.FOUND,
                    title=f"@{username} → user {user.id}",
                    url=f"https://t.me/{username}",
                    detail=f"first={getattr(user,'first_name','')} last={getattr(user,'last_name','')} "
                           f"bot={getattr(user,'bot',False)} verified={getattr(user,'verified',False)}",
                    severity=Severity.HIGH,
                    extra={"user_id": user.id, "is_bot": getattr(user, "bot", False),
                           "verified": getattr(user, "verified", False),
                           "premium": getattr(user, "premium", False)},
                )
                return
            if chat:
                yield Hit(
                    module=NAME, source="Telegram", category="messaging",
                    status=HitStatus.FOUND,
                    title=f"@{username} → channel/chat {chat.id}",
                    url=f"https://t.me/{username}",
                    detail=f"title={getattr(chat,'title','')} participants={getattr(chat,'participants_count','?')}",
                    severity=Severity.HIGH,
                    extra={"chat_id": chat.id, "title": getattr(chat, "title", "")},
                )
                return
        except errors.UsernameNotOccupiedError:
            yield Hit(module=NAME, source="Telegram", category="messaging",
                      status=HitStatus.NOT_FOUND, detail="username free")
            return
        except errors.FloodWaitError as e:
            yield Hit(module=NAME, source="Telegram", category="messaging",
                      status=HitStatus.RATELIMITED, detail=f"FloodWait {e.seconds}s",
                      severity=Severity.MEDIUM)
            return
        except Exception as e:
            yield Hit(module=NAME, source="Telegram", category="messaging",
                      status=HitStatus.ERROR, detail=str(e))

    # fallback: t.me HTML
    url = f"https://t.me/{username}"
    try:
        client = await get_client()
        r = await client.get(url)
        body = r.text or ""
        if "tgme_page_extra" in body or "<meta property=\"og:title\"" in body:
            yield Hit(module=NAME, source="t.me", category="messaging",
                      status=HitStatus.FOUND, url=url, detail="t.me page exists",
                      severity=Severity.MEDIUM)
        else:
            yield Hit(module=NAME, source="t.me", category="messaging",
                      status=HitStatus.NOT_FOUND, url=url, detail="no t.me preview")
    except Exception as e:
        yield Hit(module=NAME, source="t.me", status=HitStatus.ERROR, detail=str(e))


async def lookup_phone(num: str) -> AsyncIterator[Hit]:
    """Phone → Telegram user resolution via temporary contact import.

    The contact is deleted from your address book immediately after lookup.
    Returns Hit(SKIPPED) if Telethon isn't configured.
    """
    c = await _ensure_client()
    if c is None:
        yield Hit(
            module=NAME, source="Telegram MTProto", category="messaging",
            status=HitStatus.SKIPPED,
            detail="set TELEGRAM_API_ID/HASH/PHONE and run scripts/telegram_login.py once",
        )
        return
    phone = clean_phone(num)
    if not phone:
        return
    digits = phone.lstrip("+")
    try:
        result = await c(functions.contacts.ImportContactsRequest(
            contacts=[types.InputPhoneContact(
                client_id=random.randint(0, 2**31 - 1),
                phone=phone,
                first_name="lookup",
                last_name="probe",
            )]
        ))
        if not result.users:
            yield Hit(module=NAME, source="Telegram MTProto", category="messaging",
                      status=HitStatus.NOT_FOUND, detail="phone not on Telegram (or hidden)")
            return
        user = result.users[0]
        username = getattr(user, "username", None)
        yield Hit(
            module=NAME, source="Telegram MTProto", category="messaging",
            status=HitStatus.FOUND,
            title=f"+{digits} → @{username or user.id}",
            url=f"https://t.me/{username}" if username else "",
            detail=f"user_id={user.id} first={getattr(user,'first_name','')} "
                   f"last={getattr(user,'last_name','')} username={username}",
            severity=Severity.HIGH,
            extra={
                "user_id": user.id, "username": username,
                "first_name": getattr(user, "first_name", ""),
                "last_name": getattr(user, "last_name", ""),
                "premium": getattr(user, "premium", False),
                "verified": getattr(user, "verified", False),
            },
        )
        # clean up: delete the contact we imported
        try:
            await c(functions.contacts.DeleteContactsRequest(id=[user.id]))
        except Exception:
            pass
    except errors.FloodWaitError as e:
        yield Hit(module=NAME, source="Telegram MTProto", category="messaging",
                  status=HitStatus.RATELIMITED, detail=f"FloodWait {e.seconds}s",
                  severity=Severity.MEDIUM)
    except Exception as e:
        yield Hit(module=NAME, source="Telegram MTProto", category="messaging",
                  status=HitStatus.ERROR, detail=str(e))


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind == QueryKind.TELEGRAM or query.kind == QueryKind.USERNAME:
        user = clean_username(query.value)
        if user:
            async for h in _tg_username_probe(user):
                yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.TELEGRAM], run)


@asynccontextmanager
async def telegram_session() -> Any:
    """Standalone session context — used by scripts/telegram_login.py."""
    s = settings()
    if not s.telegram_api_id or not s.telegram_api_hash:
        raise RuntimeError("TELEGRAM_API_ID and TELEGRAM_API_HASH must be set")
    session_path = str(s.telethon_dir / s.telegram_session_name)
    c = TelegramClient(session_path, s.telegram_api_id, s.telegram_api_hash)
    await c.connect()
    try:
        yield c
    finally:
        await c.disconnect()
