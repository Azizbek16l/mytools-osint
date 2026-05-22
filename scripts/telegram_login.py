"""Interactive one-time Telegram MTProto sign-in.

Run once to authorise the userbot session. Telegram will SMS a code to your
TELEGRAM_PHONE; enter it at the prompt. The session is persisted at
%LOCALAPPDATA%\\mytools-osint\\telethon\\<TELEGRAM_SESSION_NAME>.session — guard
it like a password (anyone with this file has YOUR Telegram account access).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.core.config import settings  # noqa: E402
from app.modules.telegram import telegram_session  # noqa: E402


async def main() -> int:
    s = settings()
    if not (s.telegram_api_id and s.telegram_api_hash and s.telegram_phone):
        print("Set TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_PHONE in .env first.", file=sys.stderr)
        print("Get them from https://my.telegram.org/apps", file=sys.stderr)
        return 2
    async with telegram_session() as c:
        if await c.is_user_authorized():
            me = await c.get_me()
            print(f"already signed in as @{me.username or me.id} (+{me.phone})")
            return 0
        await c.send_code_request(s.telegram_phone)
        code = input(f"Enter SMS code sent to {s.telegram_phone}: ").strip()
        try:
            await c.sign_in(phone=s.telegram_phone, code=code)
        except Exception as e:
            if "two-factor" in str(e).lower() or "password" in str(e).lower():
                pw = input("2FA password: ")
                await c.sign_in(password=pw)
            else:
                raise
        me = await c.get_me()
        print(f"signed in as @{me.username or me.id} (+{me.phone})")
        return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
