"""Phase 1 of Telegram MTProto sign-in: request the login code.

Telegram delivers the code to the existing Telegram client (mobile/desktop)
of TELEGRAM_PHONE — NOT via SMS. The phone_code_hash needed for phase 2 is
persisted to %LOCALAPPDATA%\\mytools-osint\\telethon\\_login_state.json.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings
from app.modules.telegram import telegram_session


async def main() -> int:
    s = settings()
    if not (s.telegram_api_id and s.telegram_api_hash and s.telegram_phone):
        print("Set TELEGRAM_API_ID, TELEGRAM_API_HASH, TELEGRAM_PHONE in .env first.",
              file=sys.stderr)
        return 2
    state_path = s.telethon_dir / "_login_state.json"
    async with telegram_session() as c:
        if await c.is_user_authorized():
            me = await c.get_me()
            print(f"already signed in as @{me.username or me.id} (+{me.phone})")
            return 0
        sent = await c.send_code_request(s.telegram_phone)
        state_path.write_text(
            json.dumps({"phone": s.telegram_phone, "phone_code_hash": sent.phone_code_hash}),
            encoding="utf-8",
        )
        kind = type(sent.type).__name__ if hasattr(sent, "type") else "code"
        print(f"OK — Telegram sent a code via {kind} to {s.telegram_phone}.", flush=True)
        print("Run: python scripts/tg_sign_in.py <code>  (or with --password for 2FA)", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
