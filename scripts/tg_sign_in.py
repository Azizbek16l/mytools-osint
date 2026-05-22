"""Phase 2 of Telegram MTProto sign-in: complete with the code (and 2FA password).

Reads phone_code_hash that phase 1 (tg_send_code.py) saved, then calls sign_in.
On success the session file under telethon_dir is authorised and persistent.

Usage:
  python scripts/tg_sign_in.py <code> [--password <2fa>]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from telethon.errors import SessionPasswordNeededError

from app.core.config import settings
from app.modules.telegram import telegram_session


async def main(code: str | None, password: str | None) -> int:
    s = settings()
    state_path = s.telethon_dir / "_login_state.json"
    async with telegram_session() as c:
        if await c.is_user_authorized():
            me = await c.get_me()
            print(f"already signed in as @{me.username or me.id} (+{me.phone})")
            state_path.unlink(missing_ok=True)
            return 0
        # If code is supplied, try the code step first
        if code:
            if not state_path.exists():
                print("No login state found — run scripts/tg_send_code.py first.",
                      file=sys.stderr)
                return 2
            state = json.loads(state_path.read_text(encoding="utf-8"))
            try:
                await c.sign_in(
                    phone=state["phone"], code=code,
                    phone_code_hash=state["phone_code_hash"],
                )
            except SessionPasswordNeededError:
                if not password:
                    print("PASSWORD_NEEDED — re-run with --password <your 2FA password>",
                          file=sys.stderr)
                    return 3
                await c.sign_in(password=password)
            except Exception as e:
                # Code might already be consumed by a prior attempt — fall through to password if provided
                if password:
                    print(f"code step failed ({e}); trying password-only step…", file=sys.stderr)
                else:
                    raise
        if not await c.is_user_authorized() and password:
            await c.sign_in(password=password)
        if not await c.is_user_authorized():
            print("Still not authorized — code may be expired/consumed. "
                  "Run tg_send_code.py to request a fresh code.", file=sys.stderr)
            return 4
        me = await c.get_me()
        print(f"OK — signed in as @{me.username or me.id} (+{me.phone}) "
              f"user_id={me.id} premium={getattr(me,'premium',False)}",
              flush=True)
        state_path.unlink(missing_ok=True)
        return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("code", nargs="?", default=None,
                    help="Login code Telegram sent (omit to do 2FA password step only)")
    ap.add_argument("--password", default=None, help="Two-factor password if enabled")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(main(args.code, args.password)))
