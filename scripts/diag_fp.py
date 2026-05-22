"""Diagnostic: direct-probe the known FP suspects to verify the FP-guard fires."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.modules.base import probe_site
from app.modules.username import load_sites


SUSPECTS = (
    "ArtBreeder", "Duolingo", "Bio Sites", "Destructoid", "MAGABOOK",
    "secure_donation", "Wireclub", "game_debate", "Steam Group", "Telegram (web)",
)


async def main() -> int:
    all_sites = load_sites()
    subset = [s for s in all_sites if s["name"] in SUSPECTS]
    for s in subset:
        try:
            h = await probe_site(s, "lazizanizomiddinova", "username")
        except Exception as e:
            print(f"{s['name']:22}  ERROR  {e}")
            continue
        print(f"{s['name']:22}  status={h.status.value:12}  detail={h.detail[:80]}")
        print(f"  extra={list(h.extra.keys())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
