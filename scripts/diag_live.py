"""Render the streaming Group once with mock hits to verify the layout displays."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rich.console import Console

from app.core.types import Hit, HitStatus, Query, QueryKind
from app.ui.interactive import _render_group


def main() -> int:
    q = Query(kind=QueryKind.DOMAIN, value="bluetm.uz")
    hits = [
        Hit(module="domain", source="DNS:A", category="dns",
            status=HitStatus.FOUND, detail="216.198.79.1", url=""),
        Hit(module="domain", source="DNS:NS", category="dns",
            status=HitStatus.FOUND, detail="ns.cloudflare.com", url=""),
        Hit(module="domain", source="urlscan.io", category="recon",
            status=HitStatus.FOUND, detail="scanned 2026-05-18  ip=185.203.238.165",
            url="https://urlscan.io/result/019e3a"),
        Hit(module="discovery", source="Dork:inurl", category="dork",
            status=HitStatus.FOUND, detail="open in browser to pivot",
            url="https://www.google.com/search?q=site%3Abluetm.uz"),
    ]
    console = Console(force_terminal=True)
    console.print(_render_group(q, hits, 12345, done=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
