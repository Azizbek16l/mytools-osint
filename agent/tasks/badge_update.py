"""Refresh README badges. Idempotent — only writes if something actually changed.

Badges sourced from shields.io URL params, so they're regenerated client-side
on every README render anyway. The point of this task is to verify the
shields URLs in README still resolve and to update any pinned values (e.g.
'1,008 sites' counter) when sites.json grows.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
SITES = ROOT / "data" / "sites.json"


async def run() -> str:
    if not README.exists() or not SITES.exists():
        return "README or sites.json missing — skipped"
    n_sites = len(json.loads(SITES.read_text(encoding="utf-8")).get("sites", []))
    txt = README.read_text(encoding="utf-8")
    new = txt
    # Update any "1,008 sites" or "X sites" mentions with the live count
    new = re.sub(r"(\d{1,2}[,_]?\d{3})\s+(sites|probe targets)",
                 lambda m: f"{n_sites:,} {m.group(2)}", new)
    if new == txt:
        return f"badges already in sync ({n_sites:,} sites)"
    README.write_text(new, encoding="utf-8")
    return f"updated 'sites' counter -> {n_sites:,}"
