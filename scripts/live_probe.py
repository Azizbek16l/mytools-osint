"""One-off live probe — runs a query end-to-end against the network.

Usage:
  python scripts/live_probe.py <value>            # auto-detects kind
  python scripts/live_probe.py --kind email me@example.com
  python scripts/live_probe.py --kind phone +998901234567
"""
from __future__ import annotations

import argparse
import asyncio
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import load_settings
from app.core.http import close_client
from app.core.runner import runner
from app.core.types import HitStatus, Query, QueryKind

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_PHONE_RE = re.compile(r"^\+?[0-9 ()\-]{6,}$")


def detect_kind(value: str) -> QueryKind:
    v = value.strip()
    if _EMAIL_RE.match(v):
        return QueryKind.EMAIL
    digits = re.sub(r"\D", "", v)
    if _PHONE_RE.match(v) and 6 <= len(digits) <= 16:
        return QueryKind.PHONE
    if v.startswith("@"):
        return QueryKind.USERNAME
    if "." in v and "/" not in v and "@" not in v:
        return QueryKind.DOMAIN
    return QueryKind.USERNAME


async def main(value: str, kind: QueryKind) -> int:
    load_settings()
    r = runner()
    q = Query(kind=kind, value=value)
    found_total = 0
    errors = 0
    total = 0
    positives: list = []

    def status_marker(h) -> str:
        return {
            HitStatus.FOUND: "OK ",
            HitStatus.NOT_FOUND: ".. ",
            HitStatus.UNCERTAIN: "?  ",
            HitStatus.ERROR: "ER ",
            HitStatus.RATELIMITED: "RL ",
            HitStatus.SKIPPED: "-- ",
        }.get(h.status, "?  ")

    async def on_hit(h) -> None:
        nonlocal found_total, errors, total
        total += 1
        if h.status == HitStatus.FOUND:
            found_total += 1
            positives.append(h)
            url = (h.url or "").replace("https://", "")
            print(f"  [{status_marker(h)}] {h.module:18} {h.source:28} {h.detail[:80]}", flush=True)
            if url:
                print(f"        {url}", flush=True)
        elif h.status == HitStatus.RATELIMITED:
            print(f"  [{status_marker(h)}] {h.module:18} {h.source:28} {h.detail}", flush=True)
        elif h.status == HitStatus.SKIPPED and "breach" in (h.category or ""):
            # breach checks are noteworthy even when skipped (key missing)
            print(f"  [{status_marker(h)}] {h.module:18} {h.source:28} {h.detail}", flush=True)
        elif h.status == HitStatus.NOT_FOUND and "breach" in (h.category or ""):
            # surface the "clean" breach results — they are useful
            print(f"  [{status_marker(h)}] {h.module:18} {h.source:28} {h.detail}", flush=True)
        elif h.status == HitStatus.ERROR:
            errors += 1

    print(f"Probing {kind.value}: {value}\n", flush=True)
    result = await r.run(q, on_hit=on_hit)
    await close_client()
    print(f"\nDone: {result.found}/{result.total} positive, {len(result.errors)} errors, {result.duration_ms} ms")
    return 0 if result.found > 0 else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("value")
    ap.add_argument("--kind", choices=[k.value for k in QueryKind], default=None)
    args = ap.parse_args()
    k = QueryKind(args.kind) if args.kind else detect_kind(args.value)
    raise SystemExit(asyncio.run(main(args.value, k)))
