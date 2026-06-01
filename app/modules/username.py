"""Username enumeration. Sherlock-style — probes ~1000 sites concurrently."""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.runner import Runner
from app.core.types import Hit, Query, QueryKind

from .base import clean_username, stream_probes

NAME = "username"
_SITES_PATH = Path(__file__).resolve().parents[2] / "data" / "sites.json"
_cached_sites: list[dict[str, Any]] | None = None

# Tail-latency control for the ~1000-site fan-out.
#
# Root cause (measured, not guessed): the old defaults were timeout=10s + 1
# retry. The retry was pure tail-latency tax — a username site that times out
# or 403s essentially never flips to a real hit on a second attempt, yet the
# retry adds a full extra ~10s attempt. Worse, under a 1000-way fan-out a probe
# can sit *tens of seconds* queued in the shared HTTP/2 connection pool / event
# loop and still return a valid response far past the per-phase httpx timeout —
# instrumentation showed individual probes taking 30–42s while returning normal
# 2xx/4xx. Those zombie-tail probes serialise through the global gate and are
# what pushed a full octocat scan to 90–137s.
#
# Fix (surgical, hit-preserving):
#   * retries=0 — drop the latency-doubling retry (real blips still surface as
#     UNAVAILABLE, not ERROR, via classify_*).
#   * HARD per-probe wall-clock ceiling — the decisive lever. The per-phase
#     httpx timeout can't see pool/loop queueing; asyncio.wait_for can. Set well
#     ABOVE the phase timeout (20s) so it only reaps genuine zombies and does
#     NOT cut legitimately-slow big sites (Instagram/Pinterest/Roblox routinely
#     answer in 9–15s under load — an 8–9s cap measurably dropped those).
#   * per-phase timeout left at the global default (10s) for the same reason.
# The per-host gate in stream_probes is LEFT INTACT — it prevents 403/429 storms
# against sites sharing a WAF/CDN. We tune timeout/retry, not it.
_USERNAME_HARD_TIMEOUT = 20.0   # absolute wall-clock ceiling per probe

# The fan-out is ~1000 sites across ~917 DISTINCT hosts, so the per-host gate
# (per_host=4) almost never binds — wall-clock is dominated by the GLOBAL cap.
# The default http_concurrency (40) is tuned for the small per-kind module sets;
# for this one huge fan-out we raise the cap so it drains faster. The HTTP pool
# (max_connections >= 128) and the per-host gate both still hold, so this is
# faster WITHOUT re-introducing 403/429 storms.
_USERNAME_CONCURRENCY = 100


def load_sites() -> list[dict[str, Any]]:
    global _cached_sites
    if _cached_sites is None:
        try:
            raw = json.loads(_SITES_PATH.read_text(encoding="utf-8"))
            _cached_sites = raw.get("sites", [])
        except Exception:
            _cached_sites = []
    return _cached_sites


async def run(query: Query) -> AsyncIterator[Hit]:
    user = clean_username(query.value)
    if not user:
        return
    s = settings()
    sites = load_sites()
    async for h in stream_probes(
        sites, user, NAME,
        concurrency=max(s.http_concurrency, _USERNAME_CONCURRENCY),
        timeout=s.http_timeout_sec,
        # Username probes don't benefit from the retry: a timed-out/blocked site
        # almost never flips to a real hit on a second try, and the retry's
        # extra full-timeout attempt is what blew up tail latency. Real
        # transient blips are still captured as UNAVAILABLE (not ERROR).
        retries=0,
        # Hard wall-clock ceiling: reaps zombie probes stuck in the pool/loop
        # (the real tail) without cutting legitimately-slow big sites.
        hard_timeout=_USERNAME_HARD_TIMEOUT,
    ):
        yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.USERNAME], run)
