"""Username enumeration. Sherlock-style — probes ~80+ sites concurrently."""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

from app.core.config import settings
from app.core.runner import Runner
from app.core.types import Hit, Query, QueryKind

from .base import clean_username, stream_probes

NAME = "username"
_SITES_PATH = Path(__file__).resolve().parents[2] / "data" / "sites.json"
_cached_sites: list[dict] | None = None


def load_sites() -> list[dict]:
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
        concurrency=s.http_concurrency,
        timeout=s.http_timeout_sec,
        retries=s.username_retry,
    ):
        yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.USERNAME], run)
