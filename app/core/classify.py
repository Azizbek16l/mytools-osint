"""HTTP / exception → HitStatus classifier.

Keeps the "is this our bug or theirs?" decision in one place so we render and
count outcomes consistently across modules.
"""
from __future__ import annotations

import asyncio

import httpx

from app.core.types import HitStatus

# Upstream is unhealthy (Cloudflare 5xx codes incl.). We *did* reach them.
_UPSTREAM_DOWN = {500, 502, 503, 504, 521, 522, 523, 524, 525, 530}


def classify_http(status_code: int) -> HitStatus:
    """Map an HTTP status to a HitStatus.

    Callers should still post-classify 200 + empty-body as NO_DATA — that
    distinction lives in the source-specific logic, not here.
    """
    if status_code == 200:
        return HitStatus.FOUND
    if status_code == 429:
        return HitStatus.RATELIMITED
    if status_code in _UPSTREAM_DOWN:
        return HitStatus.UNAVAILABLE
    if status_code in (401, 403):
        # auth required / geofenced / quota — the source is up, we just can't
        # read it right now. UNAVAILABLE, not ERROR (it's not our bug).
        return HitStatus.UNAVAILABLE
    if status_code in (404, 410):
        # third-party source has no record for this target → "no data", not a
        # tool bug. (e.g. HackerTarget 404 for an unindexed domain.)
        return HitStatus.NO_DATA
    if status_code in (400, 422):
        # malformed request shape (bad URL / unsupported params) — that's ours.
        return HitStatus.ERROR
    if 400 <= status_code < 500:
        # other 4xx (405/406/451/…) — upstream rejected us but isn't down.
        return HitStatus.UNAVAILABLE
    return HitStatus.UNCERTAIN


def classify_exception(e: BaseException) -> HitStatus:
    """Map a transport-level exception to a HitStatus.

    Timeouts / connection resets / protocol errors are upstream issues, not
    bugs in our code — surface them as UNAVAILABLE so they don't pollute the
    "errors" counter.
    """
    if isinstance(e, (
        asyncio.TimeoutError,
        httpx.TimeoutException,
        httpx.ConnectError,
        httpx.ReadError,
        httpx.RemoteProtocolError,
        httpx.NetworkError,
        ConnectionResetError,
        ConnectionAbortedError,
    )):
        return HitStatus.UNAVAILABLE
    return HitStatus.ERROR
