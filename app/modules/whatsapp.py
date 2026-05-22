"""WhatsApp existence probe.

Note: WhatsApp does not expose a reliable public 'is this number registered' API.
The wa.me deep link always serves a generic landing page; the only signal is
that an invalid number returns a different page. For deeper checks (last seen,
profile pic), you need a logged-in WhatsApp Web/Business API session — out of
scope for this tool.
"""
from __future__ import annotations

from collections.abc import AsyncIterator

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

from .base import clean_phone

NAME = "whatsapp"


async def run(query: Query) -> AsyncIterator[Hit]:
    num = clean_phone(query.value).lstrip("+")
    if not num:
        return
    url = f"https://wa.me/{num}"
    try:
        client = await get_client()
        r = await client.get(url)
        body = (r.text or "").lower()
        if "phone number shared via url is invalid" in body:
            yield Hit(module=NAME, source="wa.me", category="messaging",
                      status=HitStatus.NOT_FOUND, url=url,
                      detail="invalid per wa.me redirect")
            return
        if r.status_code == 200:
            yield Hit(
                module=NAME, source="wa.me", category="messaging",
                status=HitStatus.UNCERTAIN, url=url,
                detail="wa.me deep link reachable (deep-existence requires logged-in WA session)",
                severity=Severity.LOW,
            )
            return
        yield Hit(module=NAME, source="wa.me", status=HitStatus.UNCERTAIN,
                  url=url, detail=f"HTTP {r.status_code}")
    except Exception as e:
        yield Hit(module=NAME, source="wa.me", status=HitStatus.ERROR, detail=str(e))


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.WHATSAPP], run)
