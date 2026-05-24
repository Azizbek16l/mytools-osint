"""Tor relay / exit-node check for an IP.

Uses the Tor Project's onionoo API — free, no key. Returns whether the IP
is currently (or was historically) a Tor relay, with role flags (Exit,
Guard, Authority, Stable).

Endpoint:   https://onionoo.torproject.org/details?search=<ip>&fields=…
Backed by:  https://check.torproject.org as a fallback (rate-limited HTML).
"""
from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "tor_check"

_ONIONOO = ("https://onionoo.torproject.org/details?search={ip}"
            "&fields=nickname,or_addresses,exit_addresses,flags,country,"
            "last_seen,first_seen,bandwidth_rate")


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.IP:
        return
    ip = (query.value or "").strip().split("/", 1)[0]
    if not _is_ip(ip):
        return
    url = _ONIONOO.format(ip=ip)
    try:
        client = await get_client()
        r = await client.get(url, timeout=8.0,
                             headers={"Accept": "application/json"})
    except Exception as e:
        yield Hit(module=NAME, source="onionoo", category="ip-reputation",
                  url=url, status=classify_exception(e),
                  title=ip, detail=f"{type(e).__name__}: {e}")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="onionoo", category="ip-reputation",
                  url=url, status=classify_http(r.status_code),
                  title=ip, detail=f"HTTP {r.status_code}")
        return
    try:
        data = r.json()
    except Exception as e:
        yield Hit(module=NAME, source="onionoo", category="ip-reputation",
                  url=url, status=HitStatus.ERROR,
                  title=ip, detail=f"bad json: {e}")
        return
    relays = data.get("relays") or []
    if not relays:
        yield Hit(module=NAME, source="onionoo", category="ip-reputation",
                  url=url, status=HitStatus.NO_DATA,
                  title=ip, detail="not a Tor relay (or no historical record)")
        return
    rel = relays[0]
    flags = rel.get("flags") or []
    is_exit = "Exit" in flags or bool(rel.get("exit_addresses"))
    nick = rel.get("nickname", "?")
    country = rel.get("country", "?").upper()
    last_seen = rel.get("last_seen", "?")
    detail = (f"Tor relay '{nick}' ({country}) | "
              f"flags: {', '.join(flags) or '-'} | last_seen={last_seen}")
    yield Hit(
        module=NAME, source="onionoo", category="ip-reputation",
        url=f"https://metrics.torproject.org/rs.html#details/{rel.get('fingerprint', '')}",
        status=HitStatus.FOUND, title=ip,
        detail=detail,
        severity=Severity.HIGH if is_exit else Severity.MEDIUM,
        extra={"nickname": nick, "country": country, "flags": flags,
               "is_exit": is_exit, "last_seen": last_seen,
               "first_seen": rel.get("first_seen"),
               "bandwidth_rate": rel.get("bandwidth_rate")},
    )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.IP], run)
