"""IP / domain quick OSINT.

Sources:
  - IPinfo (key required) — ASN, geo, company, anycast, privacy flags
  - reverse DNS
  - DNS A/AAAA/MX/TXT lookup if input is a domain
"""
from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator

import dns.asyncresolver

from app.core.config import settings
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "ip"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _ipinfo(ip: str) -> Hit:
    s = settings()
    if not s.has_ipinfo:
        return Hit(module=NAME, source="IPinfo", category="ip",
                   status=HitStatus.SKIPPED, detail="set IPINFO_API_TOKEN")
    try:
        client = await get_client()
        r = await client.get(
            f"https://ipinfo.io/{ip}",
            headers={"Authorization": f"Bearer {s.ipinfo_api_token}",
                     "Accept": "application/json"},
        )
        if r.status_code == 200:
            data = r.json()
            return Hit(
                module=NAME, source="IPinfo", category="ip",
                status=HitStatus.FOUND, title=ip,
                detail=f"{data.get('city','')} {data.get('country','')} — "
                       f"{data.get('org','')}",
                extra=data, severity=Severity.MEDIUM,
            )
        return Hit(module=NAME, source="IPinfo", status=HitStatus.UNCERTAIN,
                   detail=f"HTTP {r.status_code}")
    except Exception as e:
        return Hit(module=NAME, source="IPinfo", status=HitStatus.ERROR, detail=str(e))


async def _ptr(ip: str) -> Hit:
    try:
        ans = await dns.asyncresolver.resolve_address(ip, lifetime=5)
        names = sorted({str(a).rstrip(".") for a in ans})
        return Hit(module=NAME, source="rDNS", category="ip",
                   status=HitStatus.FOUND if names else HitStatus.NOT_FOUND,
                   detail=", ".join(names[:4]), extra={"ptr": names})
    except Exception as e:
        return Hit(module=NAME, source="rDNS", status=HitStatus.ERROR, detail=str(e))


async def _domain(name: str) -> AsyncIterator[Hit]:
    for rtype in ("A", "AAAA", "MX", "TXT", "NS"):
        try:
            ans = await dns.asyncresolver.resolve(name, rtype, lifetime=5)
            vals = [str(a).strip(".") for a in ans]
            if vals:
                yield Hit(
                    module=NAME, source=f"DNS:{rtype}", category="dns",
                    status=HitStatus.FOUND, title=name,
                    detail=", ".join(vals[:6]),
                    extra={rtype: vals},
                )
        except Exception as e:
            yield Hit(module=NAME, source=f"DNS:{rtype}", category="dns",
                      status=HitStatus.NOT_FOUND, detail=str(e))


async def run(query: Query) -> AsyncIterator[Hit]:
    value = query.value.strip()
    if not value:
        return
    if _is_ip(value):
        yield await _ipinfo(value)
        yield await _ptr(value)
    elif query.kind == QueryKind.DOMAIN or "." in value:
        async for h in _domain(value):
            yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.IP, QueryKind.DOMAIN], run)
