"""RIPEstat Data API — authoritative ASN/prefix/whois/routing (v4.2).

Best free network-intel source on the internet. No key, no signup, no per-day
cap (8 concurrent req per IP). 30+ data calls. We hit the most-useful subset:
- network-info   → prefix + ASN holding this IP
- prefix-overview → covering prefix + visibility + status
- whois          → routing-registry + IRR-objects (better than legacy WHOIS)
- abuse-contact-finder → abuse@ email for reporting
- announced-prefixes → all prefixes announced by an AS (for ASN queries)

Endpoint: https://stat.ripe.net/data/{call}/data.json?resource={value}
"""
from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "ripestat"
_BASE = "https://stat.ripe.net/data/{call}/data.json"
_TIMEOUT = 10.0


async def _call(client, call: str, resource: str) -> dict | None:
    url = _BASE.format(call=call) + f"?resource={resource}&sourceapp=mytools-osint"
    try:
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"accept": "application/json"})
    except Exception:
        return None
    if r.status_code != 200:
        return None
    try:
        return r.json()
    except Exception:
        return None


async def _enrich_ip(ip: str) -> AsyncIterator[Hit]:
    client = await get_client()
    ni, ov, ab = await asyncio.gather(
        _call(client, "network-info", ip),
        _call(client, "prefix-overview", ip),
        _call(client, "abuse-contact-finder", ip),
    )
    asn = None
    prefix = None
    if isinstance(ni, dict):
        d = ni.get("data") or {}
        asn = (d.get("asns") or [None])[0] if d.get("asns") else None
        prefix = d.get("prefix")
    holder = None
    if isinstance(ov, dict):
        d = ov.get("data") or {}
        holder = d.get("asns", [{}])[0].get("holder") if d.get("asns") else None
        prefix = prefix or d.get("resource")
    abuse_email = None
    if isinstance(ab, dict):
        d = ab.get("data") or {}
        contacts = d.get("abuse_contacts") or []
        abuse_email = contacts[0] if contacts else None

    if asn or prefix or holder:
        detail_bits = []
        if asn:    detail_bits.append(f"AS{asn}")
        if holder: detail_bits.append(holder)
        if prefix: detail_bits.append(prefix)
        if abuse_email: detail_bits.append(f"abuse={abuse_email}")
        yield Hit(module=NAME, source="RIPEstat",
                  category="ip",
                  url=f"https://stat.ripe.net/{ip}",
                  status=HitStatus.FOUND,
                  title=f"{ip} → AS{asn or '?'} {holder or ''}".strip(),
                  detail=" · ".join(detail_bits),
                  severity=Severity.INFO,
                  extra={"asn": asn, "prefix": prefix, "holder": holder,
                         "abuse_email": abuse_email})
    else:
        yield Hit(module=NAME, source="RIPEstat", category="ip",
                  url=f"https://stat.ripe.net/{ip}",
                  status=HitStatus.NO_DATA,
                  detail="no RIPE data for this IP")


async def _enrich_domain(domain: str) -> AsyncIterator[Hit]:
    # Resolve domain → A records, enrich each unique IP (cap 4).
    try:
        import dns.asyncresolver
        ans = await dns.asyncresolver.resolve(domain, "A", lifetime=5.0)
        ips = sorted({str(r) for r in ans})[:4]
    except Exception as e:
        yield Hit(module=NAME, source="RIPEstat", category="dns",
                  status=HitStatus.ERROR,
                  detail=f"dns resolve failed: {e}")
        return
    for ip in ips:
        async for h in _enrich_ip(ip):
            yield h


async def _run(query: Query) -> AsyncIterator[Hit]:
    if query.kind == QueryKind.IP:
        try:
            ipaddress.ip_address(query.value)
        except ValueError:
            return
        async for h in _enrich_ip(query.value):
            yield h
    elif query.kind == QueryKind.DOMAIN:
        async for h in _enrich_domain(query.value):
            yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.IP, QueryKind.DOMAIN], _run)
