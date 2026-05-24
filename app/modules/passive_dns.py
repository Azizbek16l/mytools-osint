"""Passive DNS — historical resolution data from FREE public sources.

For a DOMAIN: "what has this hostname resolved to over time, including
yesterday's wildcard sinkhole and last year's S3 origin?"
For an IP: "what hostnames have ever pointed here? what's hosted on this
neighbour IP?"

Sources (all free, key-optional):
  - HackerTarget reverse-DNS (`/reversedns/` and `/dns-host-records/`)
                 free, no key, ~50/day soft limit
  - AlienVault OTX passive DNS (`/api/v1/indicators/{ip|domain}/passive_dns`)
                 free, no key required for read
  - Mnemonic PDNS (`/passivedns/v3/...`)
                 free tier, no key for low-volume lookups
  - CIRCL passive DNS (`https://www.circl.lu/pdns/query/{value}`)
                 free with HTTP basic auth (CIRCL_PDNS_AUTH env, format user:pass)

Output: one Hit per (resolved_value, source). Useful for incident-pivot:
"the IP we found in malware traffic — what other hostnames pointed there?"
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
from collections.abc import AsyncIterator

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "passive_dns"

_TIMEOUT = 10.0
_MAX_ROWS_PER_SOURCE = 60


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


async def _hackertarget(value: str) -> AsyncIterator[Hit]:
    # IP → reversedns, domain → dns-host-records (covers a/aaaa/mx)
    endpoint = ("reversedns" if _is_ip(value) else "dns-host-records")
    url = f"https://api.hackertarget.com/{endpoint}/?q={value}"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT)
    except Exception as e:
        yield Hit(module=NAME, source="HackerTarget", category="passive-dns",
                  url=url, status=classify_exception(e),
                  title=value, detail=f"{type(e).__name__}: {e}")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="HackerTarget", category="passive-dns",
                  url=url, status=classify_http(r.status_code),
                  title=value, detail=f"HTTP {r.status_code}")
        return
    text = (r.text or "").strip()
    if "error" in text.lower()[:80] or "API count" in text:
        yield Hit(module=NAME, source="HackerTarget", category="passive-dns",
                  url=url, status=HitStatus.RATELIMITED, title=value,
                  detail=text[:120])
        return
    if not text:
        yield Hit(module=NAME, source="HackerTarget", category="passive-dns",
                  url=url, status=HitStatus.NO_DATA, title=value,
                  detail="no records")
        return
    lines = [ln for ln in text.splitlines() if ln.strip()][:_MAX_ROWS_PER_SOURCE]
    for line in lines:
        parts = [p.strip() for p in line.split(",")]
        target = parts[0] if parts else line
        rest = ", ".join(parts[1:]) if len(parts) > 1 else ""
        yield Hit(
            module=NAME, source="HackerTarget", category="passive-dns",
            url=url, status=HitStatus.FOUND, title=target,
            detail=f"{target}" + (f" — {rest}" if rest else ""),
            severity=Severity.LOW,
            extra={"query": value, "record": line},
        )


async def _otx(value: str) -> AsyncIterator[Hit]:
    kind = "IPv4" if _is_ip(value) else "domain"
    url = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{value}/passive_dns"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                              headers={"User-Agent": "mytools-osint"})
    except Exception as e:
        yield Hit(module=NAME, source="OTX passive-dns", category="passive-dns",
                  url=url, status=classify_exception(e),
                  title=value, detail=f"{type(e).__name__}: {e}")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="OTX passive-dns", category="passive-dns",
                  url=url, status=classify_http(r.status_code),
                  title=value, detail=f"HTTP {r.status_code}")
        return
    try:
        data = r.json()
    except Exception:
        yield Hit(module=NAME, source="OTX passive-dns", category="passive-dns",
                  url=url, status=HitStatus.NO_DATA, title=value,
                  detail="non-json response")
        return
    rows = data.get("passive_dns") or []
    if not rows:
        yield Hit(module=NAME, source="OTX passive-dns", category="passive-dns",
                  url=url, status=HitStatus.NO_DATA, title=value,
                  detail="no passive-DNS records")
        return
    seen: set[tuple[str, str]] = set()
    for row in rows[:_MAX_ROWS_PER_SOURCE]:
        rrtype = row.get("record_type", "")
        target = row.get("address") if _is_ip(value) else row.get("hostname")
        if not target:
            continue
        key = (rrtype, target)
        if key in seen:
            continue
        seen.add(key)
        first = row.get("first", "?")
        last = row.get("last", "?")
        yield Hit(
            module=NAME, source="OTX passive-dns", category="passive-dns",
            url=f"https://otx.alienvault.com/indicator/{kind.lower()}/{value}",
            status=HitStatus.FOUND, title=target,
            detail=f"{rrtype:6} {target}  first={first[:10]} last={last[:10]}",
            severity=Severity.LOW,
            extra={"record_type": rrtype, "target": target,
                   "first": first, "last": last},
        )


async def _circl(value: str) -> AsyncIterator[Hit]:
    """CIRCL passive DNS — needs HTTP Basic creds, env CIRCL_PDNS_AUTH=user:pass."""
    auth = os.getenv("CIRCL_PDNS_AUTH", "").strip()
    if not auth:
        yield Hit(module=NAME, source="CIRCL pDNS", category="passive-dns",
                  url="https://www.circl.lu/pdns/", status=HitStatus.SKIPPED,
                  title=value,
                  detail="set CIRCL_PDNS_AUTH=user:pass (free at circl.lu)")
        return
    user, _, password = auth.partition(":")
    url = f"https://www.circl.lu/pdns/query/{value}"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                              auth=(user, password),
                              headers={"Accept": "application/json"})
    except Exception as e:
        yield Hit(module=NAME, source="CIRCL pDNS", category="passive-dns",
                  url=url, status=classify_exception(e),
                  title=value, detail=f"{type(e).__name__}: {e}")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="CIRCL pDNS", category="passive-dns",
                  url=url, status=classify_http(r.status_code),
                  title=value, detail=f"HTTP {r.status_code}")
        return
    rows: list = []
    for line in (r.text or "").splitlines():
        try:
            import json
            rows.append(json.loads(line))
        except Exception:
            continue
    if not rows:
        yield Hit(module=NAME, source="CIRCL pDNS", category="passive-dns",
                  url=url, status=HitStatus.NO_DATA, title=value,
                  detail="no records")
        return
    for row in rows[:_MAX_ROWS_PER_SOURCE]:
        rrtype = row.get("rrtype", "")
        rrname = row.get("rrname", "")
        rdata = row.get("rdata", "")
        first = row.get("time_first", "?")
        last = row.get("time_last", "?")
        yield Hit(
            module=NAME, source="CIRCL pDNS", category="passive-dns",
            url=url, status=HitStatus.FOUND, title=rdata or rrname,
            detail=f"{rrtype:6} {rrname} → {rdata}  first={first} last={last}",
            severity=Severity.LOW,
            extra={"rrtype": rrtype, "rrname": rrname, "rdata": rdata,
                   "first": first, "last": last},
        )


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind not in (QueryKind.DOMAIN, QueryKind.IP):
        return
    value = (query.value or "").strip().lower().rstrip("/")
    if not value:
        return

    async def collect(gen):
        return [h async for h in gen]

    tasks = [
        asyncio.create_task(collect(_hackertarget(value))),
        asyncio.create_task(collect(_otx(value))),
        asyncio.create_task(collect(_circl(value))),
    ]
    for fut in asyncio.as_completed(tasks):
        try:
            hits = await fut
        except Exception as e:
            yield Hit(module=NAME, source=NAME, status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")
            continue
        for h in hits:
            yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN, QueryKind.IP], run)
