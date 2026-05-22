"""Domain & subdomain enumeration via FREE sources (no API key).

Sources:
  - crt.sh — Certificate Transparency logs (subdomains, historical certs)
  - HackerTarget hostsearch — DNS recon (free, soft rate-limit)
  - urlscan.io public — recent scans referencing the domain
  - DNS A/AAAA/MX/TXT/NS/CAA via dns.asyncresolver
"""
from __future__ import annotations

from collections.abc import AsyncIterator

import dns.asyncresolver

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "domain"


def _normalize(value: str) -> str:
    v = value.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    return v.split("/", 1)[0].split("?", 1)[0]


async def _crtsh(domain: str) -> AsyncIterator[Hit]:
    """Certificate Transparency: subdomain leak via historical certs."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        client = await get_client()
        r = await client.get(url, headers={"Accept": "application/json"}, timeout=20)
        if r.status_code != 200:
            yield Hit(module=NAME, source="crt.sh", category="dns",
                      status=HitStatus.UNCERTAIN, detail=f"HTTP {r.status_code}")
            return
        try:
            data = r.json()
        except Exception:
            data = []
        if not data:
            yield Hit(module=NAME, source="crt.sh", category="dns",
                      status=HitStatus.NOT_FOUND, detail="no CT entries")
            return
        subs: set[str] = set()
        for row in data:
            names = (row.get("name_value") or "").splitlines()
            for n in names:
                n = n.strip().lower().lstrip("*.")
                if n and (n == domain or n.endswith("." + domain)):
                    subs.add(n)
        subs.discard(domain)
        for s in sorted(subs)[:200]:
            yield Hit(
                module=NAME, source="crt.sh", category="subdomain",
                status=HitStatus.FOUND, title=s,
                detail="subdomain seen in Certificate Transparency logs",
                url=f"https://crt.sh/?q={s}",
                severity=Severity.MEDIUM, extra={"subdomain": s},
            )
        yield Hit(
            module=NAME, source="crt.sh", category="dns",
            status=HitStatus.FOUND,
            title=f"{len(subs)} subdomain(s) via CT",
            detail=f"crt.sh returned {len(data)} cert entries; {len(subs)} unique subdomains",
            url=f"https://crt.sh/?q=%25.{domain}",
        )
    except Exception as e:
        yield Hit(module=NAME, source="crt.sh", category="dns",
                  status=HitStatus.ERROR, detail=str(e))


async def _hackertarget(domain: str) -> AsyncIterator[Hit]:
    """Free DNS recon — soft rate-limit (50/day no key)."""
    base = "https://api.hackertarget.com"
    client = await get_client()
    # hostsearch — known subdomains + their A records
    try:
        r = await client.get(f"{base}/hostsearch/?q={domain}", timeout=15)
        if r.status_code == 200 and r.text and "API count exceeded" not in r.text:
            lines = [ln for ln in r.text.strip().splitlines() if "," in ln]
            for ln in lines[:60]:
                host, ip = ln.split(",", 1)
                yield Hit(
                    module=NAME, source="HackerTarget:hostsearch",
                    category="subdomain", status=HitStatus.FOUND,
                    title=host.strip(),
                    detail=f"A record: {ip.strip()}",
                    extra={"host": host.strip(), "ip": ip.strip()},
                )
        elif "API count exceeded" in (r.text or ""):
            yield Hit(module=NAME, source="HackerTarget", category="dns",
                      status=HitStatus.RATELIMITED, detail="daily free quota exhausted")
    except Exception as e:
        yield Hit(module=NAME, source="HackerTarget:hostsearch",
                  status=HitStatus.ERROR, detail=str(e))


async def _urlscan(domain: str) -> AsyncIterator[Hit]:
    """Free public urlscan.io search — recent scans, no key needed for search."""
    url = f"https://urlscan.io/api/v1/search/?q=domain%3A{domain}&size=15"
    try:
        client = await get_client()
        r = await client.get(url, headers={"Accept": "application/json"}, timeout=20)
        if r.status_code != 200:
            yield Hit(module=NAME, source="urlscan.io", category="recon",
                      status=HitStatus.UNCERTAIN, detail=f"HTTP {r.status_code}")
            return
        data = r.json() or {}
        results = data.get("results") or []
        if not results:
            yield Hit(module=NAME, source="urlscan.io", category="recon",
                      status=HitStatus.NOT_FOUND, detail="no recent scans referencing domain")
            return
        for entry in results[:15]:
            page = entry.get("page") or {}
            task = entry.get("task") or {}
            yield Hit(
                module=NAME, source="urlscan.io", category="recon",
                status=HitStatus.FOUND,
                title=page.get("url") or task.get("url", "?"),
                detail=f"scanned {task.get('time','?')}  ip={page.get('ip','?')} "
                       f"country={page.get('country','?')}",
                url=f"https://urlscan.io/result/{entry.get('_id','')}",
                severity=Severity.MEDIUM,
                extra={"page": page, "task": task},
            )
    except Exception as e:
        yield Hit(module=NAME, source="urlscan.io", category="recon",
                  status=HitStatus.ERROR, detail=str(e))


async def _records(domain: str) -> AsyncIterator[Hit]:
    """Direct DNS lookups — A/AAAA/MX/TXT/NS/CAA/SOA."""
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CAA", "SOA"):
        try:
            ans = await dns.asyncresolver.resolve(domain, rtype, lifetime=5)
            vals = [str(a).strip(".") for a in ans]
            if vals:
                yield Hit(
                    module=NAME, source=f"DNS:{rtype}", category="dns",
                    status=HitStatus.FOUND, title=domain,
                    detail=", ".join(vals[:6]),
                    extra={rtype: vals},
                )
        except Exception:
            pass


async def run(query: Query) -> AsyncIterator[Hit]:
    domain = _normalize(query.value)
    if not domain or "." not in domain:
        return
    async for h in _records(domain):
        yield h
    async for h in _crtsh(domain):
        yield h
    async for h in _hackertarget(domain):
        yield h
    async for h in _urlscan(domain):
        yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
