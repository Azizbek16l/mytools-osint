"""HackerTarget free-tier API — multi-tool quick lookups (v4.2).

One unauthenticated endpoint family providing hostsearch, reverse-DNS,
DNS records, HTTP headers, geoip, mtr. Free quota: 50-200 req/day/IP
(scales with operator's mood — they don't publish exact numbers).

We use a tight subset that adds value without burning quota:
- hostsearch   → subdomain enum (cross-checks CertSpotter + crt.sh)
- reversedns   → for IP queries, lists hosts pointing at this IP
- dnslookup    → quick MX/NS/TXT one-liner for domain queries

Endpoint: https://api.hackertarget.com/{tool}/?q={resource}
Response: plain text (one record per line).
"""
from __future__ import annotations

from collections.abc import AsyncIterator

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "hackertarget"
_TIMEOUT = 12.0
_MAX_LINES = 500


async def _call(tool: str, resource: str) -> tuple[int, list[str]]:
    """Returns (status_code, lines). 200+empty means quota exceeded."""
    client = await get_client()
    url = f"https://api.hackertarget.com/{tool}/?q={resource}"
    try:
        r = await client.get(url, timeout=_TIMEOUT)
    except Exception:
        return 0, []
    if r.status_code != 200:
        return r.status_code, []
    txt = r.text.strip()
    if not txt or "error" in txt.lower()[:60] or "api count" in txt.lower():
        return 429, []
    return 200, [ln.strip() for ln in txt.splitlines() if ln.strip()][:_MAX_LINES]


async def _run_domain(domain: str) -> AsyncIterator[Hit]:
    status, lines = await _call("hostsearch", domain)
    if status == 429:
        yield Hit(module=NAME, source="HackerTarget (hostsearch)",
                  category="dns", status=HitStatus.RATELIMITED,
                  detail="free 50-200 req/day quota exhausted")
        return
    if status != 200:
        yield Hit(module=NAME, source="HackerTarget (hostsearch)",
                  category="dns", status=HitStatus.NO_DATA,
                  detail=f"HTTP {status}")
        return
    subs: set[str] = set()
    for line in lines:
        # Format: "subdomain,IP"
        sub = line.split(",", 1)[0].strip().lower()
        if sub and sub.endswith(domain) and sub != domain:
            subs.add(sub)
    for sub in sorted(subs):
        yield Hit(module=NAME, source="HackerTarget", category="dns",
                  url=f"https://{sub}", status=HitStatus.FOUND,
                  title=f"subdomain: {sub}",
                  detail="surfaced by HackerTarget hostsearch",
                  severity=Severity.LOW,
                  extra={"subdomain": sub})
    yield Hit(module=NAME, source="HackerTarget", category="dns",
              status=HitStatus.FOUND,
              title=f"{len(subs)} subdomains via HackerTarget",
              detail="cross-validates CertSpotter + crt.sh",
              severity=Severity.INFO,
              extra={"unique_subdomains": len(subs)})


async def _run_ip(ip: str) -> AsyncIterator[Hit]:
    status, lines = await _call("reverseiplookup", ip)
    if status == 429:
        yield Hit(module=NAME, source="HackerTarget (reverseip)",
                  category="ip", status=HitStatus.RATELIMITED,
                  detail="free quota exhausted")
        return
    if status != 200:
        yield Hit(module=NAME, source="HackerTarget (reverseip)",
                  category="ip", status=HitStatus.NO_DATA,
                  detail=f"HTTP {status}")
        return
    hosts = sorted({ln.lower() for ln in lines if ln})
    for host in hosts:
        yield Hit(module=NAME, source="HackerTarget", category="ip",
                  url=f"https://{host}", status=HitStatus.FOUND,
                  title=f"co-hosted: {host}",
                  detail=f"resolves to {ip} (HackerTarget reverse-IP)",
                  severity=Severity.LOW,
                  extra={"hostname": host, "ip": ip})
    yield Hit(module=NAME, source="HackerTarget", category="ip",
              status=HitStatus.FOUND,
              title=f"{len(hosts)} co-hosted hostnames on {ip}",
              detail="virtual hosts via HackerTarget reverse-IP",
              severity=Severity.INFO,
              extra={"co_hosted_count": len(hosts)})


async def _run(query: Query) -> AsyncIterator[Hit]:
    val = (query.value or "").strip().lower()
    if query.kind == QueryKind.DOMAIN:
        async for h in _run_domain(val):
            yield h
    elif query.kind == QueryKind.IP:
        async for h in _run_ip(val):
            yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN, QueryKind.IP], _run)
