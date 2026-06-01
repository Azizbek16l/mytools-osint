"""Shodan InternetDB — FREE, no key, no rate limit advertised.

`https://internetdb.shodan.io/<ip>` returns a JSON snapshot of what Shodan
already knows about that IP: open ports, hostnames, CPEs, vulnerabilities
(CVE list), and tags. This is the single biggest "free win" in the IP
recon space — no other public source gives CVEs for an arbitrary IP
without auth.

For DOMAIN queries we resolve A/AAAA first and probe every unique IP.
Severity is bumped to HIGH when vulns are present and CRITICAL when a
CVE has a known exploit class (rough heuristic via tag list).
"""
from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator
from typing import Any

import dns.asyncresolver

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "internetdb"

_URL = "https://internetdb.shodan.io/{ip}"
_TIMEOUT = 8.0
_MAX_IPS_PER_DOMAIN = 8


async def _resolve_ips(host: str) -> list[str]:
    out: set[str] = set()
    for rtype in ("A", "AAAA"):
        try:
            ans = await dns.asyncresolver.resolve(host, rtype, lifetime=5.0)
        except Exception:  # noqa: S112, BLE001 — DNS failures are expected
            continue
        for r in ans:
            out.add(r.to_text())
    return sorted(out)[:_MAX_IPS_PER_DOMAIN]


def _severity_for(vulns: list[Any], tags: list[Any]) -> Severity:
    if not vulns:
        return Severity.LOW
    tags_l = [str(t).lower() for t in tags]
    if any(t in tags_l for t in ("compromised", "honeypot", "malware", "cnc", "tor")):
        return Severity.CRITICAL
    if len(vulns) >= 5:
        return Severity.HIGH
    return Severity.MEDIUM


async def _probe_one(ip: str) -> Hit:
    url = _URL.format(ip=ip)
    try:
        client = await get_client()
        r = await client.get(url, headers={"Accept": "application/json"}, timeout=_TIMEOUT)
    except Exception as e:
        return Hit(module=NAME, source="Shodan InternetDB", category="ip",
                   url=url, status=classify_exception(e),
                   title=ip, detail=f"{type(e).__name__}: {e}")
    if r.status_code == 404:
        return Hit(module=NAME, source="Shodan InternetDB", category="ip",
                   url=url, status=HitStatus.NO_DATA, title=ip,
                   detail="not indexed by Shodan")
    if r.status_code != 200:
        return Hit(module=NAME, source="Shodan InternetDB", category="ip",
                   url=url, status=classify_http(r.status_code), title=ip,
                   detail=f"HTTP {r.status_code}")
    try:
        data = r.json()
    except Exception as e:
        return Hit(module=NAME, source="Shodan InternetDB", category="ip",
                   url=url, status=HitStatus.ERROR, title=ip,
                   detail=f"bad json: {e}")
    ports = data.get("ports") or []
    hostnames = data.get("hostnames") or []
    cpes = data.get("cpes") or []
    vulns = data.get("vulns") or []
    tags = data.get("tags") or []
    bits = []
    if ports:
        bits.append(f"{len(ports)} ports: {', '.join(map(str, ports[:8]))}"
                    + (" …" if len(ports) > 8 else ""))
    if vulns:
        bits.append(f"{len(vulns)} CVEs: {', '.join(vulns[:5])}"
                    + (" …" if len(vulns) > 5 else ""))
    if hostnames:
        bits.append(f"hosts: {', '.join(hostnames[:3])}")
    if tags:
        bits.append(f"tags: {', '.join(tags[:5])}")
    detail = " | ".join(bits) if bits else "no public footprint"
    return Hit(
        module=NAME, source="Shodan InternetDB", category="ip",
        url=url, status=HitStatus.FOUND if (ports or vulns or hostnames) else HitStatus.NO_DATA,
        title=ip, detail=detail,
        severity=_severity_for(vulns, tags),
        extra={"ports": ports, "hostnames": hostnames, "cpes": cpes,
               "vulns": vulns, "tags": tags},
    )


async def run(query: Query) -> AsyncIterator[Hit]:
    value = (query.value or "").strip()
    if not value:
        return

    ips: list[str] = []
    if query.kind == QueryKind.IP:
        try:
            ipaddress.ip_address(value.split("/", 1)[0])
            ips = [value.split("/", 1)[0]]
        except ValueError:
            return
    elif query.kind == QueryKind.DOMAIN:
        ips = await _resolve_ips(value)
        if not ips:
            yield Hit(module=NAME, source="Shodan InternetDB", category="ip",
                      status=HitStatus.NO_DATA, title=value,
                      detail="no A/AAAA records to probe")
            return
    else:
        return

    sem = asyncio.Semaphore(4)

    async def one(ip: str) -> Hit:
        async with sem:
            return await _probe_one(ip)

    tasks = [asyncio.create_task(one(ip)) for ip in ips]
    for fut in asyncio.as_completed(tasks):
        try:
            yield await fut
        except Exception as e:
            yield Hit(module=NAME, source="Shodan InternetDB", category="ip",
                      status=HitStatus.ERROR, detail=f"{type(e).__name__}: {e}")


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.IP, QueryKind.DOMAIN], run)
