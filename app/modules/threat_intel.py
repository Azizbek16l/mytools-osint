"""Threat-intel lookups against FREE public IOC feeds.

Sources:
  - URLhaus (abuse.ch)   POST host/url to https://urlhaus-api.abuse.ch/v1/host/ or /url/
                          NOTE: as of 2024, abuse.ch requires a free `Auth-Key`
                          header. Get one at https://auth.abuse.ch/ and set
                          `ABUSE_CH_API_KEY` env var. Module SKIPS politely if unset.
  - ThreatFox (abuse.ch) POST query to https://threatfox-api.abuse.ch/api/v1/
                          (same Auth-Key requirement as URLhaus.)
  - PhishTank            HTTPS POST https://checkurl.phishtank.com/checkurl/
                          (no key required — works for individual URL lookups.)

A "found" hit means the target is on at least one threat-intel feed — treat
seriously regardless of confidence.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
from collections.abc import AsyncIterator, Awaitable

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "threat_intel"


def _abuse_ch_key() -> str:
    return os.getenv("ABUSE_CH_API_KEY", "").strip()

_URLHAUS_HOST = "https://urlhaus-api.abuse.ch/v1/host/"
_URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"
_THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
_PHISHTANK = "https://checkurl.phishtank.com/checkurl/"
_TIMEOUT = 8.0


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


async def _urlhaus(host_or_ip: str) -> Hit:
    key = _abuse_ch_key()
    if not key:
        return Hit(module=NAME, source="URLhaus", category="threat-intel",
                   url=_URLHAUS_HOST, status=HitStatus.SKIPPED,
                   title=host_or_ip,
                   detail="set ABUSE_CH_API_KEY (free at auth.abuse.ch) to enable URLhaus")
    try:
        client = await get_client()
        r = await client.post(
            _URLHAUS_HOST,
            data={"host": host_or_ip},
            headers={"Auth-Key": key},
            timeout=_TIMEOUT,
        )
    except Exception as e:
        return Hit(module=NAME, source="URLhaus", category="threat-intel",
                   url=_URLHAUS_HOST, status=classify_exception(e),
                   title=host_or_ip, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200:
        return Hit(module=NAME, source="URLhaus", category="threat-intel",
                   url=_URLHAUS_HOST, status=classify_http(r.status_code),
                   title=host_or_ip, detail=f"HTTP {r.status_code}")
    try:
        data = r.json()
    except Exception as e:
        return Hit(module=NAME, source="URLhaus", category="threat-intel",
                   url=_URLHAUS_HOST, status=HitStatus.ERROR,
                   title=host_or_ip, detail=f"bad json: {e}")
    if data.get("query_status") == "no_results":
        return Hit(module=NAME, source="URLhaus", category="threat-intel",
                   url=_URLHAUS_HOST, status=HitStatus.NO_DATA,
                   title=host_or_ip, detail="clean (not in URLhaus DB)")
    if data.get("query_status") != "ok":
        return Hit(module=NAME, source="URLhaus", category="threat-intel",
                   url=_URLHAUS_HOST, status=HitStatus.ERROR,
                   title=host_or_ip,
                   detail=f"query_status={data.get('query_status')}")
    urls = data.get("urls") or []
    online = sum(1 for u in urls if u.get("url_status") == "online")
    tags = sorted({t for u in urls for t in (u.get("tags") or [])})[:8]
    threats = sorted({u.get("threat") for u in urls if u.get("threat")})[:4]
    detail = (f"{len(urls)} known malicious URL(s), {online} online | "
              f"threats: {', '.join(threats) or '-'} | "
              f"tags: {', '.join(tags) or '-'}")
    return Hit(
        module=NAME, source="URLhaus", category="threat-intel",
        url=f"https://urlhaus.abuse.ch/browse.php?search={host_or_ip}",
        status=HitStatus.FOUND, title=host_or_ip,
        detail=detail, severity=Severity.CRITICAL if online else Severity.HIGH,
        extra={"urls": urls[:20], "tags": tags, "threats": threats},
    )


async def _threatfox(value: str) -> Hit:
    key = _abuse_ch_key()
    if not key:
        return Hit(module=NAME, source="ThreatFox", category="threat-intel",
                   url=_THREATFOX, status=HitStatus.SKIPPED,
                   title=value,
                   detail="set ABUSE_CH_API_KEY (free at auth.abuse.ch) to enable ThreatFox")
    payload = {"query": "search_ioc", "search_term": value, "exact_match": True}
    try:
        client = await get_client()
        r = await client.post(_THREATFOX, json=payload,
                              headers={"Auth-Key": key}, timeout=_TIMEOUT)
    except Exception as e:
        return Hit(module=NAME, source="ThreatFox", category="threat-intel",
                   url=_THREATFOX, status=classify_exception(e),
                   title=value, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200:
        return Hit(module=NAME, source="ThreatFox", category="threat-intel",
                   url=_THREATFOX, status=classify_http(r.status_code),
                   title=value, detail=f"HTTP {r.status_code}")
    try:
        data = r.json()
    except Exception as e:
        return Hit(module=NAME, source="ThreatFox", category="threat-intel",
                   url=_THREATFOX, status=HitStatus.ERROR,
                   title=value, detail=f"bad json: {e}")
    if data.get("query_status") == "no_result":
        return Hit(module=NAME, source="ThreatFox", category="threat-intel",
                   url=_THREATFOX, status=HitStatus.NO_DATA,
                   title=value, detail="clean (not in ThreatFox IOC DB)")
    if data.get("query_status") != "ok":
        return Hit(module=NAME, source="ThreatFox", category="threat-intel",
                   url=_THREATFOX, status=HitStatus.ERROR,
                   title=value, detail=f"query_status={data.get('query_status')}")
    iocs = data.get("data") or []
    families = sorted({i.get("malware_printable") for i in iocs if i.get("malware_printable")})[:4]
    tags = sorted({t for i in iocs for t in (i.get("tags") or [])})[:8]
    detail = (f"{len(iocs)} IOC entr{'y' if len(iocs) == 1 else 'ies'} | "
              f"families: {', '.join(families) or '-'} | "
              f"tags: {', '.join(tags) or '-'}")
    return Hit(
        module=NAME, source="ThreatFox", category="threat-intel",
        url=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{value}",
        status=HitStatus.FOUND, title=value, detail=detail,
        severity=Severity.CRITICAL,
        extra={"iocs": iocs[:20], "families": families, "tags": tags},
    )


async def _phishtank(host: str) -> Hit:
    """PhishTank checkurl. Requires a full URL, so we wrap host in http(s)://."""
    full = host if "://" in host else f"http://{host}/"
    try:
        client = await get_client()
        r = await client.post(
            _PHISHTANK,
            data={"url": full, "format": "json"},
            headers={"User-Agent": "phishtank/mytools-osint"},
            timeout=_TIMEOUT,
        )
    except Exception as e:
        return Hit(module=NAME, source="PhishTank", category="threat-intel",
                   url=_PHISHTANK, status=classify_exception(e),
                   title=host, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200:
        return Hit(module=NAME, source="PhishTank", category="threat-intel",
                   url=_PHISHTANK, status=classify_http(r.status_code),
                   title=host, detail=f"HTTP {r.status_code}")
    try:
        data = r.json()
    except Exception:
        return Hit(module=NAME, source="PhishTank", category="threat-intel",
                   url=_PHISHTANK, status=HitStatus.NO_DATA,
                   title=host, detail="non-json response")
    results = (data.get("results") or {})
    in_db = bool(results.get("in_database"))
    if not in_db:
        return Hit(module=NAME, source="PhishTank", category="threat-intel",
                   url=_PHISHTANK, status=HitStatus.NO_DATA,
                   title=host, detail="clean (not in PhishTank DB)")
    verified = bool(results.get("verified"))
    detail = (f"in PhishTank DB | verified={verified} | "
              f"id={results.get('phish_id', '-')}")
    return Hit(
        module=NAME, source="PhishTank", category="threat-intel",
        url=results.get("phish_detail_page", _PHISHTANK),
        status=HitStatus.FOUND, title=host, detail=detail,
        severity=Severity.CRITICAL if verified else Severity.HIGH,
        extra=results,
    )


async def run(query: Query) -> AsyncIterator[Hit]:
    value = (query.value or "").strip().lower().rstrip("/")
    if not value:
        return
    if query.kind == QueryKind.IP:
        host = value.split("/", 1)[0]
    elif query.kind == QueryKind.DOMAIN:
        host = value
    else:
        return

    sem = asyncio.Semaphore(3)

    async def gated(coro: Awaitable[Hit]) -> Hit:
        async with sem:
            return await coro

    probes = [
        gated(_urlhaus(host)),
        gated(_threatfox(host)),
    ]
    if not _is_ip(host):
        probes.append(gated(_phishtank(host)))

    tasks = [asyncio.create_task(p) for p in probes]
    for fut in asyncio.as_completed(tasks):
        try:
            yield await fut
        except Exception as e:
            yield Hit(module=NAME, source=NAME, category="threat-intel",
                      status=HitStatus.ERROR, detail=f"{type(e).__name__}: {e}")


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.IP, QueryKind.DOMAIN], run)
