"""Additional FREE IP intel — Spamhaus DROP, GreyNoise community, optional AbuseIPDB.

Sources:
  - GreyNoise Community  — `https://api.greynoise.io/v3/community/<ip>` (free, no key,
    rate-limited per source IP). Tells you whether the IP is a known internet-wide
    scanner / noise generator, and what GreyNoise classifies it as.
  - Spamhaus DROP list   — text file at https://www.spamhaus.org/drop/drop.txt
    listing "do not route or peer" CIDRs (hijacked netblocks and known bad actors).
    Cached in-process for 1h.
  - AbuseIPDB (`/api/v2/check`) — free 1000/day WITH key. Skipped silently when
    `ABUSEIPDB_API_KEY` is unset; never blocks the scan.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from collections.abc import AsyncIterator

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "ip_extras"

_GREYNOISE = "https://api.greynoise.io/v3/community/{ip}"
_SPAMHAUS_DROP = "https://www.spamhaus.org/drop/drop.txt"
_ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"

# Spamhaus DROP cache — refreshed every hour. The list is small (~kilobytes).
_DROP_CACHE: dict[str, object] = {"expires": 0.0, "networks": []}
_DROP_LOCK = asyncio.Lock()
_DROP_TTL_S = 3600


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _load_spamhaus_drop() -> tuple[list[ipaddress.IPv4Network], str]:
    """Fetch & parse the Spamhaus DROP list. Cached for 1h.

    Returns (networks, detail). On outage, returns ([], reason) but the
    cache keeps any previously-loaded value usable.
    """
    async with _DROP_LOCK:
        now = time.monotonic()
        if now < _DROP_CACHE["expires"] and _DROP_CACHE["networks"]:
            return _DROP_CACHE["networks"], "cached"  # type: ignore[return-value]
        client = await get_client()
        try:
            r = await client.get(
                _SPAMHAUS_DROP,
                headers={"Accept": "text/plain", "User-Agent": "mytools-osint"},
                timeout=10,
            )
        except BaseException as e:
            return _DROP_CACHE["networks"], f"{type(e).__name__}: {e}"[:120]  # type: ignore[return-value]
        if r.status_code != 200:
            return _DROP_CACHE["networks"], f"HTTP {r.status_code}"  # type: ignore[return-value]
        networks: list[ipaddress.IPv4Network] = []
        for line in (r.text or "").splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            # Format: "1.2.3.0/24 ; SBL12345"
            cidr = line.split(";", 1)[0].strip()
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        _DROP_CACHE["networks"] = networks
        _DROP_CACHE["expires"] = now + _DROP_TTL_S
        return networks, f"{len(networks)} CIDRs loaded"


async def _spamhaus(ip: str) -> AsyncIterator[Hit]:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return
    if ip_obj.version != 4:
        # DROP is IPv4-only.
        yield Hit(
            module=NAME, source="Spamhaus DROP", category="threat",
            status=HitStatus.SKIPPED,
            detail="DROP list is IPv4 only",
        )
        return
    networks, detail = await _load_spamhaus_drop()
    if not networks:
        yield Hit(
            module=NAME, source="Spamhaus DROP", category="threat",
            status=HitStatus.UNAVAILABLE, detail=detail or "list unavailable",
            url=_SPAMHAUS_DROP,
        )
        return
    for net in networks:
        if ip_obj in net:
            yield Hit(
                module=NAME, source="Spamhaus DROP", category="threat",
                status=HitStatus.FOUND,
                title=f"{ip} in {net}",
                detail=(f"listed in Spamhaus DROP (do-not-route). "
                        f"network={net} matches={detail}"),
                url=_SPAMHAUS_DROP,
                severity=Severity.HIGH,
                extra={"network": str(net), "ip": ip},
            )
            return
    yield Hit(
        module=NAME, source="Spamhaus DROP", category="threat",
        status=HitStatus.NOT_FOUND,
        detail=f"not in DROP list ({detail})",
        url=_SPAMHAUS_DROP,
    )


def _greynoise_severity(data: dict) -> Severity:
    classification = (data.get("classification") or "").lower()
    if classification == "malicious":
        return Severity.HIGH
    if classification == "benign":
        return Severity.LOW
    return Severity.MEDIUM


async def _greynoise(ip: str) -> AsyncIterator[Hit]:
    url = _GREYNOISE.format(ip=ip)
    client = await get_client()
    try:
        r = await client.get(
            url,
            headers={"Accept": "application/json", "User-Agent": "mytools-osint"},
            timeout=10,
        )
    except BaseException as e:
        yield Hit(
            module=NAME, source="GreyNoise community", category="threat",
            status=classify_exception(e), detail=f"{type(e).__name__}: {e}"[:120],
            url=url,
        )
        return

    if r.status_code == 404:
        yield Hit(
            module=NAME, source="GreyNoise community", category="threat",
            status=HitStatus.NOT_FOUND,
            detail="IP not observed by GreyNoise sensors",
            url=url,
        )
        return
    if r.status_code == 429:
        yield Hit(
            module=NAME, source="GreyNoise community", category="threat",
            status=HitStatus.RATELIMITED,
            detail="429 — community tier throttled, wait or get a key",
            url=url,
        )
        return
    if r.status_code != 200:
        yield Hit(
            module=NAME, source="GreyNoise community", category="threat",
            status=classify_http(r.status_code),
            detail=f"HTTP {r.status_code}", url=url,
        )
        return
    try:
        data = r.json() or {}
    except Exception:
        yield Hit(
            module=NAME, source="GreyNoise community", category="threat",
            status=HitStatus.ERROR, detail="unparseable JSON", url=url,
        )
        return

    noise = bool(data.get("noise"))
    riot = bool(data.get("riot"))
    classification = data.get("classification") or "unknown"
    name = data.get("name") or "?"
    last = data.get("last_seen") or ""
    detail = (f"classification={classification} noise={noise} riot={riot} "
              f"name={name} last_seen={last}")
    yield Hit(
        module=NAME, source="GreyNoise community", category="threat",
        status=HitStatus.FOUND,
        title=f"GreyNoise: {classification}",
        detail=detail,
        url=data.get("link") or url,
        severity=_greynoise_severity(data),
        extra=data,
    )


async def _abuseipdb(ip: str) -> AsyncIterator[Hit]:
    """Optional, key-only. Free 1000/day with `ABUSEIPDB_API_KEY` env var."""
    key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if not key:
        yield Hit(
            module=NAME, source="AbuseIPDB", category="threat",
            status=HitStatus.SKIPPED,
            detail="set ABUSEIPDB_API_KEY for 1000 free checks/day",
        )
        return
    client = await get_client()
    try:
        r = await client.get(
            _ABUSEIPDB,
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""},
            headers={"Key": key, "Accept": "application/json",
                     "User-Agent": "mytools-osint"},
            timeout=10,
        )
    except BaseException as e:
        yield Hit(
            module=NAME, source="AbuseIPDB", category="threat",
            status=classify_exception(e), detail=f"{type(e).__name__}: {e}"[:120],
        )
        return

    if r.status_code == 429:
        yield Hit(
            module=NAME, source="AbuseIPDB", category="threat",
            status=HitStatus.RATELIMITED, detail="daily quota exhausted",
        )
        return
    if r.status_code == 401:
        yield Hit(
            module=NAME, source="AbuseIPDB", category="threat",
            status=HitStatus.ERROR, detail="invalid ABUSEIPDB_API_KEY",
        )
        return
    if r.status_code != 200:
        yield Hit(
            module=NAME, source="AbuseIPDB", category="threat",
            status=classify_http(r.status_code), detail=f"HTTP {r.status_code}",
        )
        return
    try:
        body = (r.json() or {}).get("data") or {}
    except Exception:
        yield Hit(
            module=NAME, source="AbuseIPDB", category="threat",
            status=HitStatus.ERROR, detail="unparseable JSON",
        )
        return

    score = body.get("abuseConfidenceScore", 0)
    reports = body.get("totalReports", 0)
    if score >= 75:
        sev = Severity.HIGH
    elif score >= 25:
        sev = Severity.MEDIUM
    else:
        sev = Severity.LOW
    yield Hit(
        module=NAME, source="AbuseIPDB", category="threat",
        status=HitStatus.FOUND,
        title=f"AbuseIPDB confidence {score}/100",
        detail=(f"reports={reports} country={body.get('countryCode','?')} "
                f"isp={body.get('isp','?')} usage={body.get('usageType','?')}"),
        url=f"https://www.abuseipdb.com/check/{ip}",
        severity=sev,
        extra=body,
    )


async def run(query: Query) -> AsyncIterator[Hit]:
    value = query.value.strip()
    if not value or not _is_ip(value):
        return
    async for h in _greynoise(value):
        yield h
    async for h in _spamhaus(value):
        yield h
    async for h in _abuseipdb(value):
        yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.IP], run)
