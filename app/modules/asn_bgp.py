"""ASN/BGP/IXP — Team Cymru WHOIS + BGPView (free, no key).

Three free sources:
  1. Team Cymru WHOIS (whois.cymru.com:43) — ASN, prefix, country, registry
  2. BGPView (api.bgpview.io) — upstreams/peers/prefixes (soft rate limit)
  3. (PeeringDB — disabled by default to keep latency low)
"""
from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "asn_bgp"


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return False


async def _cymru(ip: str) -> dict | None:
    """Plain TCP WHOIS to whois.cymru.com:43, verbose mode."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("whois.cymru.com", 43), timeout=5,
        )
    except Exception:
        return None
    try:
        writer.write(f"begin\nverbose\n{ip}\nend\n".encode())
        await writer.drain()
        chunks: list[bytes] = []
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=3)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks).decode("utf-8", "replace")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    # parse: ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    for line in raw.splitlines():
        if "|" not in line or line.startswith("AS") or "Bulk mode" in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 7:
            return {
                "asn": parts[0],
                "ip": parts[1],
                "prefix": parts[2],
                "country": parts[3],
                "registry": parts[4],
                "allocated": parts[5],
                "as_name": parts[6],
            }
    return None


async def _bgpview_ip(ip: str) -> dict | None:
    client = await get_client()
    try:
        r = await client.get(f"https://api.bgpview.io/ip/{ip}",
                             headers={"Accept": "application/json"}, timeout=10)
        if r.status_code != 200:
            return None
        return r.json().get("data")
    except Exception:
        return None


async def _bgpview_asn(asn: int) -> dict | None:
    client = await get_client()
    try:
        r = await client.get(f"https://api.bgpview.io/asn/{asn}",
                             headers={"Accept": "application/json"}, timeout=10)
        if r.status_code != 200:
            return None
        return r.json().get("data")
    except Exception:
        return None


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.IP:
        return
    ip = query.value.strip()
    if not ip:
        return
    if _is_private(ip):
        yield Hit(module=NAME, source="Team Cymru", category="asn",
                  status=HitStatus.SKIPPED,
                  detail=f"{ip} is private/reserved/loopback — no public ASN")
        return

    # Cymru first — fast, gives ASN/prefix
    cymru = await _cymru(ip)
    if cymru:
        yield Hit(
            module=NAME, source="Team Cymru", category="asn",
            status=HitStatus.FOUND,
            title=f"AS{cymru['asn']}  {cymru['as_name'][:48]}",
            detail=f"prefix={cymru['prefix']} · country={cymru['country']} "
                   f"· registry={cymru['registry']} · allocated={cymru['allocated']}",
            severity=Severity.INFO,
            url=f"https://bgpview.io/ip/{ip}",
            extra=cymru,
        )
        # Use ASN to fetch upstreams / peers (best-effort)
        try:
            asn_int = int(cymru["asn"].split()[0])
        except ValueError:
            asn_int = 0
        if asn_int:
            asn_data = await _bgpview_asn(asn_int)
            if asn_data:
                upstreams = (asn_data.get("ipv4_upstreams") or [])[:8]
                if upstreams:
                    yield Hit(
                        module=NAME, source=f"BGPView:AS{asn_int}", category="asn",
                        status=HitStatus.FOUND,
                        title=f"{len(upstreams)} IPv4 upstreams",
                        detail=", ".join(f"AS{u.get('asn')} {u.get('name', '')[:24]}"
                                         for u in upstreams),
                        url=f"https://bgpview.io/asn/{asn_int}",
                        extra={"upstreams": upstreams},
                    )
        return

    # Cymru failed — try BGPView directly
    data = await _bgpview_ip(ip)
    if data:
        prefixes = data.get("prefixes") or []
        if prefixes:
            p = prefixes[0]
            asn = p.get("asn", {}) or {}
            yield Hit(
                module=NAME, source="BGPView", category="asn",
                status=HitStatus.FOUND,
                title=f"AS{asn.get('asn')} {asn.get('name','')[:48]}",
                detail=f"prefix={p.get('prefix')} · country={asn.get('country_code')}",
                url=f"https://bgpview.io/ip/{ip}",
                extra=data,
            )
            return

    yield Hit(module=NAME, source="ASN lookup", category="asn",
              status=HitStatus.NOT_FOUND, detail="no ASN info from Cymru or BGPView")


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.IP], run)
