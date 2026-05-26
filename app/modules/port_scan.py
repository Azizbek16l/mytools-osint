"""Active port scanner — TCP-connect + banner grab.

For a DOMAIN or IP target: resolve to IPs (if domain), then concurrently
try TCP connect to the top-50 ports. For each open port, read up to 256B
of banner. Maps to PORT entities in the graph (EXPOSES_PORT edge).

Defaults:
  - top-50 ports only (the "interesting" subset — admin, db, mail, web)
  - --port-scan-deep env unlocks top-1000 (TODO when needed)
  - Semaphore(20), 2s timeout per port

OPSEC:
  - Refuses when --opsec is on (TCP connect over Tor is slow + loud)
  - Override: OSINT_PORT_SCAN_OVER_TOR=1
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
from collections.abc import AsyncIterator

import dns.asyncresolver

from app.core.http import _opsec_on
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "port_scan"

TIMEOUT = 2.0
CONCURRENCY = 20
BANNER_BYTES = 256

# Top-50 interesting ports for OSINT: admin panels, dbs, mail, web, dev tools.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389,
    443, 445, 465, 587, 631, 636, 873, 990, 993, 995, 1433, 1521, 1723,
    2049, 2222, 2375, 2376, 3000, 3306, 3389, 4000, 4040, 5000, 5432,
    5601, 5672, 5984, 6379, 6443, 7000, 7474, 8000, 8008, 8080, 8081,
    8086, 8088, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9200, 9300,
    9418, 9999, 10000, 11211, 15672, 27017, 50070,
]

# Severity heuristics — exposed databases are HIGH; common web ports INFO
HIGH_SEV_PORTS = {21, 22, 23, 25, 110, 139, 445, 1433, 1521, 2049, 2375,
                  2376, 3306, 3389, 5432, 5984, 6379, 6443, 9200, 11211,
                  27017, 50070, 5601, 8086, 15672}


async def _resolve_to_ips(host: str) -> list[str]:
    try:
        ans = await dns.asyncresolver.resolve(host, "A", lifetime=4.0)
        return [r.to_text() for r in ans][:4]  # cap fan-out
    except Exception:
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            return []


async def _scan_port(ip: str, port: int) -> tuple[int, bool, bytes]:
    """Returns (port, is_open, banner_bytes)."""
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=TIMEOUT)
        banner = b""
        try:
            banner = await asyncio.wait_for(reader.read(BANNER_BYTES), timeout=1.5)
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return (port, True, banner)
    except Exception:
        return (port, False, b"")


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind not in (QueryKind.DOMAIN, QueryKind.IP):
        return
    value = (query.value or "").strip().lower()
    if not value:
        return

    if _opsec_on() and not os.getenv("OSINT_PORT_SCAN_OVER_TOR"):
        yield Hit(module=NAME, source="opsec-guard", category="port-scan",
                  status=HitStatus.SKIPPED, title=value,
                  detail="port_scan SKIPPED in OPSEC mode (TCP-connect over Tor is slow + loud). "
                         "Override with OSINT_PORT_SCAN_OVER_TOR=1.")
        return

    ips = await _resolve_to_ips(value)
    if not ips:
        yield Hit(module=NAME, source="resolve", category="port-scan",
                  status=HitStatus.NO_DATA, title=value,
                  detail="no A records to scan")
        return

    yield Hit(module=NAME, source="targets", category="port-scan",
              status=HitStatus.NO_DATA, title=value,
              detail=f"scanning {len(ips)} IP(s) × {len(TOP_PORTS)} top ports = "
                     f"{len(ips) * len(TOP_PORTS)} connects",
              severity=Severity.INFO)

    sem = asyncio.Semaphore(CONCURRENCY)

    async def gated(ip, port):
        async with sem:
            return ip, *(await _scan_port(ip, port))

    tasks = []
    for ip in ips:
        for port in TOP_PORTS:
            tasks.append(asyncio.create_task(gated(ip, port)))

    n_open = 0
    for fut in asyncio.as_completed(tasks):
        try:
            ip, port, is_open, banner = await fut
        except Exception as e:
            yield Hit(module=NAME, source=NAME, status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")
            continue
        if not is_open:
            continue
        n_open += 1
        banner_str = banner.decode("utf-8", errors="replace").strip()[:160]
        sev = Severity.HIGH if port in HIGH_SEV_PORTS else Severity.INFO
        yield Hit(
            module=NAME, source=f"tcp/{port}", category="port-scan",
            url=f"https://{ip}:{port}/" if port in (443, 8443) else "",
            status=HitStatus.FOUND, title=f"{ip}:{port}",
            detail=f"OPEN · banner: {banner_str!r}" if banner_str else "OPEN · (no banner)",
            severity=sev,
            extra={"ip": ip, "port": port, "banner": banner_str},
        )

    yield Hit(module=NAME, source="summary", category="port-scan",
              status=HitStatus.FOUND if n_open else HitStatus.NO_DATA,
              title=value,
              detail=f"{n_open}/{len(tasks)} ports open across {len(ips)} IP(s)",
              severity=Severity.INFO,
              extra={"open": n_open, "scanned": len(tasks), "ips": ips})


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN, QueryKind.IP], run)
