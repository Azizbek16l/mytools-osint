"""Domain & subdomain enumeration via FREE passive sources (no API keys).

Sources (all free, no auth):
  - crt.sh                — Certificate Transparency logs
  - HackerTarget          — hostsearch (~50 req/day soft limit)
  - urlscan.io public     — recent scans referencing the domain
  - AlienVault OTX        — passive DNS (no key for read)
  - subdomain.center      — third-party recursive collector
  - RapidDNS              — HTML scrape, no key
  - Wayback Machine CDX   — historical URLs of *.{domain}/*
  - ThreatMiner v2        — free 10 req/min
  - DNS A/AAAA/MX/TXT/NS/CAA/SOA via dns.asyncresolver

Each discovered subdomain is emitted as its OWN Hit with the FQDN in `source`
so it shows up cleanly in the CLI table.
"""
from __future__ import annotations

import asyncio
import re
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


def _keep_sub(host: str, domain: str) -> str | None:
    """Return clean lowercase FQDN if `host` is a subdomain of `domain` (or itself)."""
    h = (host or "").strip().lower().lstrip("*.").rstrip(".")
    if not h:
        return None
    if h == domain or h.endswith("." + domain):
        return h
    return None


# ---- per-source coroutines ------------------------------------------------

async def _crtsh(domain: str) -> tuple[set[str], str]:
    """Certificate Transparency. crt.sh is slow on popular domains — 90s + 1 retry."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs: set[str] = set()
    last_err = ""
    for attempt in range(2):
        try:
            client = await get_client()
            r = await client.get(
                url,
                headers={"Accept": "application/json",
                         "User-Agent": "mytools-osint (subdomain enumeration)"},
                timeout=90, follow_redirects=True,
            )
            if r.status_code != 200:
                last_err = f"HTTP {r.status_code}"
                if r.status_code in (502, 503, 504):
                    await asyncio.sleep(2)
                    continue
                return subs, last_err
            try:
                data = r.json()
            except Exception:
                return subs, "unparseable JSON"
            for row in data or []:
                for n in (row.get("name_value") or "").splitlines():
                    s = _keep_sub(n, domain)
                    if s:
                        subs.add(s)
                cn = row.get("common_name") or ""
                s = _keep_sub(cn, domain)
                if s:
                    subs.add(s)
            return subs, f"{len(subs)} unique via {len(data)} certs"
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            if attempt == 0:
                await asyncio.sleep(1)
    return subs, last_err


async def _hackertarget(domain: str) -> tuple[dict[str, str], str]:
    """Returns {host: ip_csv}."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    out: dict[str, str] = {}
    try:
        client = await get_client()
        r = await client.get(url, timeout=15)
        body = r.text or ""
        if "API count exceeded" in body or "request limit" in body.lower():
            return out, "rate-limited (50/day)"
        if r.status_code != 200:
            return out, f"HTTP {r.status_code}"
        for ln in body.strip().splitlines():
            if "," not in ln:
                continue
            host, ip = ln.split(",", 1)
            s = _keep_sub(host, domain)
            if s:
                out[s] = ip.strip()
        return out, f"{len(out)} hosts"
    except Exception as e:
        return out, f"{type(e).__name__}: {e}"


async def _certspotter(domain: str) -> tuple[set[str], str]:
    """SSL Mate Certspotter — alternative CT source (free, 100/hour, no key)."""
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           f"&include_subdomains=true&expand=dns_names")
    subs: set[str] = set()
    try:
        client = await get_client()
        r = await client.get(url, headers={"Accept": "application/json",
                                           "User-Agent": "mytools-osint"},
                             timeout=25)
        if r.status_code != 200:
            return subs, f"HTTP {r.status_code}"
        for entry in r.json() or []:
            for name in entry.get("dns_names") or []:
                s = _keep_sub(name, domain)
                if s:
                    subs.add(s)
        return subs, f"{len(subs)} hosts"
    except Exception as e:
        return subs, f"{type(e).__name__}: {e}"


async def _otx(domain: str) -> tuple[set[str], str]:
    """AlienVault OTX passive DNS — free, no key. Hits two endpoints."""
    subs: set[str] = set()
    headers = {"Accept": "application/json", "User-Agent": "mytools-osint"}
    # Endpoint 1: passive_dns gives hostname→ip historic mappings
    # Endpoint 2: url_list (if any) often surfaces fresh subdomains
    last_err = ""
    for path in (f"indicators/domain/{domain}/passive_dns",
                 f"indicators/domain/{domain}/url_list?limit=500"):
        try:
            client = await get_client()
            r = await client.get(f"https://otx.alienvault.com/api/v1/{path}",
                                 headers=headers, timeout=25)
            if r.status_code != 200:
                last_err = f"HTTP {r.status_code}"
                continue
            data = r.json() or {}
            for rec in data.get("passive_dns") or []:
                s = _keep_sub(rec.get("hostname", ""), domain)
                if s:
                    subs.add(s)
            for rec in data.get("url_list") or []:
                u = rec.get("url", "")
                host = u.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
                s = _keep_sub(host, domain)
                if s:
                    subs.add(s)
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
    return subs, f"{len(subs)} hosts" if subs else (last_err or "0 hosts")


async def _subdomain_center(domain: str) -> tuple[set[str], str]:
    """subdomain.center recursive collector."""
    url = f"https://api.subdomain.center/?domain={domain}"
    subs: set[str] = set()
    try:
        client = await get_client()
        r = await client.get(url, headers={"Accept": "application/json"}, timeout=20)
        if r.status_code != 200:
            return subs, f"HTTP {r.status_code}"
        data = r.json() or []
        for host in data:
            s = _keep_sub(host, domain)
            if s:
                subs.add(s)
        return subs, f"{len(subs)} hosts"
    except Exception as e:
        return subs, f"{type(e).__name__}: {e}"


# RapidDNS HTML structure: subdomains appear inside <td>...</td> cells in the
# results table. Match anything that looks like a host ending in our target.
_RAPIDDNS_HOST_RE = re.compile(r"([a-zA-Z0-9][a-zA-Z0-9\-_.]*?[a-zA-Z0-9])")


async def _rapiddns(domain: str) -> tuple[set[str], str]:
    """RapidDNS — HTML scrape (no API)."""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
    subs: set[str] = set()
    try:
        client = await get_client()
        r = await client.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
            timeout=25, follow_redirects=True,
        )
        if r.status_code != 200:
            return subs, f"HTTP {r.status_code}"
        # broad capture: every word that ends with .{domain}
        for m in re.findall(rf"\b([a-zA-Z0-9][a-zA-Z0-9\-_.]*?\.{re.escape(domain)})\b",
                            r.text or ""):
            s = _keep_sub(m, domain)
            if s:
                subs.add(s)
        return subs, f"{len(subs)} hosts"
    except Exception as e:
        return subs, f"{type(e).__name__}: {e}"


async def _wayback(domain: str) -> tuple[set[str], str]:
    """Wayback CDX — matchType=domain enumerates all URLs of a domain + its subs."""
    url = (f"https://web.archive.org/cdx/search/cdx?url={domain}"
           f"&matchType=domain&fl=original&collapse=urlkey&output=text&limit=5000")
    subs: set[str] = set()
    try:
        client = await get_client()
        r = await client.get(url, timeout=40,
                             headers={"User-Agent": "mytools-osint"})
        if r.status_code != 200:
            return subs, f"HTTP {r.status_code}"
        for ln in (r.text or "").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            host = ln.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            s = _keep_sub(host, domain)
            if s:
                subs.add(s)
        return subs, f"{len(subs)} hosts"
    except Exception as e:
        return subs, f"{type(e).__name__}: {e}"


async def _threatminer(domain: str) -> tuple[set[str], str]:
    """ThreatMiner v2 — rt=5 = subdomains."""
    url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
    subs: set[str] = set()
    try:
        client = await get_client()
        r = await client.get(url, headers={"Accept": "application/json"}, timeout=15)
        if r.status_code != 200:
            return subs, f"HTTP {r.status_code}"
        data = r.json() or {}
        if data.get("status_code") in (200, "200"):
            for h in data.get("results", []) or []:
                s = _keep_sub(h, domain)
                if s:
                    subs.add(s)
        return subs, f"{len(subs)} hosts"
    except Exception as e:
        return subs, f"{type(e).__name__}: {e}"


async def _urlscan(domain: str) -> AsyncIterator[Hit]:
    """Recent urlscan.io scans — emit each as its own Hit."""
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
                      status=HitStatus.NOT_FOUND, detail="no recent scans")
            return
        for entry in results[:10]:
            page = entry.get("page") or {}
            task = entry.get("task") or {}
            yield Hit(
                module=NAME, source=f"urlscan: {page.get('url','?')[:60]}",
                category="recon", status=HitStatus.FOUND,
                title=page.get("url") or task.get("url", "?"),
                detail=f"ip={page.get('ip','?')} country={page.get('country','?')} "
                       f"scanned={task.get('time','?')}",
                url=f"https://urlscan.io/result/{entry.get('_id','')}",
                severity=Severity.MEDIUM,
            )
    except Exception as e:
        yield Hit(module=NAME, source="urlscan.io", status=HitStatus.ERROR, detail=str(e))


async def _records(domain: str) -> AsyncIterator[Hit]:
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


# ---- main coroutine -------------------------------------------------------

async def run(query: Query) -> AsyncIterator[Hit]:
    domain = _normalize(query.value)
    if not domain or "." not in domain:
        return

    # DNS records first (fast, useful even when subdomain enum is slow)
    async for h in _records(domain):
        yield h

    # Fan out all subdomain-collection sources in parallel
    tasks = {
        "crt.sh":          asyncio.create_task(_crtsh(domain)),
        "Certspotter":     asyncio.create_task(_certspotter(domain)),
        "HackerTarget":    asyncio.create_task(_hackertarget(domain)),
        "AlienVault OTX":  asyncio.create_task(_otx(domain)),
        "subdomain.center":asyncio.create_task(_subdomain_center(domain)),
        "RapidDNS":        asyncio.create_task(_rapiddns(domain)),
        "Wayback CDX":     asyncio.create_task(_wayback(domain)),
        "ThreatMiner":     asyncio.create_task(_threatminer(domain)),
    }

    all_subs: dict[str, set[str]] = {}    # subdomain -> sources that saw it
    summaries: list[tuple[str, str, int]] = []

    for name, task in tasks.items():
        try:
            result = await task
        except Exception as e:
            yield Hit(module=NAME, source=name, category="subdomain",
                      status=HitStatus.ERROR, detail=str(e))
            continue
        # HackerTarget returns dict[host->ip], others return set
        if isinstance(result[0], dict):
            subs = set(result[0].keys())
            ip_map = result[0]
        else:
            subs = result[0]
            ip_map = {}
        summary = result[1]
        for s in subs:
            all_subs.setdefault(s, set()).add(name)
            if s in ip_map:
                all_subs[s].add(f"IP:{ip_map[s]}")
        summaries.append((name, summary, len(subs)))

    # Emit ONE Hit per discovered subdomain — host visible in source column.
    # Confidence is encoded in Severity: ≥3 sources = HIGH, 2 = MEDIUM, 1 = LOW.
    for sub in sorted(all_subs):
        sources = all_subs[sub]
        ip_marks = [m for m in sources if m.startswith("IP:")]
        passive = [m for m in sources if not m.startswith("IP:")]
        n = len(passive)
        if n >= 3:
            sev = Severity.HIGH
        elif n >= 2:
            sev = Severity.MEDIUM
        else:
            sev = Severity.LOW
        dots = "●" * min(n, 3) + "○" * max(0, 3 - n)
        detail = f"{dots}  seen by {n} source(s): {', '.join(sorted(passive))}"
        if ip_marks:
            detail += "  ·  " + ", ".join(ip_marks)
        yield Hit(
            module=NAME, source=sub, category="subdomain",
            status=HitStatus.FOUND, title=sub,
            detail=detail, url=f"https://{sub}",
            severity=sev, extra={"sources": list(sources), "confidence": n},
        )

    # Per-source summary. Tagged category="summary" so cli.py can hide them by
    # default and only show under --debug. Outage classification:
    #   count > 0     → FOUND (meaningful)
    #   HTTP 5xx/timeout → UNAVAILABLE (service down, NOT our bug)
    #   "0 hosts"     → NO_DATA (service reachable, just empty)
    for name, summary, count in summaries:
        if count > 0:
            yield Hit(
                module=NAME, source=f"{name} (summary)", category="summary",
                status=HitStatus.FOUND, title=name, detail=summary,
                severity=Severity.INFO,
            )
            continue
        s_lower = summary.lower()
        if any(m in s_lower for m in (
            "http 5", "timeout", "remoteproto", "connection",
            "remotedisconnect", "networkerror", "readtimeout", "connecterror",
        )):
            status = HitStatus.UNAVAILABLE
            detail = f"service unavailable — {summary}"
        else:
            status = HitStatus.NO_DATA
            detail = summary or "no data"
        yield Hit(
            module=NAME, source=f"{name} (summary)", category="summary",
            status=status, title=name, detail=detail, severity=Severity.INFO,
        )

    # urlscan.io entries — separate (these are scans, not subdomains)
    async for h in _urlscan(domain):
        yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
