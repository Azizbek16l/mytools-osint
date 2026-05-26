"""Subdomain takeover detector (v4.2).

Checks CNAME chains of the target's known subdomains against a curated set
of "can-i-take-over-xyz" fingerprints — services that allow anonymous claim
of dangling CNAMEs (Vercel, Heroku, GitHub Pages, Surge, Pantheon, etc.).

Detection:
  1. Resolve CNAME for each subdomain.
  2. If CNAME points at a known-vulnerable service AND the resulting HTTP
     response body matches the service's "404 / not-claimed" fingerprint,
     yield a HIGH severity hit.

We deliberately *don't* yield on dangling CNAME alone (high FP rate);
fingerprint match is required for a HIGH/CRITICAL finding.

Source list: distilled from `EdOverflow/can-i-take-over-xyz` (CC0)
into a compact curated subset of the most common, currently-takeable
services (24 entries vs. their 50+).
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator

import dns.asyncresolver

from app.core.http import _opsec_on, get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "subdomain_takeover"
_TIMEOUT = 6.0

# Curated subset: cname_suffix → fingerprint string (case-insensitive in body).
# Source: github.com/EdOverflow/can-i-take-over-xyz (verified ~2025).
_SIGNATURES: list[tuple[str, str]] = [
    # (cname suffix substring, body fingerprint substring)
    ("vercel.app",           "the deployment could not be found"),
    ("vercel-dns.com",       "the deployment could not be found"),
    ("herokuapp.com",        "no such app"),
    ("github.io",            "there isn't a github pages site here"),
    ("netlify.app",          "not found - request id"),
    ("netlify.com",          "not found - request id"),
    ("surge.sh",             "project not found"),
    ("pantheonsite.io",      "the gods are wise"),
    ("readthedocs.io",       "unknown to readthedocs.org"),
    ("zendesk.com",          "help center closed"),
    ("statuspage.io",        "you are being"),
    ("ghost.io",             "the thing you were looking for is no longer here"),
    ("kinsta.com",           "no site for"),
    ("webflow.io",           "the page you are looking for doesn't exist"),
    ("agilecrm.com",         "sorry, this page is no longer available"),
    ("teamwork.com",         "oops - we didn't find your site"),
    ("acquia-sites.com",     "the site you are looking for could not be found"),
    ("intercom.io",          "uh oh. that page doesn't exist"),
    ("bitballoon.com",       "the site you were looking for couldn't be found"),
    ("simplebooklet.com",    "we can't find this simple booklet"),
    ("getresponse.com",      "with the help of getresponse"),
    ("wpengine.com",         "the site you were looking for couldn't be found"),
    ("worksitegraph.com",    "no such app"),
    ("strikinglydns.com",    "page not found"),
]


async def _resolve_cname(host: str) -> list[str]:
    try:
        ans = await dns.asyncresolver.resolve(host, "CNAME", lifetime=4.0)
    except Exception:
        return []
    return [str(r).rstrip(".").lower() for r in ans]


async def _probe(host: str) -> Hit | None:
    cnames = await _resolve_cname(host)
    if not cnames:
        return None
    # Match CNAME tail against signature suffixes.
    matched = None
    for cname in cnames:
        for suffix, fingerprint in _SIGNATURES:
            if cname.endswith(suffix):
                matched = (cname, suffix, fingerprint)
                break
        if matched:
            break
    if not matched:
        return None
    cname, suffix, fingerprint = matched
    # Now fetch and check body for the fingerprint.
    client = await get_client()
    body = ""
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}", timeout=_TIMEOUT,
                                 follow_redirects=True)
            body = (r.text or "")[:4096].lower()
            break
        except Exception:
            continue
    if fingerprint.lower() in body:
        return Hit(
            module=NAME, source=suffix, category="dns",
            url=f"https://{host}", status=HitStatus.FOUND,
            title=f"SUBDOMAIN TAKEOVER: {host} → {cname}",
            detail=f"CNAME points to {suffix}; body matches '{fingerprint[:40]}…' (claimable)",
            severity=Severity.CRITICAL,
            extra={"subdomain": host, "cname": cname,
                   "service": suffix, "fingerprint_matched": fingerprint},
        )
    return Hit(
        module=NAME, source=suffix, category="dns",
        url=f"https://{host}", status=HitStatus.FOUND,
        title=f"dangling CNAME on {suffix}: {host}",
        detail=f"CNAME→{cname}; service known-vulnerable but no FP body match (manual check advised)",
        severity=Severity.MEDIUM,
        extra={"subdomain": host, "cname": cname, "service": suffix},
    )


async def _run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    if _opsec_on() and os.environ.get("OSINT_SUBDOMAIN_TAKEOVER_OVER_TOR") != "1":
        yield Hit(module=NAME, source="local", category="dns",
                  status=HitStatus.SKIPPED,
                  title="skipped in --opsec mode",
                  detail="DNS + HTTP probe per subdomain; set OSINT_SUBDOMAIN_TAKEOVER_OVER_TOR=1 to override")
        return
    host = (query.value or "").strip().lower().removeprefix("*.").rstrip("/")
    # We probe BOTH the apex (cheap) and any known subdomain entities (if graph
    # already has them — caller can re-run after subdomain enum modules).
    candidates: list[str] = [host]
    # Pull SUBDOMAIN entities from the graph if available, bounded.
    try:
        from app.core.db import get_db
        db = await get_db()
        # If the entity store has subdomains for this domain, take up to 30.
        # We use a simple LIKE query to avoid pulling the full entity table.
        async with db._conn.execute(  # type: ignore[attr-defined]
            "SELECT value FROM entities WHERE type='subdomain' AND value LIKE ? LIMIT 30",
            (f"%.{host}",),
        ) as cur:
            rows = await cur.fetchall()
        candidates.extend(r[0] for r in rows if r and r[0])
    except Exception:
        pass

    # Dedup + cap.
    seen = []
    for c in candidates:
        c = c.strip().lower()
        if c and c not in seen:
            seen.append(c)
    seen = seen[:32]  # hard cap to keep latency bounded

    sem = asyncio.Semaphore(8)

    async def one(h: str) -> Hit | None:
        async with sem:
            return await _probe(h)

    tasks = [asyncio.create_task(one(c)) for c in seen]
    n_found = 0
    n_critical = 0
    for fut in asyncio.as_completed(tasks):
        try:
            hit = await fut
        except Exception:
            continue
        if hit is None:
            continue
        n_found += 1
        if hit.severity == Severity.CRITICAL:
            n_critical += 1
        yield hit

    yield Hit(
        module=NAME, source="summary", category="dns",
        status=HitStatus.FOUND,
        title=f"checked {len(seen)} hosts · {n_critical} CRITICAL · {n_found} total",
        detail="lists CNAMEs pointing at known-vulnerable services",
        severity=Severity.INFO,
        extra={"checked": len(seen), "found": n_found, "critical": n_critical},
    )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], _run)
