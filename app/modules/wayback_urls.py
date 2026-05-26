"""Wayback Machine CDX URL extractor (v4.2).

Queries the public CDX server (no key, no rate-limit advertised) for every
URL ever archived for the target host or any of its subdomains. Returns a
deduplicated, capped sample plus a summary. Massive free intel: historic
admin paths, leaked params, removed-but-archived staging hostnames, JS
files with secrets, deprecated APIs.

Endpoint: https://web.archive.org/cdx/search/cdx
  ?url=*.example.com/*
  &output=json
  &collapse=urlkey
  &limit=<N>
"""
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from urllib.parse import quote, urlsplit

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "wayback_urls"
_MAX_URLS = 100            # cap CDX response — keep memory + UI sane (smaller = faster)
_TIMEOUT = 12.0            # CDX is slow on busy targets — bail fast not on top of httpx retry
_SAMPLE_PER_KIND = 5       # rows to surface as individual hits per "interesting" path kind

# Heuristic "this URL is interesting" — admin paths, secrets, configs, dev files.
_INTERESTING_RE = (
    "/admin", "/dashboard", "/login", "/api/", "/v1/", "/v2/", "/graphql",
    "/.env", "/.git", "/wp-admin", "/swagger", "/debug", "/backup",
    "/internal", "/private", "/staging", "/dev/", "/test/",
)


async def _run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    host = (query.value or "").strip().lower().removeprefix("*.").rstrip("/")
    # Wildcard subdomains query — surfaces forgotten staging/dev hosts too.
    pattern = quote(f"*.{host}/*", safe="*")
    url = (f"https://web.archive.org/cdx/search/cdx?url={pattern}"
           f"&output=json&collapse=urlkey&limit={_MAX_URLS}")
    client = await get_client()
    try:
        r = await client.get(url, timeout=_TIMEOUT)
    except Exception as e:
        # Timeouts are common — surface cleanly as NO_DATA, not noisy ERROR.
        kind = "timeout" if "Timeout" in type(e).__name__ else "transport-error"
        yield Hit(module=NAME, source="Wayback CDX", category="osint",
                  url=url, status=HitStatus.NO_DATA,
                  title=f"Wayback CDX {kind} for {host}",
                  detail=f"CDX took >{_TIMEOUT}s — try again later or use the larger limit via API directly")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="Wayback CDX", category="osint",
                  url=url, status=HitStatus.NO_DATA,
                  detail=f"HTTP {r.status_code} from CDX")
        return
    try:
        rows = r.json()
    except Exception as e:
        yield Hit(module=NAME, source="Wayback CDX", category="osint",
                  url=url, status=HitStatus.ERROR,
                  detail=f"bad json: {e}")
        return
    if not isinstance(rows, list) or len(rows) <= 1:
        yield Hit(module=NAME, source="Wayback CDX", category="osint",
                  url=url, status=HitStatus.NO_DATA,
                  detail="0 archived URLs for this host")
        return
    # First row is the header (["urlkey","timestamp","original","mimetype","statuscode","digest","length"])
    data = rows[1:]
    archived = [row[2] for row in data if len(row) >= 3]
    # Surface a few interesting-looking URLs as discrete HIGH/MEDIUM hits.
    interesting = []
    for u in archived:
        if any(tok in u.lower() for tok in _INTERESTING_RE):
            interesting.append(u)
    for u in interesting[:_SAMPLE_PER_KIND]:
        yield Hit(module=NAME, source="Wayback CDX", category="osint",
                  url=u, status=HitStatus.FOUND,
                  title=f"historical URL: {u[:80]}",
                  detail="found in Wayback archive (may expose deprecated endpoints / paths)",
                  severity=Severity.MEDIUM,
                  extra={"original": u})
    # Subdomains discovered from URLs — feed the graph.
    sub_seen: set[str] = set()
    for u in archived:
        try:
            netloc = urlsplit(u).netloc.lower().split(":")[0]
            if netloc and netloc != host and netloc.endswith("." + host):
                sub_seen.add(netloc)
        except Exception:
            continue
    for sub in sorted(sub_seen)[:25]:
        yield Hit(module=NAME, source="Wayback CDX", category="dns",
                  url=f"https://{sub}", status=HitStatus.FOUND,
                  title=f"subdomain (historical): {sub}",
                  detail="surfaced from Wayback archive",
                  severity=Severity.LOW,
                  extra={"subdomain": sub})
    # Summary row — always last.
    yield Hit(module=NAME, source="Wayback CDX", category="osint",
              url=url, status=HitStatus.FOUND,
              title=f"{len(archived)} archived URLs · {len(sub_seen)} historical subdomains",
              detail=f"interesting paths: {len(interesting)} · sample capped at {_MAX_URLS}",
              severity=Severity.INFO,
              extra={"total_urls": len(archived), "interesting": len(interesting),
                     "subdomains": len(sub_seen)})


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], _run)
