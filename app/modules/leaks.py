"""Paste / ransomware-leak monitoring (C4).

Free sources:
  - Pastebin scrape API     — requires PRO (returns 403 anon). We log+skip.
  - GitHub gists code-search — gracefully SKIPPED without GITHUB_TOKEN.
  - api.ransomware.live      — free, no key. Apex domain match in victim list.

A tiny in-process cache TTL of 1h keeps ransomware.live polite (its endpoints
are popular). The cache is process-scoped: a fresh `osint` invocation will
re-fetch — acceptable for ops use.
"""
from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote_plus

import tldextract

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "leaks"

_TIMEOUT = 15.0
_RANSOMWARE_TTL = 3600.0

# Process-scoped cache. (url -> (expires_at, payload))
_RL_CACHE: dict[str, tuple[float, Any]] = {}


def _cache_get(key: str) -> Any | None:
    item = _RL_CACHE.get(key)
    if not item:
        return None
    exp, payload = item
    if exp < time.time():
        _RL_CACHE.pop(key, None)
        return None
    return payload


def _cache_put(key: str, payload: Any) -> None:
    _RL_CACHE[key] = (time.time() + _RANSOMWARE_TTL, payload)


def _apex(value: str) -> str:
    """Best-effort apex (registrable) domain. Returns lowercased input on failure."""
    v = (value or "").strip().lower()
    if "@" in v:
        v = v.split("@", 1)[1]
    try:
        ext = tldextract.extract(v)
        # `top_domain_under_public_suffix` is the modern name; older releases
        # still have `registered_domain`. Try the new one first, fall back.
        rd = getattr(ext, "top_domain_under_public_suffix", None) or getattr(ext, "registered_domain", "")
        if rd:
            return rd.lower()
    except Exception:
        pass
    return v


# ---- Pastebin --------------------------------------------------------------

async def _pastebin(target: str) -> AsyncIterator[Hit]:
    """Pastebin scrape API requires PRO. Without it the endpoint returns
    'YOUR IP IS NOT REGISTERED' (HTTP 200) or 403; emit ONE INFO hit either way
    so the user knows to upgrade or rely on the gist fallback.
    """
    url = "https://scrape.pastebin.com/api_scraping.php?limit=10"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"Accept": "application/json"})
    except Exception as e:
        yield Hit(module=NAME, source="pastebin", category="leak",
                  url=url, status=classify_exception(e),
                  title=target, detail=f"{type(e).__name__}: {e}")
        return
    body = (r.text or "").strip()
    # Pastebin returns 200 with this plain-text marker when IP isn't whitelisted.
    if "NOT REGISTERED" in body.upper() or r.status_code in (401, 403):
        yield Hit(
            module=NAME, source="pastebin", category="leak",
            url=url, status=HitStatus.SKIPPED, title=target,
            detail="Pastebin scrape requires PRO; falling back to GitHub-gist search",
        )
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="pastebin", category="leak",
                  url=url, status=classify_http(r.status_code),
                  title=target, detail=f"HTTP {r.status_code}")
        return
    # On the rare PRO success path: scan recent pastes for the target string.
    try:
        items = r.json() or []
    except Exception:
        yield Hit(module=NAME, source="pastebin", category="leak",
                  url=url, status=HitStatus.NO_DATA,
                  title=target, detail="unparseable JSON")
        return
    n_hits = 0
    for entry in items if isinstance(items, list) else []:
        body_url = entry.get("scrape_url") or ""
        title = entry.get("title") or "(untitled)"
        if target.lower() in (entry.get("body") or "").lower():
            n_hits += 1
            yield Hit(
                module=NAME, source=f"pastebin:{entry.get('key','?')}",
                category="leak", url=body_url,
                status=HitStatus.FOUND, title=title[:120],
                detail=f"target appears in paste {entry.get('key','?')}",
                severity=Severity.HIGH, confidence=0.9,
                extra={"key": entry.get("key"), "size": entry.get("size")},
            )
    if n_hits == 0:
        yield Hit(module=NAME, source="pastebin", category="leak",
                  status=HitStatus.NO_DATA, title=target,
                  detail="no target mentions in last 10 pastes")


# ---- GitHub gists ----------------------------------------------------------

def _gh_token() -> str:
    return (os.getenv("GITHUB_PAT", "") or os.getenv("GITHUB_TOKEN", "")).strip()


async def _github_gists(target: str) -> AsyncIterator[Hit]:
    """GitHub code-search for the target across .txt-named files (proxy for gists).

    Skipped gracefully without a token (Wave A pattern).
    """
    if not _gh_token():
        yield Hit(module=NAME, source="github-gists", category="leak",
                  status=HitStatus.SKIPPED, title=target,
                  detail="no GITHUB_TOKEN — skipped (set GITHUB_TOKEN to enable)")
        return
    q = quote_plus(f'"{target}" filename:*.txt')
    url = f"https://api.github.com/search/code?q={q}&per_page=10"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {_gh_token()}",
        "User-Agent": "mytools-osint",
    }
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT, headers=headers)
    except Exception as e:
        yield Hit(module=NAME, source="github-gists", category="leak",
                  url=url, status=classify_exception(e),
                  title=target, detail=f"{type(e).__name__}: {e}")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="github-gists", category="leak",
                  url=url, status=classify_http(r.status_code),
                  title=target, detail=f"HTTP {r.status_code}")
        return
    try:
        data = r.json() or {}
    except Exception:
        yield Hit(module=NAME, source="github-gists", category="leak",
                  url=url, status=HitStatus.NO_DATA,
                  title=target, detail="unparseable JSON")
        return
    items = data.get("items") or []
    if not items:
        yield Hit(module=NAME, source="github-gists", category="leak",
                  url=url, status=HitStatus.NO_DATA,
                  title=target, detail="no .txt files mention this target")
        return
    for it in items[:10]:
        repo = (it.get("repository") or {}).get("full_name") or "?"
        path = it.get("path", "?")
        yield Hit(
            module=NAME, source=f"github:{repo}", category="leak",
            url=it.get("html_url", ""),
            status=HitStatus.FOUND, title=f"{repo}/{path}",
            detail=f"{target} appears in {path}",
            severity=Severity.HIGH, confidence=0.85,
            extra={"repo": repo, "path": path},
        )


# ---- ransomware.live -------------------------------------------------------

async def _rl_get(client, url: str) -> Any:
    cached = _cache_get(url)
    if cached is not None:
        return cached
    r = await client.get(url, timeout=_TIMEOUT,
                         headers={"Accept": "application/json",
                                  "User-Agent": "mytools-osint"})
    if r.status_code != 200:
        return {"_error": f"HTTP {r.status_code}"}
    try:
        data = r.json()
    except Exception:
        return {"_error": "unparseable JSON"}
    _cache_put(url, data)
    return data


async def _ransomware_live(target: str) -> AsyncIterator[Hit]:
    """Match the target's apex against recent ransomware victims.

    Endpoint: https://api.ransomware.live/recentvictims  (free, no key)
    """
    apex = _apex(target)
    if not apex or "." not in apex:
        yield Hit(module=NAME, source="ransomware.live", category="leak",
                  status=HitStatus.NO_DATA, title=target,
                  detail="no apex domain to match against")
        return
    url = "https://api.ransomware.live/recentvictims"
    try:
        client = await get_client()
        data = await _rl_get(client, url)
    except Exception as e:
        yield Hit(module=NAME, source="ransomware.live", category="leak",
                  url=url, status=classify_exception(e),
                  title=target, detail=f"{type(e).__name__}: {e}")
        return
    if isinstance(data, dict) and data.get("_error"):
        yield Hit(module=NAME, source="ransomware.live", category="leak",
                  url=url, status=HitStatus.UNAVAILABLE,
                  title=target, detail=str(data["_error"]))
        return
    victims = data if isinstance(data, list) else (data or {}).get("victims") or []
    matches = []
    for v in victims:
        if not isinstance(v, dict):
            continue
        # Compare against any field that plausibly holds a victim name/domain.
        candidates = " ".join(str(v.get(k, "")) for k in (
            "victim", "post_title", "title", "url", "domain")).lower()
        if apex and apex in candidates:
            matches.append(v)
    if not matches:
        yield Hit(module=NAME, source="ransomware.live", category="leak",
                  url=url, status=HitStatus.NO_DATA,
                  title=apex, detail=f"no recent victims match {apex}")
        return
    for v in matches[:5]:
        group = v.get("group_name") or v.get("group") or "?"
        post_url = v.get("post_url") or v.get("url") or url
        yield Hit(
            module=NAME, source=f"ransomware.live:{group}", category="leak",
            url=post_url, status=HitStatus.FOUND, title=apex,
            detail=f"victim listed by {group} ({v.get('discovered','')})",
            severity=Severity.CRITICAL, confidence=0.95,
            extra={"group": group, "victim": v.get("victim"),
                   "discovered": v.get("discovered")},
            evidence={"group": str(group), "match_apex": apex},
        )


# ---- main coroutine -------------------------------------------------------

async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind not in (QueryKind.EMAIL, QueryKind.DOMAIN):
        return
    target = (query.value or "").strip()
    if not target:
        return

    async def _collect(gen):
        return [h async for h in gen]

    tasks = [
        asyncio.create_task(_collect(_pastebin(target))),
        asyncio.create_task(_collect(_github_gists(target))),
        asyncio.create_task(_collect(_ransomware_live(target))),
    ]
    for t in tasks:
        try:
            for h in await t:
                yield h
        except Exception as e:
            yield Hit(module=NAME, source=NAME, category="leak",
                      status=HitStatus.ERROR, detail=str(e))


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.EMAIL, QueryKind.DOMAIN], run)
