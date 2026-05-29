"""Search-engine dorking (C3).

Two free SERPs: DuckDuckGo HTML + Bing. One query per engine per dork — the
total request budget per target is small on purpose (rate limits will mask the
signal otherwise). 4-6 dorks per kind, 30 results parsed max per response.

Parsing is defensive: we use regex over `<a href=…>` + nearby text so a single
class-name change at DDG/Bing doesn't break the module.
"""
from __future__ import annotations

import asyncio
import html
import re
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, quote_plus, urlparse

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "dorks"

_TIMEOUT = 18.0
_MAX_RESULTS = 30

# DDG HTML lite endpoint returns plain anchor tags + result snippets — robust.
_DDG_URL = "https://html.duckduckgo.com/html/?q={q}"
_BING_URL = "https://www.bing.com/search?q={q}&count=30"

# Dork templates per kind. Keep these small; each extra dork doubles ban-rate.
DORKS_DOMAIN = [
    'site:{} filetype:pdf',
    'site:{} "internal" OR "confidential"',
    'intitle:"index of" site:{}',
    'inurl:wp-admin site:{}',
]
DORKS_EMAIL = [
    '"{}"',
    '"{}" site:pastebin.com',
    '"{}" site:github.com',
]
DORKS_USERNAME = [
    '"{}" site:reddit.com',
    '"{}" site:github.com',
    '"{}" site:linkedin.com',
]


def _dorks_for(kind: QueryKind, target: str) -> list[str]:
    if kind == QueryKind.DOMAIN:
        tpls = DORKS_DOMAIN
    elif kind == QueryKind.EMAIL:
        tpls = DORKS_EMAIL
    elif kind == QueryKind.USERNAME:
        tpls = DORKS_USERNAME
    else:
        return []
    return [t.format(target) for t in tpls]


# ---- SERP parsers ---------------------------------------------------------

# DDG HTML lite: result anchors live in `class="result__a"` and target the URL
# via an internal redirector (uddg=…). We extract the final URL from the query.
_DDG_RESULT_RE = re.compile(
    r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)

# Bing: each result is wrapped in <li class="b_algo"> with an <h2><a href="…">
_BING_RESULT_RE = re.compile(
    r'<li[^>]*class="b_algo"[^>]*>.*?<h2[^>]*>\s*<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)


def _strip(text: str) -> str:
    """Remove tags + decode HTML entities. Keeps the result title readable."""
    return html.unescape(re.sub(r"<[^>]+>", "", text)).strip()


def _unwrap_ddg_url(raw: str) -> str:
    """DDG's lite SERP wraps real URLs in /l/?uddg=<encoded>."""
    if raw.startswith(("http://", "https://")):
        return raw
    try:
        p = urlparse(raw if raw.startswith("//") is False else "https:" + raw)
        if "uddg" in (p.query or ""):
            qs = parse_qs(p.query)
            return qs.get("uddg", [""])[0] or raw
    except Exception:
        pass
    return raw


def _parse_ddg(html_text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in _DDG_RESULT_RE.finditer(html_text):
        url = _unwrap_ddg_url(m.group(1))
        title = _strip(m.group(2))
        if url and title:
            out.append((title, url))
        if len(out) >= _MAX_RESULTS:
            break
    return out


def _parse_bing(html_text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for m in _BING_RESULT_RE.finditer(html_text):
        url = m.group(1)
        title = _strip(m.group(2))
        if url and title:
            out.append((title, url))
        if len(out) >= _MAX_RESULTS:
            break
    return out


# ---- per-engine query -----------------------------------------------------

async def _query(engine: str, url: str, dork: str) -> AsyncIterator[Hit]:
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"Accept": "text/html"})
    except Exception as e:
        yield Hit(module=NAME, source=engine, category="serp",
                  status=HitStatus.UNAVAILABLE, title=dork,
                  detail=f"{type(e).__name__}: {e}")
        return
    if r.status_code == 429:
        yield Hit(module=NAME, source=engine, category="serp",
                  status=HitStatus.RATELIMITED, title=dork,
                  detail="HTTP 429 — backoff required")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source=engine, category="serp",
                  status=HitStatus.UNAVAILABLE, title=dork,
                  detail=f"HTTP {r.status_code}")
        return
    body = r.text or ""
    parser = _parse_ddg if engine == "DuckDuckGo" else _parse_bing
    results = parser(body)
    if not results:
        # 200 but no results matched — could be honest zero, or SERP layout
        # drift. Either way: NO_DATA + a hint to file an issue.
        yield Hit(
            module=NAME, source=engine, category="serp",
            status=HitStatus.NO_DATA, title=dork,
            detail="SERP layout drift — please file an issue",
            evidence={"engine": engine, "dork": dork[:120]},
        )
        return
    for title, target_url in results:
        yield Hit(
            module=NAME, source=engine, category="serp",
            status=HitStatus.FOUND, title=title[:160],
            detail=f"dork: {dork}",
            url=target_url, severity=Severity.MEDIUM,
            confidence=0.7,
            evidence={"engine": engine, "dork": dork[:120]},
        )


# ---- main coroutine -------------------------------------------------------

async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind not in (QueryKind.DOMAIN, QueryKind.EMAIL, QueryKind.USERNAME):
        return
    target = (query.value or "").strip().lstrip("@")
    if not target:
        return
    dorks = _dorks_for(query.kind, target)
    if not dorks:
        return

    # One request per (engine, dork). Engines run in parallel; dorks within an
    # engine run sequentially to stay polite.
    async def _engine_runner(engine: str, url_tpl: str) -> list[Hit]:
        out: list[Hit] = []
        for dork in dorks:
            url = url_tpl.format(q=quote_plus(dork))
            async for h in _query(engine, url, dork):
                out.append(h)
        return out

    tasks = [
        asyncio.create_task(_engine_runner("DuckDuckGo", _DDG_URL)),
        asyncio.create_task(_engine_runner("Bing", _BING_URL)),
    ]
    n_results = 0
    for t in tasks:
        try:
            for h in await t:
                if h.status == HitStatus.FOUND:
                    n_results += 1
                yield h
        except Exception as e:
            yield Hit(module=NAME, source="dorks", category="serp",
                      status=HitStatus.ERROR, detail=str(e))
    yield Hit(
        module=NAME, source="summary", category="serp",
        status=HitStatus.FOUND if n_results else HitStatus.NO_DATA,
        title=target,
        detail=f"{n_results} result(s) across {len(dorks)} dork(s) × 2 engines",
        severity=Severity.INFO,
        extra={"results": n_results, "dorks": len(dorks)},
    )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN, QueryKind.EMAIL, QueryKind.USERNAME], run)
