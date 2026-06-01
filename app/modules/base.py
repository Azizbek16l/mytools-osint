"""Helpers shared by every OSINT module."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import time
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.confidence import score_username_hit
from app.core.http import get_client
from app.core.types import Hit, HitStatus, Severity

log = logging.getLogger("osint.modules.base")


def _safe_search(pattern: str | None, text: str, flags: int = 0) -> bool:
    """re.search that never raises on a malformed site pattern.

    Several site signatures in data/sites.json ship broken regexes; a raw
    re.search would raise re.error mid-probe and abort it. Returns False (no
    match) for an empty or uncompilable pattern instead.
    """
    if not pattern:
        return False
    try:
        return bool(re.search(pattern, text, flags))
    except re.error:
        return False


def md5(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def clean_username(value: str) -> str:
    return value.strip().lstrip("@").strip()


def clean_email(value: str) -> str:
    return value.strip().lower()


def clean_phone(value: str) -> str:
    # keep digits and leading +
    v = value.strip().replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if v.startswith("+"):
        return "+" + re.sub(r"\D", "", v[1:])
    return re.sub(r"\D", "", v)


async def probe_site(
    site: dict[str, Any],
    target: str,
    module: str,
    *,
    timeout: float | None = None,
    retries: int = 0,
) -> Hit:
    """Run one site-signature check. Returns a Hit (positive, negative, or error)."""
    url_template: str = site["url"]
    valid_chars = site.get("valid_chars")
    # A handful of site signatures ship malformed regexes (unbalanced parens,
    # unterminated char-sets). re.match would raise re.error — an *Exception*,
    # not a timeout — which used to propagate out and burn the probe as a bogus
    # ERROR. Treat an unusable valid_chars as "no constraint" so the probe still
    # runs (data-quality bug in the site list, not a reason to fail the probe).
    if valid_chars:
        try:
            ok = bool(re.match(valid_chars, target))
        except re.error as e:
            # Broken pattern in the site list (data-quality bug): don't gate on
            # it and don't burn the probe as a bogus ERROR — but log it so a bad
            # dataset entry is observable. A compile-time test on data/sites.json
            # (test_sites_golden) guards against this slipping in unnoticed.
            log.debug("site %r has an invalid valid_chars regex %r: %s",
                      site.get("name"), valid_chars, e)
            ok = True
        if not ok:
            return Hit(
                module=module,
                source=site["name"],
                category=site.get("category", ""),
                url=url_template.replace("{}", target),
                status=HitStatus.SKIPPED,
                detail="invalid username for site",
            )
    # transforms (e.g. md5 of email for Gravatar)
    transform = site.get("transform")
    target_for_url = target
    if transform == "md5_email":
        target_for_url = md5(target)
    url = url_template.replace("{}", target_for_url).replace("{md5}", md5(target))

    method = site.get("method", "GET").upper()
    headers = site.get("headers") or {}
    client = await get_client()
    started = time.perf_counter()
    attempt = 0
    resp: httpx.Response | None = None
    while True:
        try:
            req_kw: dict[str, Any] = {"headers": headers}
            if timeout is not None:
                req_kw["timeout"] = timeout
            if "data" in site:
                req_kw["data"] = {
                    k: (v.replace("{}", target_for_url) if isinstance(v, str) else v)
                    for k, v in site["data"].items()
                }
            if "json" in site:
                req_kw["json"] = {
                    k: (v.replace("{}", target_for_url) if isinstance(v, str) else v)
                    for k, v in site["json"].items()
                }
            resp = await client.request(method, url, **req_kw)
            break
        except (httpx.TimeoutException, httpx.NetworkError) as e:
            if attempt < retries:
                attempt += 1
                await asyncio.sleep(0.3 * (2**attempt))
                continue
            # A connect/read timeout or DNS failure is transient/unreachable —
            # the site is down or blocking us, not a bug in our code. Surface as
            # UNAVAILABLE so it doesn't pollute the "errors" counter.
            return Hit(
                module=module,
                source=site["name"],
                category=site.get("category", ""),
                url=url,
                status=HitStatus.UNAVAILABLE,
                detail=f"{type(e).__name__}: {e}",
                latency_ms=int((time.perf_counter() - started) * 1000),
            )
    latency = int((time.perf_counter() - started) * 1000)
    code = resp.status_code if resp else 0
    body_text = ""
    if resp is not None and resp.headers.get("content-type", "").lower().startswith(("text/", "application/json", "application/xml")):
        try:
            body_text = resp.text
        except Exception:
            body_text = ""

    check = site.get("check", "status")
    status = HitStatus.UNCERTAIN
    detail = f"HTTP {code}"

    bad_status = site.get("bad_status") or []
    good_status = site.get("good_status") or []

    # Generic 404-in-body markers that single-page JS apps serve with HTTP 200.
    # Tuned to catch the most common SPA-style soft-404s without over-matching.
    _SOFT_404 = (
        "page not found", "user not found", "doesn't exist", "does not exist",
        "no such user", "sorry, that page doesn", "404 - not found",
        "this account doesn't exist", "this page isn", "we couldn't find",
        "не найден", "не существует", "topilmadi",
    )
    body_lower = body_text.lower() if body_text else ""
    soft_404 = body_text != "" and any(m in body_lower for m in _SOFT_404)

    # Extract og:* meta tags + <title> in one shot — used both for the
    # "strong match" check and for enrichment of FOUND hits.
    # Handle either attribute order: property=…content=… OR content=…property=…
    target_lower = target.lower()
    og: dict[str, str] = {}
    page_title = ""
    if body_text:
        for prop in ("og:title", "og:description", "og:image", "og:url", "og:site_name"):
            p = re.escape(prop)
            m = re.search(
                rf'<meta\b[^>]*(?:property|name)=["\']{p}["\'][^>]*content=["\']([^"\']+)',
                body_text, re.IGNORECASE,
            )
            if not m:
                m = re.search(
                    rf'<meta\b[^>]*content=["\']([^"\']+)["\'][^>]*(?:property|name)=["\']{p}["\']',
                    body_text, re.IGNORECASE,
                )
            if m:
                og[prop] = m.group(1).strip()
        m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body_text, re.IGNORECASE)
        if m:
            page_title = m.group(1).strip()
    og_or_title = og.get("og:title") or og.get("og:description") or og.get("og:url") or page_title
    strong_match = bool(og_or_title) and target_lower in og_or_title.lower()

    if code in (403, 429):
        status = HitStatus.RATELIMITED
        detail = f"HTTP {code} (rate-limited)"
    elif check == "status":
        if code in good_status and code not in bad_status:
            if soft_404:
                status = HitStatus.NOT_FOUND
                detail = f"HTTP {code} but body contains 404 marker"
            elif strong_match:
                status = HitStatus.FOUND
                detail = f"HTTP {code} (og/title mentions target)"
            else:
                # 200 from a site we can't strongly verify — downgrade to UNCERTAIN
                status = HitStatus.UNCERTAIN
                detail = f"HTTP {code} (no strong content marker)"
        elif code in bad_status:
            status = HitStatus.NOT_FOUND
        elif 200 <= code < 300:
            if soft_404:
                status = HitStatus.NOT_FOUND
                detail = f"HTTP {code} but body contains 404 marker"
            elif strong_match:
                status = HitStatus.FOUND
                detail = f"HTTP {code} (og/title mentions target)"
            else:
                status = HitStatus.UNCERTAIN
                detail = f"HTTP {code} (no strong content marker)"
        elif 400 <= code < 500:
            status = HitStatus.NOT_FOUND
    elif check == "regex":
        good = site.get("good_regex")
        bad = site.get("bad_regex")
        bm = _safe_search(bad, body_text, re.IGNORECASE | re.DOTALL)
        gm = _safe_search(good, body_text, re.IGNORECASE | re.DOTALL)
        # Status-code-based decision dominates regex match: a 4xx without an
        # explicit good_status override is a strong NOT_FOUND signal even if
        # the body coincidentally matches a generic good_regex like `<title>`.
        if code in bad_status or bm and not gm or 400 <= code < 500 and code not in good_status:
            status = HitStatus.NOT_FOUND
        elif gm and not bm or code in good_status or (200 <= code < 300 and not bad):
            status = HitStatus.FOUND
    elif check == "url":
        final = str(resp.url) if resp else ""
        marker = site.get("bad_url_contains", "")
        if marker and marker in final:
            status = HitStatus.NOT_FOUND
        elif code in good_status or (200 <= code < 300):
            status = HitStatus.FOUND

    # Global FP-guard. For HTTP 200 we cannot trust the status alone:
    #   1. If <title> OR og:title contains an error/404 marker → NOT_FOUND
    #   2. FOUND must be backed by the target appearing in og:url, og:title, or <title>
    #      (NOT the request URL — we constructed that ourselves, so it's tautological)
    if status == HitStatus.FOUND and 200 <= code < 300:
        bad_title_markers = (
            "error", "404", "not found", "doesn't exist", "does not exist",
            "this page isn", "this account doesn", "page isn",
        )
        check_titles = []
        if page_title:
            check_titles.append(page_title.lower())
        if og.get("og:title"):
            check_titles.append(og["og:title"].lower())
        if og.get("og:description"):
            check_titles.append(og["og:description"].lower())
        hit_marker = next((m for t in check_titles for m in bad_title_markers if m in t), None)
        if hit_marker:
            status = HitStatus.NOT_FOUND
            tshort = (og.get("og:title") or page_title or "")[:60]
            detail = f"HTTP {code} but title contains '{hit_marker}': {tshort}"
        else:
            # We deliberately do NOT trust og:url — many SPAs reflect the requested
            # URL back into og:url even on soft-404. og:title / og:description /
            # <title> are stronger signals because they're computed from real
            # profile content.
            verifications = [
                og.get("og:title", ""), og.get("og:description", ""), page_title,
            ]
            if not any(target_lower in v.lower() for v in verifications if v):
                status = HitStatus.UNCERTAIN
                detail = f"HTTP {code} but target absent from og:title/og:description/<title>"

    severity = Severity.MEDIUM if status == HitStatus.FOUND else Severity.INFO

    # Enrichment — attach the og:* fields we already extracted from the response.
    extra: dict[str, Any] = {}
    enrich_bits: list[str] = []
    if og.get("og:title"):
        extra["og_title"] = og["og:title"]
        enrich_bits.append(f"title={og['og:title'][:60]}")
    elif page_title:
        extra["page_title"] = page_title
        enrich_bits.append(f"title={page_title[:60]}")
    if og.get("og:description"):
        extra["og_description"] = og["og:description"]
        enrich_bits.append(f"bio={og['og:description'][:60]}")
    if og.get("og:image"):
        extra["og_image"] = og["og:image"]
        enrich_bits.append(f"img={og['og:image']}")
    if og.get("og:site_name"):
        extra["og_site_name"] = og["og:site_name"]
    if status == HitStatus.FOUND and enrich_bits:
        detail = " | ".join(enrich_bits[:3])

    # Confidence + evidence trail. We score whatever the final status ends up as
    # (a soft-404 downgraded to NOT_FOUND gets ~0.05 — the producer is very
    # sure the account is absent; a bare 200 stays uncertain at ~0.40).
    confidence = score_username_hit(
        code=code, soft_404=soft_404,
        strong_match=strong_match, has_og=bool(og),
    )
    evidence: dict[str, str] = {
        "http_status": str(code),
        "soft_404": "true" if soft_404 else "false",
        "strong_match": "true" if strong_match else "false",
    }
    if og.get("og:title"):
        evidence["og_title_excerpt"] = og["og:title"][:80]
    if page_title:
        evidence["page_title_excerpt"] = page_title[:80]

    return Hit(
        module=module,
        source=site["name"],
        category=site.get("category", ""),
        url=url,
        status=status,
        title=og.get("og:title") or site["name"],
        detail=detail,
        severity=severity,
        latency_ms=latency,
        extra=extra,
        confidence=confidence,
        evidence=evidence,
    )


def _host_key(site: dict[str, Any]) -> str:
    """Registrable-ish host for per-host throttling (last two labels)."""
    host = (urlparse(site.get("url", "")).hostname or site.get("name", "")).lower()
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


async def stream_probes(
    sites: list[dict[str, Any]],
    target: str,
    module: str,
    *,
    concurrency: int = 30,
    timeout: float | None = None,
    retries: int = 0,
    per_host: int = 4,
    hard_timeout: float | None = None,
) -> AsyncIterator[Hit]:
    """Run all site probes concurrently, yielding Hits as they finish.

    Two gates: a global cap (`concurrency`) and a per-host cap (`per_host`).
    Without the per-host cap, bursting ~1000 probes fans dozens of parallel
    hits at sites sharing a WAF/CDN, tripping burst detection → 403/429 storms.

    ``hard_timeout`` (opt-in; ``None`` = off, unchanged for existing callers) is
    a wall-clock ceiling enforced per probe via :func:`asyncio.wait_for`. The
    per-call httpx ``timeout`` bounds each network *phase* (connect/read/…), but
    under a ~1000-way fan-out a probe can still spend tens of seconds queued in
    the shared HTTP/2 pool / event loop and return a valid response far past
    ``timeout`` — measured 30–42s probes on a full username scan. Those tail
    probes serialise through the global gate and dominate total runtime. The
    hard ceiling converts that unbounded tail into a bounded one; a probe that
    blows it is surfaced as UNAVAILABLE (upstream-too-slow, not our bug).
    """
    sem = asyncio.Semaphore(concurrency)
    host_sems: dict[str, asyncio.Semaphore] = {}

    def _host_sem(site: dict[str, Any]) -> asyncio.Semaphore:
        key = _host_key(site)
        s = host_sems.get(key)
        if s is None:
            s = asyncio.Semaphore(per_host)
            host_sems[key] = s
        return s

    async def one(site: dict[str, Any]) -> Hit:
        # Spread the initial wave so 1000 probes don't all hit shared WAFs in the
        # same instant (cheap burst desync; complements the per-host gate).
        await asyncio.sleep(random.uniform(0, 0.12))
        # Per-host gate first (queues same-host probes), then the global cap.
        async with _host_sem(site), sem:
            coro = probe_site(site, target, module, timeout=timeout, retries=retries)
            try:
                if hard_timeout is not None:
                    return await asyncio.wait_for(coro, timeout=hard_timeout)
                return await coro
            except TimeoutError:  # asyncio.TimeoutError is an alias on 3.11+
                # Hard ceiling hit — the site is too slow under load to be worth
                # waiting on. Not our bug, so UNAVAILABLE (keeps it out of the
                # ERROR counter, same as a transport timeout in probe_site).
                return Hit(
                    module=module, source=site.get("name", "?"),
                    category=site.get("category", ""),
                    status=HitStatus.UNAVAILABLE,
                    detail=f"hard timeout >{hard_timeout:g}s (slow under load)",
                )
            except Exception as e:
                # A malformed site signature (e.g. bad regex) must not kill the
                # whole fan-out — surface it as ERROR but keep the site name.
                return Hit(
                    module=module, source=site.get("name", "?"),
                    category=site.get("category", ""),
                    status=HitStatus.ERROR, detail=f"{type(e).__name__}: {e}",
                )

    tasks = [asyncio.create_task(one(s)) for s in sites]
    for fut in asyncio.as_completed(tasks):
        try:
            yield await fut
        except Exception as e:
            yield Hit(module=module, source="?", status=HitStatus.ERROR, detail=str(e))
