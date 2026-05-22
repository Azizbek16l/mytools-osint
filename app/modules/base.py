"""Helpers shared by every OSINT module."""
from __future__ import annotations

import asyncio
import hashlib
import re
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx

from app.core.http import get_client
from app.core.types import Hit, HitStatus, Severity


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
    if valid_chars and not re.match(valid_chars, target):
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
                req_kw["data"] = {k: v.replace("{}", target_for_url) for k, v in site["data"].items()}
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
            return Hit(
                module=module,
                source=site["name"],
                category=site.get("category", ""),
                url=url,
                status=HitStatus.ERROR,
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
        bm = bool(bad and re.search(bad, body_text, re.IGNORECASE | re.DOTALL))
        gm = bool(good and re.search(good, body_text, re.IGNORECASE | re.DOTALL))
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
    )


async def stream_probes(
    sites: list[dict[str, Any]],
    target: str,
    module: str,
    *,
    concurrency: int = 30,
    timeout: float | None = None,
    retries: int = 0,
) -> AsyncIterator[Hit]:
    """Run all site probes concurrently, yielding Hits as they finish."""
    sem = asyncio.Semaphore(concurrency)

    async def one(site: dict[str, Any]) -> Hit:
        async with sem:
            return await probe_site(site, target, module, timeout=timeout, retries=retries)

    tasks = [asyncio.create_task(one(s)) for s in sites]
    for fut in asyncio.as_completed(tasks):
        try:
            yield await fut
        except Exception as e:
            yield Hit(module=module, source="?", status=HitStatus.ERROR, detail=str(e))
