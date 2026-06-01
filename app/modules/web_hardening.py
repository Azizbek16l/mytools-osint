"""Web hardening audit: CORS misconfig + cookie security + robots/sitemap + HTTP-method probe.

Four cheap web-app posture checks, one module:

  cors_check       — fetch with Origin: evil.example; flag wildcard or echoed Origin
  cookie_audit     — every Set-Cookie checked for Secure / HttpOnly / SameSite
  robots_sitemap   — fetch /robots.txt + /sitemap.xml; surface unusual paths
  http_methods     — OPTIONS probe; flag TRACE / PUT / DELETE if allowed

Pure HTTP, no auth. Designed to be safe for production targets — only
GET and OPTIONS, no payloads, no state-mutating calls.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator

from app.core.classify import classify_exception
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "web_hardening"

_TIMEOUT = 8.0

INTERESTING_ROBOTS_PATHS = re.compile(
    r"/(admin|administrator|wp-admin|phpmyadmin|api|graphql|debug|trace|"
    r"backup|backups|\.git|\.env|config|console|swagger|openapi|"
    r"actuator|metrics|status|dev|staging|test|internal|private|secret)",
    re.IGNORECASE,
)


# ---------- CORS ------------------------------------------------------------

async def _cors(domain: str) -> AsyncIterator[Hit]:
    url = f"https://{domain}/"
    evil = "https://evil.example"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"Origin": evil,
                                      "User-Agent": "mytools-osint/cors"})
    except Exception as e:
        yield Hit(module=NAME, source="cors", category="web-hardening",
                  url=url, status=classify_exception(e),
                  title=domain, detail=f"{type(e).__name__}: {e}")
        return
    acao = r.headers.get("access-control-allow-origin", "").strip()
    acac = r.headers.get("access-control-allow-credentials", "").strip().lower()
    if not acao:
        yield Hit(module=NAME, source="cors", category="web-hardening",
                  url=url, status=HitStatus.NO_DATA, title=domain,
                  detail="no Access-Control-Allow-Origin header (CORS not exposed)")
        return
    if acao == "*":
        sev = Severity.LOW if acac != "true" else Severity.CRITICAL
        detail = (f"ACAO: * | ACAC: {acac or '(unset)'} — "
                  + ("CRITICAL: wildcard + credentials ⇒ any origin can read auth'd responses"
                     if sev == Severity.CRITICAL
                     else "wildcard ACAO is usually OK for public read-only endpoints"))
        yield Hit(module=NAME, source="cors", category="web-hardening",
                  url=url, status=HitStatus.FOUND, title=domain,
                  detail=detail, severity=sev,
                  extra={"acao": acao, "acac": acac})
        return
    if acao == evil:
        sev = Severity.CRITICAL if acac == "true" else Severity.HIGH
        yield Hit(module=NAME, source="cors", category="web-hardening",
                  url=url, status=HitStatus.FOUND, title=domain,
                  detail=f"ACAO echoes any Origin (saw: {evil}) | ACAC={acac} "
                         "— attacker site can pivot off auth'd browser sessions",
                  severity=sev,
                  extra={"acao": acao, "acac": acac, "origin_echo": True})
        return
    yield Hit(module=NAME, source="cors", category="web-hardening",
              url=url, status=HitStatus.NO_DATA, title=domain,
              detail=f"ACAO restricted to: {acao[:80]}",
              extra={"acao": acao, "acac": acac})


# ---------- cookies ---------------------------------------------------------

async def _cookies(domain: str) -> AsyncIterator[Hit]:
    url = f"https://{domain}/"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT)
    except Exception as e:
        yield Hit(module=NAME, source="cookie-audit", category="web-hardening",
                  url=url, status=classify_exception(e),
                  title=domain, detail=f"{type(e).__name__}: {e}")
        return
    set_cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") \
        else [r.headers.get("set-cookie", "")] if r.headers.get("set-cookie") else []
    if not set_cookies:
        yield Hit(module=NAME, source="cookie-audit", category="web-hardening",
                  url=url, status=HitStatus.NO_DATA, title=domain,
                  detail="no Set-Cookie headers in response")
        return
    issues: list[str] = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        miss = []
        if "secure" not in low:
            miss.append("Secure")
        if "httponly" not in low:
            miss.append("HttpOnly")
        if "samesite" not in low:
            miss.append("SameSite")
        if miss:
            issues.append(f"{name} missing: {', '.join(miss)}")
    if issues:
        # Worst-case severity: HIGH if a session cookie is missing HttpOnly+Secure
        sev = Severity.HIGH if any("session" in i.lower() or "auth" in i.lower()
                                    or "token" in i.lower() for i in issues) \
              else Severity.MEDIUM
        yield Hit(module=NAME, source="cookie-audit", category="web-hardening",
                  url=url, status=HitStatus.FOUND, title=domain,
                  detail=" | ".join(issues[:5]) +
                         (f" | …+{len(issues)-5}" if len(issues) > 5 else ""),
                  severity=sev,
                  extra={"issues": issues, "cookies_seen": len(set_cookies)})
    else:
        yield Hit(module=NAME, source="cookie-audit", category="web-hardening",
                  url=url, status=HitStatus.FOUND, title=domain,
                  detail=f"{len(set_cookies)} cookie(s) all set with Secure+HttpOnly+SameSite",
                  severity=Severity.INFO)


# ---------- robots + sitemap ------------------------------------------------

async def _robots_sitemap(domain: str) -> AsyncIterator[Hit]:
    base = f"https://{domain}"
    for path, label in (("/robots.txt", "robots.txt"),
                         ("/sitemap.xml", "sitemap.xml")):
        url = base + path
        try:
            client = await get_client()
            r = await client.get(url, timeout=_TIMEOUT)
        except Exception as e:
            yield Hit(module=NAME, source=label, category="web-hardening",
                      url=url, status=classify_exception(e),
                      title=domain, detail=f"{type(e).__name__}: {e}")
            continue
        if r.status_code != 200 or not r.text:
            yield Hit(module=NAME, source=label, category="web-hardening",
                      url=url, status=HitStatus.NO_DATA, title=domain,
                      detail=f"HTTP {r.status_code}")
            continue
        body = r.text[:50000]
        interesting = INTERESTING_ROBOTS_PATHS.findall(body)
        unique = sorted({m.lower() for m in interesting})
        if unique:
            yield Hit(module=NAME, source=label, category="web-hardening",
                      url=url, status=HitStatus.FOUND, title=domain,
                      detail=f"{len(unique)} interesting path(s): "
                             f"{', '.join('/'+u for u in unique[:8])}"
                             + (f" …+{len(unique)-8}" if len(unique) > 8 else ""),
                      severity=Severity.MEDIUM,
                      extra={"paths": unique})
        else:
            yield Hit(module=NAME, source=label, category="web-hardening",
                      url=url, status=HitStatus.FOUND, title=domain,
                      detail=f"{label} present, no obviously-sensitive paths",
                      severity=Severity.INFO,
                      extra={"size_bytes": len(r.text)})


# ---------- HTTP methods ----------------------------------------------------

async def _methods(domain: str) -> AsyncIterator[Hit]:
    url = f"https://{domain}/"
    try:
        client = await get_client()
        r = await client.request("OPTIONS", url, timeout=_TIMEOUT)
    except Exception as e:
        yield Hit(module=NAME, source="http-methods", category="web-hardening",
                  url=url, status=classify_exception(e),
                  title=domain, detail=f"{type(e).__name__}: {e}")
        return
    allow = r.headers.get("allow", "").strip()
    if not allow:
        yield Hit(module=NAME, source="http-methods", category="web-hardening",
                  url=url, status=HitStatus.NO_DATA, title=domain,
                  detail="server doesn't expose Allow header on OPTIONS")
        return
    methods = sorted({m.strip().upper() for m in allow.split(",") if m.strip()})
    dangerous = sorted(set(methods) & {"PUT", "DELETE", "TRACE", "TRACK", "PATCH",
                                        "CONNECT"})
    if dangerous:
        sev = Severity.HIGH if "TRACE" in dangerous or "TRACK" in dangerous \
              else Severity.MEDIUM
        yield Hit(module=NAME, source="http-methods", category="web-hardening",
                  url=url, status=HitStatus.FOUND, title=domain,
                  detail=f"OPTIONS allows: {', '.join(methods)} | dangerous: {', '.join(dangerous)}",
                  severity=sev,
                  extra={"methods": methods, "dangerous": dangerous})
    else:
        yield Hit(module=NAME, source="http-methods", category="web-hardening",
                  url=url, status=HitStatus.FOUND, title=domain,
                  detail=f"OPTIONS allows: {', '.join(methods)} — looks fine",
                  severity=Severity.INFO,
                  extra={"methods": methods})


# ---------- orchestrator ----------------------------------------------------

async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    if not domain:
        return

    async def collect(gen: AsyncIterator[Hit]) -> list[Hit]:
        return [h async for h in gen]

    tasks = [
        asyncio.create_task(collect(_cors(domain))),
        asyncio.create_task(collect(_cookies(domain))),
        asyncio.create_task(collect(_robots_sitemap(domain))),
        asyncio.create_task(collect(_methods(domain))),
    ]
    for fut in asyncio.as_completed(tasks):
        try:
            hits = await fut
        except Exception as e:
            yield Hit(module=NAME, source=NAME, status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")
            continue
        for h in hits:
            yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
