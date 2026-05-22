"""HTTP security headers — score + fingerprint. Free, no API.

Scoring rubric derived from Mozilla Observatory's published weights:
  HSTS, CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, Cookie security (Secure/HttpOnly/SameSite).
"""
from __future__ import annotations

from collections.abc import AsyncIterator

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "http_headers"


def _ensure_url(value: str) -> str:
    v = value.strip()
    if v.startswith(("http://", "https://")):
        return v
    return f"https://{v}"


def _grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    if score >= 30:
        return "E"
    return "F"


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    url = _ensure_url(query.value)
    try:
        client = await get_client()
        r = await client.get(url, follow_redirects=True, timeout=15)
    except Exception as e:
        from app.core.classify import classify_exception
        yield Hit(module=NAME, source="GET", category="http",
                  status=classify_exception(e), detail=f"{type(e).__name__}: {e}"[:100])
        return

    headers = {k.lower(): v for k, v in r.headers.items()}
    score = 50
    findings: list[tuple[str, int, str]] = []  # (header, score_delta, note)

    # HSTS
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        try:
            ma = int([p.split("=")[1] for p in hsts.split(";")
                      if p.strip().startswith("max-age")][0])
        except Exception:
            ma = 0
        if ma >= 15552000:  # 6 months
            d = 10
            note = "max-age >= 6mo"
            if "includesubdomains" in hsts.lower():
                d += 5; note += " + includeSubDomains"
            if "preload" in hsts.lower():
                d += 5; note += " + preload"
        else:
            d = 3
            note = f"max-age too short ({ma}s)"
        findings.append(("HSTS", d, note))
    else:
        findings.append(("HSTS", -15, "missing — MITM-safe downgrade possible"))

    # CSP
    csp = headers.get("content-security-policy", "")
    if csp:
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            findings.append(("CSP", 3, "present but contains unsafe-* directive"))
        elif "default-src 'none'" in csp.replace('"', "'") or "default-src *" in csp:
            findings.append(("CSP", 5, "present but very permissive or empty"))
        else:
            findings.append(("CSP", 15, "present"))
    else:
        findings.append(("CSP", -20, "missing — XSS protection ad hoc"))

    # Frame-ancestors / XFO
    xfo = headers.get("x-frame-options", "")
    if "frame-ancestors" in csp.lower() or xfo:
        findings.append(("X-Frame", 5, xfo or "via CSP frame-ancestors"))
    else:
        findings.append(("X-Frame", -10, "missing — clickjacking possible"))

    # XCTO
    xcto = headers.get("x-content-type-options", "").lower()
    if xcto == "nosniff":
        findings.append(("X-Content-Type-Options", 5, "nosniff"))
    else:
        findings.append(("X-Content-Type-Options", -5, "missing nosniff"))

    # Referrer-Policy
    rp = headers.get("referrer-policy", "").lower()
    if rp:
        good = rp in {"no-referrer", "strict-origin-when-cross-origin",
                      "strict-origin", "same-origin"}
        findings.append(("Referrer-Policy", 5 if good else 2, rp))
    else:
        findings.append(("Referrer-Policy", -5, "missing"))

    # Permissions-Policy
    if "permissions-policy" in headers:
        findings.append(("Permissions-Policy", 5, "present"))

    # Cookies — quick scan
    cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []
    if not cookies and "set-cookie" in headers:
        cookies = [headers["set-cookie"]]
    weak_cookies = []
    for c in cookies:
        cl = c.lower()
        bits = []
        if "secure" not in cl:
            bits.append("no Secure")
        if "httponly" not in cl:
            bits.append("no HttpOnly")
        if "samesite" not in cl:
            bits.append("no SameSite")
        if bits:
            weak_cookies.append((c.split(";", 1)[0], ", ".join(bits)))
    if weak_cookies:
        findings.append(("Cookies", -10,
                         f"{len(weak_cookies)} cookie(s) missing flags"))

    # Server fingerprint
    for hkey in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if hkey in headers:
            yield Hit(
                module=NAME, source=f"fingerprint:{hkey}", category="fingerprint",
                status=HitStatus.FOUND, title=headers[hkey][:80],
                detail=f"{hkey}: {headers[hkey][:120]}",
                severity=Severity.INFO,
                url=str(r.url),
            )

    # Emit per-finding hits
    for header, delta, note in findings:
        score += delta
        score = max(0, min(100, score))
        sev = Severity.HIGH if delta <= -15 else Severity.MEDIUM if delta < 0 else Severity.INFO
        yield Hit(
            module=NAME, source=header, category="security-header",
            status=HitStatus.FOUND if delta >= 0 else HitStatus.NOT_FOUND,
            title=header,
            detail=f"{'+'if delta>=0 else ''}{delta} · {note}",
            severity=sev,
            url=str(r.url),
            extra={"header": header, "delta": delta, "note": note},
        )
        if weak_cookies and header == "Cookies":
            for name, issues in weak_cookies[:5]:
                yield Hit(
                    module=NAME, source=f"cookie:{name}", category="security-header",
                    status=HitStatus.FOUND, title=name,
                    detail=issues, severity=Severity.MEDIUM,
                    url=str(r.url),
                )

    # Summary
    grade = _grade(score)
    yield Hit(
        module=NAME, source="SUMMARY", category="security-header",
        status=HitStatus.FOUND,
        title=f"grade {grade} · {score}/100",
        detail=f"{len([f for f in findings if f[1]>=0])} positive · "
               f"{len([f for f in findings if f[1]<0])} negative findings",
        severity=Severity.MEDIUM if score < 60 else Severity.INFO,
        url=str(r.url),
        extra={"score": score, "grade": grade},
    )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
