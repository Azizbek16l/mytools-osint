"""Email-security posture for a DOMAIN: SPF + DMARC + DKIM (common selectors) + MTA-STS.

All checks are pure DNS / HTTPS, no auth, no rate limits to speak of.
Output is graded A–F so the user can see at a glance whether a domain
is safe to receive mail from. Hardening guidance lives in `detail`.

References:
  RFC 7208 (SPF), RFC 7489 (DMARC), RFC 6376 (DKIM), RFC 8461 (MTA-STS).
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import dns.asyncresolver

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "email_security"

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "mail", "k1", "k2",
    "dkim", "smtpapi", "mandrill", "mailgun", "sendgrid", "amazonses",
    "ses", "20161025", "20150623", "smtp", "fm1", "fm2", "fm3", "s1", "s2",
    "zoho", "everlytickey1", "everlytickey2", "litesrv",
]
_DNS_TIMEOUT = 4.0


async def _resolve_txt(name: str) -> list[str]:
    try:
        ans = await dns.asyncresolver.resolve(name, "TXT", lifetime=_DNS_TIMEOUT)
    except Exception:
        return []
    out: list[str] = []
    for r in ans:
        parts = getattr(r, "strings", None)
        if parts is not None:
            out.append(b"".join(parts).decode("utf-8", errors="replace"))
        else:
            out.append(r.to_text().strip('"'))
    return out


def _grade_spf(records: list[str]) -> tuple[str, Severity, str]:
    spfs = [r for r in records if r.lower().startswith("v=spf1")]
    if not spfs:
        return "F", Severity.HIGH, "no SPF record — spoofers can impersonate this domain"
    if len(spfs) > 1:
        return "D", Severity.HIGH, "multiple SPF records — RFC 7208 invalid, MTAs may ignore both"
    spf = spfs[0]
    if "+all" in spf:
        return "F", Severity.CRITICAL, "SPF ends with +all — anyone can send as this domain"
    if "-all" in spf:
        return "A", Severity.INFO, "SPF -all (strict reject) — good"
    if "~all" in spf:
        return "B", Severity.LOW, "SPF ~all (softfail) — better than nothing but not enforcing"
    if "?all" in spf:
        return "C", Severity.MEDIUM, "SPF ?all (neutral) — equivalent to no policy"
    return "C", Severity.MEDIUM, "SPF has no terminal 'all' qualifier — implicit ?all"


def _grade_dmarc(records: list[str]) -> tuple[str, Severity, str]:
    drs = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not drs:
        return "F", Severity.HIGH, "no DMARC record — no enforcement, no reports"
    if len(drs) > 1:
        return "D", Severity.HIGH, "multiple DMARC records — MTAs may discard policy"
    dmarc = drs[0].lower()
    if "p=reject" in dmarc:
        if "pct=" in dmarc and "pct=100" not in dmarc:
            return "B", Severity.LOW, "p=reject but pct<100 — partial enforcement"
        return "A", Severity.INFO, "p=reject — strict enforcement"
    if "p=quarantine" in dmarc:
        return "B", Severity.LOW, "p=quarantine — suspicious mail in spam, not rejected"
    if "p=none" in dmarc:
        return "D", Severity.MEDIUM, "p=none — monitor only, no enforcement"
    return "D", Severity.MEDIUM, "DMARC present but policy unclear"


async def _check_dkim(domain: str) -> list[str]:
    """Best-effort selector probe — returns the list of found selectors."""

    async def one(sel: str) -> str | None:
        recs = await _resolve_txt(f"{sel}._domainkey.{domain}")
        for r in recs:
            if "v=dkim1" in r.lower() or "p=" in r.lower():
                return sel
        return None

    sem = asyncio.Semaphore(8)

    async def gated(sel: str) -> str | None:
        async with sem:
            return await one(sel)

    results = await asyncio.gather(*[gated(s) for s in COMMON_DKIM_SELECTORS])
    return [s for s in results if s]


async def _check_mta_sts(domain: str) -> tuple[bool, str]:
    try:
        client = await get_client()
        r = await client.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                             timeout=5.0)
        if r.status_code == 200 and "STSv1" in r.text:
            return True, r.text[:120]
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    if not domain:
        return

    spf_recs = await _resolve_txt(domain)
    spf_grade, spf_sev, spf_detail = _grade_spf(spf_recs)
    yield Hit(module=NAME, source="SPF", category="email-security",
              url=f"https://mxtoolbox.com/SuperTool.aspx?action=spf%3a{domain}",
              status=HitStatus.FOUND if any("spf1" in r.lower() for r in spf_recs)
                  else HitStatus.NO_DATA,
              title=f"SPF {spf_grade}", detail=spf_detail, severity=spf_sev,
              extra={"grade": spf_grade,
                     "record": next((r for r in spf_recs if "spf1" in r.lower()), "")})

    dmarc_recs = await _resolve_txt(f"_dmarc.{domain}")
    dmarc_grade, dmarc_sev, dmarc_detail = _grade_dmarc(dmarc_recs)
    yield Hit(module=NAME, source="DMARC", category="email-security",
              url=f"https://mxtoolbox.com/SuperTool.aspx?action=dmarc%3a{domain}",
              status=HitStatus.FOUND if dmarc_recs else HitStatus.NO_DATA,
              title=f"DMARC {dmarc_grade}", detail=dmarc_detail, severity=dmarc_sev,
              extra={"grade": dmarc_grade,
                     "record": next((r for r in dmarc_recs if "dmarc1" in r.lower()), "")})

    dkim_found = await _check_dkim(domain)
    if dkim_found:
        yield Hit(module=NAME, source="DKIM", category="email-security",
                  status=HitStatus.FOUND, title=f"DKIM ({len(dkim_found)} selectors)",
                  detail=f"selectors: {', '.join(dkim_found[:8])}",
                  severity=Severity.INFO, extra={"selectors": dkim_found})
    else:
        yield Hit(module=NAME, source="DKIM", category="email-security",
                  status=HitStatus.NO_DATA, title="DKIM",
                  detail=f"no DKIM key found at {len(COMMON_DKIM_SELECTORS)} common selectors",
                  severity=Severity.MEDIUM)

    has_mta, mta_detail = await _check_mta_sts(domain)
    yield Hit(module=NAME, source="MTA-STS", category="email-security",
              url=f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
              status=HitStatus.FOUND if has_mta else HitStatus.NO_DATA,
              title="MTA-STS", detail=mta_detail if has_mta else "no MTA-STS policy",
              severity=Severity.INFO if has_mta else Severity.LOW)


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
