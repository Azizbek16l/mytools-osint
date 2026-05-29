"""OpenCorporates business-records recon (C5).

Single free source: api.opencorporates.com search endpoint.
  - works without an API key (rate-limited)
  - 429 → UNAVAILABLE + hint to set OPENCORPORATES_API_KEY

Emits Hits for each top-result company: name, jurisdiction, incorporation date,
status, registered address, and the first three officer names. A tiny built-in
'nominee director' list raises a Severity.MEDIUM red flag.
"""
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from urllib.parse import quote_plus

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "business"
_TIMEOUT = 18.0
_MAX_COMPANIES = 5

# Hand-picked nominee-service flags — common UK / offshore patterns. Not
# exhaustive: just enough to surface the obvious cases.
_NOMINEE_PATTERNS = (
    "nominee services",
    "director services",
    "secretarial services",
    "company services limited",
    "corporate nominees",
    "appleby corporate services",
    "trident corporate services",
    "ocra (mauritius)",
    "ocorian",
    "vistra",
)


def _has_nominee(name: str) -> bool:
    n = (name or "").lower()
    return any(p in n for p in _NOMINEE_PATTERNS)


def _api_key() -> str:
    return os.getenv("OPENCORPORATES_API_KEY", "").strip()


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.COMPANY:
        return
    name = (query.value or "").strip()
    if len(name) < 3:
        yield Hit(module=NAME, source="opencorporates", category="corp",
                  status=HitStatus.NO_DATA, title=name,
                  detail="company name too short (<3 chars)")
        return

    url = ("https://api.opencorporates.com/v0.4/companies/search"
           f"?q={quote_plus(name)}&format=json")
    if _api_key():
        url += f"&api_token={_api_key()}"

    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"Accept": "application/json"})
    except Exception as e:
        yield Hit(module=NAME, source="opencorporates", category="corp",
                  url=url, status=classify_exception(e),
                  title=name, detail=f"{type(e).__name__}: {e}")
        return

    if r.status_code == 429:
        yield Hit(module=NAME, source="opencorporates", category="corp",
                  url=url, status=HitStatus.UNAVAILABLE, title=name,
                  detail="HTTP 429 — set OPENCORPORATES_API_KEY for higher quota")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="opencorporates", category="corp",
                  url=url, status=classify_http(r.status_code),
                  title=name, detail=f"HTTP {r.status_code}")
        return
    try:
        data = r.json() or {}
    except Exception:
        yield Hit(module=NAME, source="opencorporates", category="corp",
                  url=url, status=HitStatus.NO_DATA,
                  title=name, detail="unparseable JSON")
        return

    companies = (((data.get("results") or {}).get("companies")) or [])
    if not companies:
        yield Hit(module=NAME, source="opencorporates", category="corp",
                  url=url, status=HitStatus.NO_DATA, title=name,
                  detail="no companies match this name")
        return

    n_active = 0
    n_nominee = 0
    for entry in companies[:_MAX_COMPANIES]:
        c = entry.get("company") or {}
        company_name = c.get("name") or "?"
        jurisdiction = c.get("jurisdiction_code") or "?"
        inc_date = c.get("incorporation_date") or ""
        status = (c.get("current_status") or "").strip()
        address = c.get("registered_address_in_full") or ""
        oc_url = c.get("opencorporates_url") or url
        officers = c.get("officers") or []
        # Some endpoints embed officers under a different key; fall back.
        if not officers:
            officers = (entry.get("officers") or [])
        names = []
        for o in officers:
            if isinstance(o, dict):
                nm = (o.get("officer") or {}).get("name") or o.get("name")
                if nm:
                    names.append(nm)
        names = names[:3]

        is_active = status.lower() in ("active", "registered", "live")
        if is_active:
            n_active += 1
        sev = Severity.MEDIUM if is_active else Severity.LOW
        detail_bits = [f"jurisdiction={jurisdiction}"]
        if inc_date:
            detail_bits.append(f"incorporated={inc_date}")
        if status:
            detail_bits.append(f"status={status}")
        if address:
            detail_bits.append(f"address={address[:60]}")
        if names:
            detail_bits.append("officers=" + ", ".join(names))
        yield Hit(
            module=NAME, source=f"opencorporates:{jurisdiction}",
            category="corp", url=oc_url,
            status=HitStatus.FOUND, title=company_name,
            detail=" · ".join(detail_bits),
            severity=sev,
            confidence=0.9 if is_active else 0.75,
            extra={"jurisdiction": jurisdiction, "status": status,
                   "incorporation_date": inc_date, "officers": names,
                   "address": address},
            evidence={"jurisdiction": jurisdiction,
                      "status": status, "officers": ", ".join(names)[:200]},
        )
        for nm in names:
            if _has_nominee(nm):
                n_nominee += 1
                yield Hit(
                    module=NAME, source=f"nominee:{nm}", category="corp",
                    url=oc_url, status=HitStatus.FOUND,
                    title=f"nominee officer at {company_name}",
                    detail=f"officer name '{nm}' matches nominee-services heuristic",
                    severity=Severity.MEDIUM, confidence=0.85,
                    extra={"officer": nm, "company": company_name},
                    evidence={"officer": nm, "heuristic": "nominee_services"},
                )

    yield Hit(
        module=NAME, source="summary", category="corp",
        status=HitStatus.FOUND if companies else HitStatus.NO_DATA,
        title=name,
        detail=(f"{len(companies)} match(es), {n_active} active, "
                f"{n_nominee} nominee-flag(s)"),
        severity=Severity.INFO,
        extra={"matches": len(companies),
               "active": n_active, "nominee_flags": n_nominee},
    )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.COMPANY], run)
