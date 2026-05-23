"""Additional FREE email OSINT — no paid key required.

Sources:
  - HIBP breach catalog (public)  — `https://haveibeenpwned.com/api/v3/breaches?domain=<d>`
    returns the catalogue of known breaches AGAINST that domain. This is NOT
    a hit on the specific email — it's contextual intel ("your provider was
    breached N times, here they are"). The per-account lookup is the paid
    endpoint; the catalogue itself is free and unauthenticated.
  - EmailRep (https://emailrep.io/{email}) — reputation, suspicious-domain
    flags, profile aggregator hits. Free 50/day, no key.

Both degrade silently on outage (UNAVAILABLE / RATELIMITED) — never crash.
"""
from __future__ import annotations

from collections.abc import AsyncIterator

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

from .base import clean_email

NAME = "email_extras"

_HIBP_CATALOG = "https://haveibeenpwned.com/api/v3/breaches"
_EMAILREP = "https://emailrep.io/{email}"


async def _hibp_breach_catalog(email: str) -> AsyncIterator[Hit]:
    """Free, unauthenticated catalog lookup: 'which breaches hit this domain?'.

    A `domain=` filter narrows the list to breaches recorded against that
    provider. We DO NOT claim the specific address was leaked — that requires
    the paid /breachedaccount endpoint (covered separately in email.py).
    """
    try:
        domain = email.split("@", 1)[1].lower().strip()
    except IndexError:
        return
    if not domain:
        return
    client = await get_client()
    try:
        r = await client.get(
            _HIBP_CATALOG,
            params={"domain": domain},
            headers={"Accept": "application/json", "User-Agent": "mytools-osint"},
            timeout=10,
        )
    except BaseException as e:
        yield Hit(
            module=NAME, source="HIBP catalog", category="breach",
            status=classify_exception(e), detail=f"{type(e).__name__}: {e}"[:120],
        )
        return

    if r.status_code != 200:
        yield Hit(
            module=NAME, source="HIBP catalog", category="breach",
            status=classify_http(r.status_code), detail=f"HTTP {r.status_code}",
        )
        return
    try:
        breaches = r.json() or []
    except Exception:
        breaches = []
    if not isinstance(breaches, list) or not breaches:
        yield Hit(
            module=NAME, source="HIBP catalog", category="breach",
            status=HitStatus.NO_DATA,
            detail=f"no catalogued breaches against {domain}",
            url="https://haveibeenpwned.com/PwnedWebsites",
        )
        return

    # Sort by date desc so the most recent leak surfaces first.
    breaches.sort(key=lambda b: b.get("BreachDate", ""), reverse=True)
    summary_titles = [b.get("Name", "?") for b in breaches[:8]]
    yield Hit(
        module=NAME, source="HIBP catalog", category="breach",
        status=HitStatus.FOUND,
        title=f"{domain}: {len(breaches)} catalogued breach(es)",
        detail=("known breach(es) against this provider's domain — "
                "not necessarily this specific address. Top: "
                + ", ".join(summary_titles)),
        url="https://haveibeenpwned.com/PwnedWebsites",
        severity=Severity.MEDIUM,
        extra={"domain": domain, "count": len(breaches),
               "names": [b.get("Name") for b in breaches]},
    )
    # Emit the top-5 individually so the result table has named rows.
    for b in breaches[:5]:
        name = b.get("Name", "?")
        date = b.get("BreachDate", "")
        cls = ", ".join((b.get("DataClasses") or [])[:5])
        sensitive = bool(b.get("IsSensitive"))
        yield Hit(
            module=NAME, source=f"HIBP catalog:{name}", category="breach",
            status=HitStatus.FOUND,
            title=b.get("Title") or name,
            detail=f"{date} — {cls}" if cls else date,
            url=f"https://haveibeenpwned.com/PwnedWebsites#{name}",
            severity=Severity.HIGH if sensitive else Severity.MEDIUM,
            extra=b,
        )


def _emailrep_severity(data: dict) -> Severity:
    if data.get("suspicious"):
        return Severity.HIGH
    if (data.get("details") or {}).get("blacklisted"):
        return Severity.HIGH
    rep = (data.get("reputation") or "").lower()
    if rep in ("high",):
        return Severity.LOW
    if rep in ("medium",):
        return Severity.MEDIUM
    return Severity.MEDIUM


async def _emailrep(email: str) -> AsyncIterator[Hit]:
    """Free reputation lookup (50/day, no key). Anonymous source IPs are throttled
    aggressively; treat ratelimits gracefully."""
    url = _EMAILREP.format(email=email)
    client = await get_client()
    try:
        r = await client.get(
            url,
            headers={"Accept": "application/json", "User-Agent": "mytools-osint"},
            timeout=10,
        )
    except BaseException as e:
        yield Hit(
            module=NAME, source="emailrep.io", category="reputation",
            status=classify_exception(e), detail=f"{type(e).__name__}: {e}"[:120],
        )
        return

    if r.status_code == 429:
        yield Hit(
            module=NAME, source="emailrep.io", category="reputation",
            status=HitStatus.RATELIMITED,
            detail="429 — free anon tier is 50/day, slow down or get a key",
            url=url,
        )
        return
    if r.status_code != 200:
        yield Hit(
            module=NAME, source="emailrep.io", category="reputation",
            status=classify_http(r.status_code),
            detail=f"HTTP {r.status_code}", url=url,
        )
        return
    try:
        data = r.json()
    except Exception:
        yield Hit(
            module=NAME, source="emailrep.io", category="reputation",
            status=HitStatus.ERROR, detail="unparseable JSON", url=url,
        )
        return
    if not isinstance(data, dict):
        yield Hit(
            module=NAME, source="emailrep.io", category="reputation",
            status=HitStatus.ERROR,
            detail=f"unexpected JSON shape: {type(data).__name__}", url=url,
        )
        return

    suspicious = bool(data.get("suspicious"))
    details = data.get("details") or {}
    profiles = details.get("profiles") or []
    rep = data.get("reputation") or "unknown"
    refs = details.get("references")
    bits: list[str] = [f"reputation={rep}", f"suspicious={suspicious}"]
    if isinstance(refs, int):
        bits.append(f"refs={refs}")
    if details.get("blacklisted"):
        bits.append("blacklisted=true")
    if details.get("malicious_activity"):
        bits.append("malicious=true")
    if profiles:
        bits.append(f"profiles={','.join(profiles[:5])}")
    yield Hit(
        module=NAME, source="emailrep.io", category="reputation",
        status=HitStatus.FOUND,
        title=f"reputation: {rep}",
        detail=" · ".join(bits),
        url=url,
        severity=_emailrep_severity(data),
        extra=data,
    )
    # Promote each linked profile to its own LOW-severity row — gives the
    # operator a direct pivot point.
    for profile in profiles[:8]:
        yield Hit(
            module=NAME, source=f"emailrep:{profile}", category="profile",
            status=HitStatus.FOUND,
            title=profile,
            detail="linked profile reported by emailrep.io",
            url=url,
            severity=Severity.LOW,
            extra={"profile": profile, "email": email},
        )


async def run(query: Query) -> AsyncIterator[Hit]:
    email = clean_email(query.value)
    if not email or "@" not in email:
        return
    async for h in _hibp_breach_catalog(email):
        yield h
    async for h in _emailrep(email):
        yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.EMAIL], run)
