"""Email OSINT.

Sources:
  - email-validator format check + DNS MX
  - HaveIBeenPwned (key required) — breaches + pastes
  - XposedOrNot (FREE, no key) — breach lookup
  - Hudson Rock Cavalier (FREE, no key) — info-stealer compromised credentials
  - ProxyNova ComB (FREE, no key) — combo list / paste search
  - Gravatar (HEAD on hash)
  - Holehe-style site enum (data/holehe_sites.json) — soft probes, may rate-limit
  - Username derivation: try email's local-part as a username on top sites
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import dns.asyncresolver
from email_validator import EmailNotValidError, validate_email

from app.core.confidence import score_breach_hit, score_email_format_hit
from app.core.config import settings
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

from .base import clean_email, md5, stream_probes

NAME = "email"
_HOLEHE_PATH = Path(__file__).resolve().parents[2] / "data" / "holehe_sites.json"


def _load_holehe() -> list[dict[str, Any]]:
    try:
        sites = json.loads(_HOLEHE_PATH.read_text(encoding="utf-8")).get("sites", [])
        return cast("list[dict[str, Any]]", sites)
    except Exception:
        return []


async def _validate(email: str) -> Hit:
    try:
        info = validate_email(email, check_deliverability=False)
        return Hit(
            module=NAME, source="format", category="validation",
            status=HitStatus.FOUND, title="email format valid",
            detail=f"local={info.local_part} domain={info.domain}",
            extra={"local": info.local_part, "domain": info.domain},
            confidence=score_email_format_hit(format_valid=True, mx_present=False),
            evidence={"format_valid": "true"},
        )
    except EmailNotValidError as e:
        return Hit(
            module=NAME, source="format", category="validation",
            status=HitStatus.NOT_FOUND, title="email format invalid",
            detail=str(e), severity=Severity.LOW,
            confidence=score_email_format_hit(format_valid=False, mx_present=False),
            evidence={"format_valid": "false", "reason": str(e)[:160]},
        )


async def _mx(email: str) -> Hit:
    try:
        domain = email.split("@", 1)[1]
    except IndexError:
        return Hit(module=NAME, source="mx", status=HitStatus.ERROR, detail="no domain")
    try:
        answers = await dns.asyncresolver.resolve(domain, "MX", lifetime=5)
        hosts = sorted({str(a.exchange).rstrip(".") for a in answers})
        return Hit(
            module=NAME, source="mx", category="validation",
            status=HitStatus.FOUND if hosts else HitStatus.NOT_FOUND,
            title=f"MX records for {domain}",
            detail=", ".join(hosts[:5]),
            extra={"mx": hosts},
            confidence=score_email_format_hit(format_valid=True, mx_present=bool(hosts)),
            evidence={"mx_count": str(len(hosts)),
                      "mx_first": hosts[0] if hosts else ""},
        )
    except Exception as e:
        return Hit(module=NAME, source="mx", status=HitStatus.ERROR, detail=str(e))


async def _gravatar(email: str) -> Hit:
    h = md5(email)
    url = f"https://www.gravatar.com/avatar/{h}?d=404"
    client = await get_client()
    try:
        r = await client.head(url)
        if r.status_code == 200:
            return Hit(
                module=NAME, source="Gravatar", category="profile",
                status=HitStatus.FOUND, url=f"https://en.gravatar.com/{h}",
                detail="avatar present", severity=Severity.MEDIUM,
                extra={"hash": h},
            )
        return Hit(
            module=NAME, source="Gravatar", category="profile",
            status=HitStatus.NOT_FOUND, url=url, detail=f"HTTP {r.status_code}",
        )
    except Exception as e:
        return Hit(module=NAME, source="Gravatar", status=HitStatus.ERROR, detail=str(e))


async def _hibp(email: str) -> AsyncIterator[Hit]:
    s = settings()
    if not s.has_hibp:
        yield Hit(
            module=NAME, source="HIBP", category="breach",
            status=HitStatus.SKIPPED, detail="set HIBP_API_KEY in .env",
        )
        return
    client = await get_client()
    headers = {"hibp-api-key": s.hibp_api_key, "user-agent": "mytools-osint"}
    base = "https://haveibeenpwned.com/api/v3"
    try:
        r = await client.get(
            f"{base}/breachedaccount/{email}?truncateResponse=false", headers=headers
        )
        if r.status_code == 200:
            breaches = r.json() if isinstance(r.json(), list) else []
            for b in breaches:
                yield Hit(
                    module=NAME, source=f"HIBP:{b.get('Name','?')}", category="breach",
                    status=HitStatus.FOUND,
                    title=b.get("Title", b.get("Name", "")),
                    detail=f"{b.get('BreachDate','')} — {', '.join(b.get('DataClasses', [])[:6])}",
                    url=f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name','')}",
                    severity=Severity.HIGH if b.get("IsSensitive") else Severity.MEDIUM,
                    extra=b,
                    confidence=score_breach_hit(
                        source_authoritative=True,
                        has_password="Passwords" in (b.get("DataClasses") or []),
                    ),
                    evidence={
                        "breach": str(b.get("Name", "")),
                        "breach_date": str(b.get("BreachDate", "")),
                        "data_classes": ", ".join(b.get("DataClasses", [])[:6]),
                    },
                )
        elif r.status_code == 404:
            yield Hit(module=NAME, source="HIBP", category="breach",
                      status=HitStatus.NOT_FOUND, detail="no breaches")
        elif r.status_code == 401:
            yield Hit(module=NAME, source="HIBP", category="breach",
                      status=HitStatus.ERROR, detail="invalid key")
        else:
            yield Hit(module=NAME, source="HIBP", category="breach",
                      status=HitStatus.UNCERTAIN, detail=f"HTTP {r.status_code}")
    except Exception as e:
        yield Hit(module=NAME, source="HIBP", status=HitStatus.ERROR, detail=str(e))


async def _xposedornot(email: str) -> AsyncIterator[Hit]:
    """FREE breach lookup — no API key needed.
    https://xposedornot.com/api_doc
    """
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        client = await get_client()
        r = await client.get(url, headers={"Accept": "application/json"})
        if r.status_code == 200:
            data = r.json() or {}
            breaches = (data.get("breaches") or [[]])[0] if isinstance(data.get("breaches"), list) else []
            if not breaches:
                yield Hit(module=NAME, source="XposedOrNot", category="breach",
                          status=HitStatus.NOT_FOUND, detail="no breaches reported")
                return
            for name in breaches:
                yield Hit(
                    module=NAME, source=f"XposedOrNot:{name}", category="breach",
                    status=HitStatus.FOUND,
                    title=name,
                    detail="breach reported by XposedOrNot",
                    url=f"https://xposedornot.com/breaches/{name}",
                    severity=Severity.HIGH,
                    extra={"breach_name": name},
                )
        elif r.status_code == 404:
            yield Hit(module=NAME, source="XposedOrNot", category="breach",
                      status=HitStatus.NOT_FOUND, detail="no breaches reported")
        elif r.status_code in (429, 403):
            yield Hit(module=NAME, source="XposedOrNot", category="breach",
                      status=HitStatus.RATELIMITED, detail=f"HTTP {r.status_code}")
        else:
            yield Hit(module=NAME, source="XposedOrNot", category="breach",
                      status=HitStatus.UNCERTAIN, detail=f"HTTP {r.status_code}")
    except Exception as e:
        yield Hit(module=NAME, source="XposedOrNot", category="breach",
                  status=HitStatus.ERROR, detail=str(e))


async def _hudson_rock(email: str) -> AsyncIterator[Hit]:
    """FREE info-stealer compromised-credential check (no key, personal use).
    https://cavalier.hudsonrock.com/api
    """
    url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
    try:
        client = await get_client()
        r = await client.get(url, params={"email": email}, headers={"Accept": "application/json"})
        if r.status_code == 200:
            data = r.json() or {}
            stealers = data.get("stealers") or []
            if not stealers:
                msg = data.get("message", "no info-stealer infections found")
                yield Hit(module=NAME, source="HudsonRock", category="breach",
                          status=HitStatus.NOT_FOUND, detail=str(msg)[:120])
                return
            for s_ in stealers[:25]:
                date = s_.get("date_compromised") or s_.get("date_uploaded") or ""
                comp = s_.get("computer_name") or "?"
                os_ = s_.get("operating_system") or "?"
                family = s_.get("stealer_family") or "?"
                yield Hit(
                    module=NAME, source=f"HudsonRock:{family}", category="breach",
                    status=HitStatus.FOUND,
                    title=f"infostealer infection ({family})",
                    detail=f"date={date} host={comp} os={os_}",
                    url="https://www.hudsonrock.com/free-tools",
                    severity=Severity.CRITICAL,
                    extra=s_,
                )
        elif r.status_code in (429, 403):
            yield Hit(module=NAME, source="HudsonRock", category="breach",
                      status=HitStatus.RATELIMITED, detail=f"HTTP {r.status_code}")
        else:
            yield Hit(module=NAME, source="HudsonRock", category="breach",
                      status=HitStatus.UNCERTAIN, detail=f"HTTP {r.status_code}")
    except Exception as e:
        yield Hit(module=NAME, source="HudsonRock", category="breach",
                  status=HitStatus.ERROR, detail=str(e))


async def _proxynova(email: str) -> AsyncIterator[Hit]:
    """FREE combo-list / paste search — leaked password pairs.
    https://api.proxynova.com/comb?query=...
    """
    url = "https://api.proxynova.com/comb"
    try:
        client = await get_client()
        r = await client.get(url, params={"query": email}, headers={"Accept": "application/json"})
        if r.status_code == 200:
            data = r.json() or {}
            lines = data.get("lines") or []
            # ProxyNova does substring matching on the whole combo line — filter to
            # lines where the email side is an EXACT match for our input.
            target = email.lower()
            exact: list[str] = []
            for raw in lines:
                left = raw.split(":", 1)[0].lower().strip()
                if left == target:
                    exact.append(raw)
            if not exact:
                yield Hit(module=NAME, source="ProxyNova ComB", category="breach",
                          status=HitStatus.NOT_FOUND,
                          detail=f"not in indexed combos (API returned {len(lines)} fuzzy lines, 0 exact)")
                return
            for raw in exact[:25]:
                _, _, pw = raw.partition(":")
                masked = (pw[:2] + "•" * max(0, len(pw) - 4) + pw[-2:]) if len(pw) >= 4 else "•" * len(pw)
                detail = f"pw={masked} ({len(pw)} chars)"
                yield Hit(
                    module=NAME, source="ProxyNova ComB", category="breach",
                    status=HitStatus.FOUND,
                    title="leaked email:password in indexed combo list",
                    detail=detail, url="https://www.proxynova.com/tools/comb",
                    severity=Severity.CRITICAL,
                    extra={"line": raw},
                    confidence=score_breach_hit(
                        source_authoritative=True, has_password=True,
                    ),
                    evidence={
                        "match_kind": "exact_email_left_side",
                        "pw_len": str(len(pw)),
                    },
                )
        elif r.status_code in (429, 403):
            yield Hit(module=NAME, source="ProxyNova ComB", category="breach",
                      status=HitStatus.RATELIMITED, detail=f"HTTP {r.status_code}")
        else:
            yield Hit(module=NAME, source="ProxyNova ComB", category="breach",
                      status=HitStatus.UNCERTAIN, detail=f"HTTP {r.status_code}")
    except Exception as e:
        yield Hit(module=NAME, source="ProxyNova ComB", category="breach",
                  status=HitStatus.ERROR, detail=str(e))


async def _username_derivation(email: str) -> AsyncIterator[Hit]:
    """Use local part as a username and probe a small high-signal set."""
    local = email.split("@", 1)[0]
    if "+" in local:
        local = local.split("+", 1)[0]
    if not local or len(local) < 3:
        return
    from .username import load_sites
    all_sites = load_sites()
    # high-signal subset: GitHub, GitLab, Twitter, Instagram, Reddit, Telegram, Mastodon, Keybase
    interesting = {
        "GitHub", "GitLab", "Twitter/X", "Instagram", "Reddit", "Telegram (web)",
        "Keybase", "Mastodon (mastodon.social)", "Threads", "Bluesky", "Medium",
        "DevTo", "Patreon", "Linktree", "TikTok",
    }
    seed = [s for s in all_sites if s.get("name") in interesting]
    s = settings()
    async for h in stream_probes(
        seed, local, NAME + ":derived",
        concurrency=min(15, s.http_concurrency),
        timeout=s.http_timeout_sec,
    ):
        h.detail = f"derived from local-part '{local}' — {h.detail}"
        yield h


async def run(query: Query) -> AsyncIterator[Hit]:
    email = clean_email(query.value)
    if not email or "@" not in email:
        return
    s = settings()

    # quick wins first (yielded ASAP)
    yield await _validate(email)
    yield await _mx(email)
    yield await _gravatar(email)

    # HIBP — fire and stream (skipped if no key)
    async for h in _hibp(email):
        yield h

    # Free breach APIs (no key) — XposedOrNot, Hudson Rock, ProxyNova
    async for h in _xposedornot(email):
        yield h
    async for h in _hudson_rock(email):
        yield h
    async for h in _proxynova(email):
        yield h

    # username derivation
    async for h in _username_derivation(email):
        yield h

    # Holehe-style site enum (last — most likely to misbehave on rate limits)
    sites = _load_holehe()
    if sites:
        async for h in stream_probes(
            sites, email, NAME,
            concurrency=min(8, s.http_concurrency),
            timeout=s.http_timeout_sec,
        ):
            yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.EMAIL], run)
