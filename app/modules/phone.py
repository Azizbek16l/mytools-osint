"""Phone number OSINT.

Sources:
  - libphonenumber (offline) — region, carrier, line-type, timezone
  - Numverify API (optional)
  - WhatsApp existence probe (delegates to whatsapp module via direct call)
  - Telegram phone lookup (delegates to telegram module via direct call)
  - Search for phone on Truecaller's public search page (best-effort, often blocked)
"""
from __future__ import annotations

from collections.abc import AsyncIterator

import phonenumbers
from phonenumbers import carrier, geocoder
from phonenumbers import timezone as pntz

from app.core.config import settings
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

from .base import clean_phone

NAME = "phone"


def _parse(num: str) -> phonenumbers.PhoneNumber | None:
    try:
        return phonenumbers.parse(num, None)
    except phonenumbers.NumberParseException:
        # try with default region UZ (Mars IT context)
        try:
            return phonenumbers.parse(num, "UZ")
        except phonenumbers.NumberParseException:
            return None


def _libphonenumber(num: str) -> Hit:
    parsed = _parse(num)
    if not parsed or not phonenumbers.is_possible_number(parsed):
        return Hit(module=NAME, source="libphonenumber", status=HitStatus.NOT_FOUND,
                   detail="not a possible phone number", severity=Severity.LOW)
    valid = phonenumbers.is_valid_number(parsed)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    region = geocoder.description_for_number(parsed, "en")
    car = carrier.name_for_number(parsed, "en")
    tz = ", ".join(pntz.time_zones_for_number(parsed))
    line_type = {
        phonenumbers.PhoneNumberType.MOBILE: "MOBILE",
        phonenumbers.PhoneNumberType.FIXED_LINE: "FIXED_LINE",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_OR_MOBILE",
        phonenumbers.PhoneNumberType.VOIP: "VOIP",
        phonenumbers.PhoneNumberType.UNKNOWN: "UNKNOWN",
    }.get(phonenumbers.number_type(parsed), "UNKNOWN")
    return Hit(
        module=NAME, source="libphonenumber", category="validation",
        status=HitStatus.FOUND if valid else HitStatus.UNCERTAIN,
        title=f"{e164} ({line_type})",
        detail=f"region={region} carrier={car} tz={tz} valid={valid}",
        extra={"e164": e164, "region": region, "carrier": car, "timezones": tz,
               "type": line_type, "valid": valid},
        severity=Severity.INFO,
    )


async def _numverify(num: str) -> Hit:
    s = settings()
    if not s.has_numverify:
        return Hit(module=NAME, source="Numverify", category="validation",
                   status=HitStatus.SKIPPED, detail="set NUMVERIFY_API_KEY")
    digits = num.lstrip("+")
    url = f"http://apilayer.net/api/validate?access_key={s.numverify_api_key}&number={digits}"
    try:
        client = await get_client()
        r = await client.get(url)
        if r.status_code == 200:
            data = r.json()
            if data.get("valid"):
                return Hit(
                    module=NAME, source="Numverify", category="validation",
                    status=HitStatus.FOUND,
                    detail=f"{data.get('country_name')} / {data.get('carrier') or '?'} / {data.get('line_type') or '?'}",
                    extra=data,
                )
            return Hit(module=NAME, source="Numverify", category="validation",
                       status=HitStatus.NOT_FOUND, detail="not valid", extra=data)
        return Hit(module=NAME, source="Numverify", status=HitStatus.ERROR,
                   detail=f"HTTP {r.status_code}")
    except Exception as e:
        return Hit(module=NAME, source="Numverify", status=HitStatus.ERROR, detail=str(e))


async def _whatsapp(num: str) -> Hit:
    """Lightweight WhatsApp existence probe via wa.me. Best-effort; results vary."""
    digits = num.lstrip("+")
    url = f"https://wa.me/{digits}"
    try:
        client = await get_client()
        r = await client.get(url)
        body = r.text or ""
        # wa.me serves a generic page; the "phone number shared via url is invalid"
        # marker indicates the lookup failed. Existence implies "Continue to chat".
        if "phone number shared via url is invalid" in body.lower():
            return Hit(module=NAME, source="WhatsApp", category="messaging",
                       status=HitStatus.NOT_FOUND, url=url, detail="wa.me reports invalid")
        if "send_a_message" in body.lower() or "continue to chat" in body.lower() or r.status_code == 200:
            return Hit(module=NAME, source="WhatsApp", category="messaging",
                       status=HitStatus.UNCERTAIN, url=url,
                       detail="wa.me reachable — cannot confirm registration without open-protocol probe",
                       severity=Severity.LOW)
        return Hit(module=NAME, source="WhatsApp", status=HitStatus.UNCERTAIN,
                   url=url, detail=f"HTTP {r.status_code}")
    except Exception as e:
        return Hit(module=NAME, source="WhatsApp", status=HitStatus.ERROR, detail=str(e))


async def _telegram_phone(num: str) -> AsyncIterator[Hit]:
    """Delegate to the telegram module's phone lookup."""
    from .telegram import lookup_phone
    async for h in lookup_phone(num):
        yield h


async def run(query: Query) -> AsyncIterator[Hit]:
    num = clean_phone(query.value)
    if not num:
        return
    # parse + libphonenumber (no network)
    yield _libphonenumber(num)
    # network probes
    yield await _numverify(num)
    yield await _whatsapp(num)
    async for h in _telegram_phone(num):
        yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.PHONE], run)
