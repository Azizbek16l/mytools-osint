"""HaveIBeenPwned Pwned-Passwords k-anonymity lookup.

This is the canonical example of privacy-preserving breach checking:
we send the FIRST 5 chars of the SHA-1 of the password and get back
ALL suffixes that share that prefix, with their breach counts. We then
match the rest locally. The password itself never leaves the host.

Useful in the analyst flow when you've been handed a credential dump:

    osint hibp-password 'P@ssw0rd!'      # k-anon check, 0 leaks if 0

CLI flag: `osint --kind password 'value'` — added a new QueryKind for this.
"""
from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "hibp_passwords"

_RANGE = "https://api.pwnedpasswords.com/range/{prefix}"


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.PASSWORD:
        return
    pw = query.value or ""
    if not pw:
        return
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = _RANGE.format(prefix=prefix)
    try:
        client = await get_client()
        r = await client.get(url, headers={"Add-Padding": "true",
                                            "User-Agent": "mytools-osint"},
                              timeout=8.0)
    except Exception as e:
        yield Hit(module=NAME, source="HIBP k-anonymity", category="breach",
                  url=url, status=classify_exception(e),
                  title="(redacted)", detail=f"{type(e).__name__}: {e}")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="HIBP k-anonymity", category="breach",
                  url=url, status=classify_http(r.status_code),
                  title="(redacted)", detail=f"HTTP {r.status_code}")
        return
    count = 0
    for line in (r.text or "").splitlines():
        if ":" not in line:
            continue
        s, c = line.split(":", 1)
        if s.strip().upper() == suffix:
            try:
                count = int(c.strip())
            except ValueError:
                count = 0
            break
    if count == 0:
        yield Hit(
            module=NAME, source="HIBP k-anonymity", category="breach",
            url="https://haveibeenpwned.com/Passwords",
            status=HitStatus.FOUND, title="(redacted)",
            detail="✓ not in any known breach corpus",
            severity=Severity.INFO,
            extra={"breach_count": 0, "k_anon_prefix": prefix},
        )
    else:
        sev = (Severity.CRITICAL if count > 10000
               else Severity.HIGH if count > 100
               else Severity.MEDIUM)
        yield Hit(
            module=NAME, source="HIBP k-anonymity", category="breach",
            url="https://haveibeenpwned.com/Passwords",
            status=HitStatus.FOUND, title="(redacted)",
            detail=f"⚠ SEEN {count:,} time(s) across breach corpus — "
                   f"do NOT reuse this password",
            severity=sev,
            extra={"breach_count": count, "k_anon_prefix": prefix},
        )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.PASSWORD], run)
