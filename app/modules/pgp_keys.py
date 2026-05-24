"""PGP key discovery for an email address.

Queries the SKS-replacement keyservers:

  - keys.openpgp.org (Verifying Keyserver — only shows emails that proved
    ownership of the address)
  - keyserver.ubuntu.com (legacy SKS pool, less verified, broader coverage)

Both expose `GET /vks/v1/by-email/{email}` style endpoints. We surface the
key's fingerprint, algorithm, and creation date if available.
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from urllib.parse import quote

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "pgp_keys"

_OPENPGP = "https://keys.openpgp.org/vks/v1/by-email/{email}"
_UBUNTU = "https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index&fingerprint=on"


async def _openpgp(email: str) -> Hit:
    url = _OPENPGP.format(email=quote(email))
    try:
        client = await get_client()
        r = await client.get(url, timeout=8.0)
    except Exception as e:
        return Hit(module=NAME, source="keys.openpgp.org", category="pgp",
                   url=url, status=classify_exception(e),
                   title=email, detail=f"{type(e).__name__}: {e}")
    if r.status_code == 404:
        return Hit(module=NAME, source="keys.openpgp.org", category="pgp",
                   url=url, status=HitStatus.NO_DATA,
                   title=email, detail="no verified PGP key for this email")
    if r.status_code != 200:
        return Hit(module=NAME, source="keys.openpgp.org", category="pgp",
                   url=url, status=classify_http(r.status_code),
                   title=email, detail=f"HTTP {r.status_code}")
    body = r.text
    # ASCII-armored key block start
    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" not in body:
        return Hit(module=NAME, source="keys.openpgp.org", category="pgp",
                   url=url, status=HitStatus.NO_DATA,
                   title=email, detail="response missing PGP block")
    return Hit(
        module=NAME, source="keys.openpgp.org", category="pgp",
        url=url, status=HitStatus.FOUND, title=email,
        detail=f"verified PGP key present ({len(body)} bytes ASCII-armored)",
        severity=Severity.MEDIUM,
        extra={"size_bytes": len(body)},
    )


_UBUNTU_FP_RE = re.compile(
    r"pub\s+(\w+)/<a[^>]*>([A-F0-9]+)</a>\s+(\d{4}-\d{2}-\d{2})",
    re.IGNORECASE,
)


async def _ubuntu(email: str) -> Hit:
    url = _UBUNTU.format(email=quote(email))
    try:
        client = await get_client()
        r = await client.get(url, timeout=8.0)
    except Exception as e:
        return Hit(module=NAME, source="keyserver.ubuntu.com", category="pgp",
                   url=url, status=classify_exception(e),
                   title=email, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200:
        return Hit(module=NAME, source="keyserver.ubuntu.com", category="pgp",
                   url=url, status=classify_http(r.status_code),
                   title=email, detail=f"HTTP {r.status_code}")
    text = r.text
    if "No results found" in text or "Public Key Server -- Search:" not in text and "pub " not in text:
        return Hit(module=NAME, source="keyserver.ubuntu.com", category="pgp",
                   url=url, status=HitStatus.NO_DATA,
                   title=email, detail="no key in SKS pool")
    matches = _UBUNTU_FP_RE.findall(text)
    if not matches:
        return Hit(module=NAME, source="keyserver.ubuntu.com", category="pgp",
                   url=url, status=HitStatus.NO_DATA,
                   title=email, detail="key page returned but no fingerprint parsed")
    algo, fp, date = matches[0]
    return Hit(
        module=NAME, source="keyserver.ubuntu.com", category="pgp",
        url=url, status=HitStatus.FOUND, title=email,
        detail=f"{algo} key {fp[-16:]} created {date} (and {len(matches)-1} more)"
               if len(matches) > 1
               else f"{algo} key {fp[-16:]} created {date}",
        severity=Severity.LOW,
        extra={"algorithm": algo, "fingerprint": fp, "created": date,
               "total_keys": len(matches)},
    )


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.EMAIL:
        return
    email = (query.value or "").strip().lower()
    if "@" not in email:
        return
    tasks = [asyncio.create_task(_openpgp(email)),
             asyncio.create_task(_ubuntu(email))]
    for fut in asyncio.as_completed(tasks):
        try:
            yield await fut
        except Exception as e:
            yield Hit(module=NAME, source="pgp", status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.EMAIL], run)
