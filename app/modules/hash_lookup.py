"""CIRCL hashlookup — FREE, no-key file-hash reputation (md5 / sha1 / sha256).

Why this exists: MalwareBazaar (``malware_bazaar.py``) now *requires*
``ABUSE_CH_API_KEY`` since abuse.ch locked their API behind auth, so on a free
install the HASH kind produced nothing. CIRCL's hashlookup
(https://hashlookup.circl.lu) is a public, no-key service that fronts the NSRL
(known-good software) catalogue plus a set of known-malicious feeds.

Response shape (verified live):
  * known hash  → HTTP 200, JSON. If the file is flagged malicious the body
                  carries a ``KnownMalicious`` key (e.g. "malshare.com") plus
                  ``source``/``hashlookup:trust``. A plain NSRL "known-good"
                  entry is 200 *without* ``KnownMalicious``.
  * unknown     → HTTP 404, ``{"message": "Non existing MD5", ...}`` → NO_DATA
                  (the service is healthy, it just doesn't know the hash — NOT
                  an error, per app/core/classify rules).

This module makes hash lookups work out of the box; ``malware_bazaar`` stays as
an optional, key-gated enrichment alongside it.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "hash_lookup"

_API = "https://hashlookup.circl.lu/lookup"
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_TIMEOUT = 12.0

# md5/sha1/sha256 only — CIRCL's lookup endpoints. (sha512 has no endpoint.)
_LEN_TO_PATH = {32: "md5", 40: "sha1", 64: "sha256"}


def _hash_path(h: str) -> str | None:
    """Return the CIRCL path segment ('md5'|'sha1'|'sha256') or None."""
    if not _HEX_RE.match(h):
        return None
    return _LEN_TO_PATH.get(len(h))


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.HASH:
        return
    h = (query.value or "").strip().lower()
    path = _hash_path(h)
    if not path:
        # sha512 (128) or non-hex — CIRCL can't look it up. Skip cleanly so the
        # key-gated malware_bazaar module can still try (it accepts sha512).
        yield Hit(module=NAME, source="CIRCL hashlookup", category="threat-intel",
                  url=_API, status=HitStatus.SKIPPED, title=query.value,
                  detail="CIRCL supports md5/sha1/sha256 only")
        return
    url = f"{_API}/{path}/{h}"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"Accept": "application/json"})
    except Exception as e:
        yield Hit(module=NAME, source="CIRCL hashlookup", category="threat-intel",
                  url=url, status=classify_exception(e),
                  title=h, detail=f"{type(e).__name__}: {e}")
        return
    if r.status_code == 404:
        # Healthy service, hash simply not in any CIRCL dataset.
        yield Hit(module=NAME, source="CIRCL hashlookup", category="threat-intel",
                  url=url, status=HitStatus.NO_DATA, title=h,
                  detail="not known to CIRCL (NSRL/known-malicious)")
        return
    if r.status_code != 200:
        yield Hit(module=NAME, source="CIRCL hashlookup", category="threat-intel",
                  url=url, status=classify_http(r.status_code),
                  title=h, detail=f"HTTP {r.status_code}")
        return
    try:
        data = r.json() or {}
    except Exception as e:
        yield Hit(module=NAME, source="CIRCL hashlookup", category="threat-intel",
                  url=url, status=HitStatus.ERROR, title=h,
                  detail=f"bad json: {e}")
        return
    # Some deployments answer 200 with a {"message": "Non existing ..."} body
    # instead of 404 — treat a body with no real fields as NO_DATA too.
    if "message" in data and "Non existing" in str(data.get("message", "")):
        yield Hit(module=NAME, source="CIRCL hashlookup", category="threat-intel",
                  url=url, status=HitStatus.NO_DATA, title=h,
                  detail="not known to CIRCL (NSRL/known-malicious)")
        return

    file_name = data.get("FileName") or ""
    source = data.get("source") or ""
    known_malicious = data.get("KnownMalicious")  # str/list when present, else absent
    trust = data.get("hashlookup:trust")
    file_type = data.get("mimetype") or ""

    if known_malicious:
        mal = (known_malicious if isinstance(known_malicious, str)
               else ", ".join(str(x) for x in known_malicious))
        detail = f"KnownMalicious: {mal}"
        if file_name:
            detail += f" | file={file_name}"
        if trust is not None:
            detail += f" | trust={trust}"
        yield Hit(
            module=NAME, source="CIRCL hashlookup", category="threat-intel",
            url=url, status=HitStatus.FOUND, title=h,
            detail=detail, severity=Severity.CRITICAL,
            extra={"hash_type": path, "known_malicious": mal,
                   "file_name": file_name, "source": source,
                   "trust": trust, "mimetype": file_type},
            confidence=0.95,
            evidence={"known_malicious": str(mal), "source": str(source)},
        )
        return

    # Known to CIRCL but NOT flagged malicious → a catalogued (often NSRL
    # known-good) file. Still a useful FOUND: the hash is a real, identified
    # artefact. Low severity, lower confidence on the "benign" judgement.
    detail = f"known file (not flagged malicious){f' | {file_name}' if file_name else ''}"
    if source:
        detail += f" | {source}"
    yield Hit(
        module=NAME, source="CIRCL hashlookup", category="threat-intel",
        url=url, status=HitStatus.FOUND, title=h,
        detail=detail, severity=Severity.INFO,
        extra={"hash_type": path, "known_malicious": False,
               "file_name": file_name, "source": source,
               "trust": trust, "mimetype": file_type},
        confidence=0.6,
        evidence={"known_malicious": "false", "source": str(source)},
    )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.HASH], run)
