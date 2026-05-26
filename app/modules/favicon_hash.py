"""Favicon hash pivoting — single most powerful infra-pivot trick (v4.2).

Computes the MMH3-32 hash of the target's favicon (Shodan's published recipe:
base64-encode the raw bytes with line breaks every 76 chars, then MMH3-32 the
result). The resulting integer can be looked up across Shodan's index to find
every other host on the internet serving the same favicon — devastating for
finding origin servers behind CDNs, sibling admin panels, malware C2 panels.

Free path: we compute the hash locally, then query Shodan InternetDB
(unauth) for IPs that may share the same favicon via SAN/hostname overlap.
For *cross-internet* matches users can paste the hash into shodan.io with
``http.favicon.hash:<hash>`` (free account, free search).

OPSEC: One HTTP GET to the target host. Refuse to run in --opsec mode.
"""
from __future__ import annotations

import base64
import ipaddress
import os
from collections.abc import AsyncIterator

from app.core.http import _opsec_on, get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity
from app.modules.web_recon import _mmh3_x86_32

NAME = "favicon_hash"

_FAVICON_PATHS = ("/favicon.ico", "/favicon.png", "/apple-touch-icon.png")
_TIMEOUT = 6.0
_MAX_BYTES = 1_000_000  # 1 MB cap — defends against /favicon.ico that serves an HTML page


def _shodan_mmh3(content: bytes) -> int:
    """Replicate Shodan's exact favicon-hash recipe (mmh3-32, signed int).

    Uses the in-tree pure-Python implementation (web_recon._mmh3_x86_32) —
    no external `mmh3` C-extension dep required.
    """
    # Shodan splits base64 into 76-char lines (RFC 2045 / MIME), terminates with \n.
    b64 = base64.encodebytes(content)  # default: 76-char lines + trailing \n
    return _mmh3_x86_32(b64)


def _is_private_host(host: str) -> bool:
    """SSRF guard — reject loopback, private, link-local, reserved, multicast IPs.

    Hostnames pass through (we trust caller-supplied DNS).
    """
    # IPv4 has at most one colon (port); IPv6 has 2+ colons. Try the full
    # string first (handles IPv6 like "::1"), then strip a port if present.
    candidates = [host]
    if host.count(":") == 1:
        candidates.append(host.split(":", 1)[0])
    elif host.startswith("[") and "]" in host:
        candidates.append(host[1:host.index("]")])
    for cand in candidates:
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return True
    return False


async def _run(query: Query) -> AsyncIterator[Hit]:
    if query.kind not in (QueryKind.DOMAIN, QueryKind.IP):
        return
    if _opsec_on() and os.environ.get("OSINT_FAVICON_HASH_OVER_TOR") != "1":
        yield Hit(module=NAME, source="favicon", category="fingerprint",
                  status=HitStatus.SKIPPED,
                  title="skipped in --opsec mode",
                  detail="set OSINT_FAVICON_HASH_OVER_TOR=1 to override")
        return

    host = (query.value or "").strip().lower().removeprefix("*.").rstrip("/")
    # SSRF guard — private / loopback / metadata IPs.
    if _is_private_host(host):
        yield Hit(module=NAME, source="favicon", category="fingerprint",
                  status=HitStatus.SKIPPED,
                  title="refused: private/loopback/link-local IP",
                  detail=f"will not probe internal address {host}")
        return
    client = await get_client()

    for path in _FAVICON_PATHS:
        url = f"https://{host}{path}"
        try:
            # No cross-host redirects for favicons — narrows SSRF surface.
            r = await client.get(url, timeout=_TIMEOUT,
                                 follow_redirects=False)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        ctype = r.headers.get("content-type", "").lower()
        # Loose check — many sites serve `image/x-icon`, `image/vnd.microsoft.icon`,
        # `image/png`, `image/jpeg`. Reject `text/html` (404 page mascarading as 200).
        if ctype.startswith("text/") or "html" in ctype:
            continue
        content = r.content[:_MAX_BYTES]
        if len(content) < 32:
            continue
        h = _shodan_mmh3(content)
        # Shodan-style facet URL the user can copy-paste into shodan.io.
        shodan_search = f"https://www.shodan.io/search?query=http.favicon.hash%3A{h}"
        yield Hit(
            module=NAME, source="favicon", category="fingerprint",
            url=url, status=HitStatus.FOUND,
            title=f"favicon mmh3 = {h}",
            detail=f"path={path} · bytes={len(content)} · search → {shodan_search}",
            severity=Severity.INFO,
            extra={"mmh3": h, "bytes": len(content),
                   "shodan_search": shodan_search, "path": path},
        )
        return  # one favicon is enough — first hit wins

    yield Hit(module=NAME, source="favicon", category="fingerprint",
              status=HitStatus.NO_DATA, title="no favicon found",
              detail="tried /favicon.ico /favicon.png /apple-touch-icon.png")


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN, QueryKind.IP], _run)
