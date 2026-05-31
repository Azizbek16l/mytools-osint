"""Query-kind inference — pure logic (no Qt, no network).

This module is the SINGLE canonical home for query-kind inference. cli.py,
the interactive shell, the agent loop, playbooks and the AI/YAML helpers all
route through :func:`infer_kind` so the routing decision (e.g. "is this a
wallet, an image, a hash, or a username?") is made in exactly one place.

Extracted from app.ui.main_window so it can be imported (and unit-tested)
without pulling in the optional PySide6 GUI dependency.

Ordering rationale (each branch must run BEFORE the ones it could be
mis-swallowed by):

  IP   → before DOMAIN/USERNAME (IPv6 ``2001:db8::1`` otherwise → USERNAME).
  EMAIL
  WALLET → before USERNAME (an ETH ``0x…`` address must not trigger the
           1000-site username probe blast).
  HASH → before PHONE/DOMAIN/USERNAME (a 32/40/64/128-char hex string is an
         IOC, not a username; checked before PHONE because a 32-hex string is
         all "digits-ish").
  IMAGE → before DOMAIN (a relative ``photo.jpg`` ends in an image extension
          and would otherwise be accepted as a ``name.tld`` domain and routed
          at the image module — which expects a fetchable/readable path).
  PHONE
  USERNAME (@-prefixed)
  DOMAIN
  USERNAME (bare token / fallback)
"""
from __future__ import annotations

import ipaddress
import re

from app.core.types import QueryKind

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_PHONE_RE = re.compile(r"^\+?[0-9 ()\-]{6,}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{2,}$")
_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)

# Wave C — wallet anchors. BTC base58 is anchored on 1/3 prefix to avoid
# collision with arbitrary 26-35 alphanumeric usernames.
_BTC_BASE58_RE = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$")
_BTC_BECH32_RE = re.compile(r"^bc1[0-9ac-hj-np-z]{6,87}$", re.IGNORECASE)
_ETH_ADDR_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

# IOC hash — md5(32) / sha1(40) / sha256(64) / sha512(128) hex digests.
_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")
_HASH_LENGTHS = (32, 40, 64, 128)

# Image: http(s) URL OR a filesystem path that ends in a common image extension.
_IMG_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".heic", ".tif", ".tiff")
_IMG_URL_RE = re.compile(r"^https?://\S+\.(?:jpg|jpeg|png|webp|heic|tiff?)(?:\?.*)?$",
                         re.IGNORECASE)


def _is_hash(value: str) -> bool:
    """True for a bare hex IOC digest of a recognised length (md5/sha*)."""
    return bool(_HASH_RE.match(value)) and len(value) in _HASH_LENGTHS


def _looks_like_image(value: str) -> bool:
    """True if ``value`` is an image — by URL, by absolute path, or by a
    bare/relative path ending in a known image extension.

    NOTE on relative paths: a value like ``photo.jpg`` (no separator, not a
    URL) ends in an image extension and must be treated as an IMAGE so it
    reaches the image module rather than being swallowed by the DOMAIN regex
    (which happily accepts ``.jpg`` as a TLD). We require the value NOT look
    like a URL with a non-image path so ``https://example.com/page.html`` is
    not pulled in here.
    """
    if _IMG_URL_RE.match(value):
        return True
    lower = value.lower()
    if not lower.endswith(_IMG_EXTS):
        return False
    # An http(s) URL that ends in an image extension already matched above; any
    # other URL-shaped value ending in an image ext (e.g. ftp://) we leave to
    # the URL handlers — only treat *non-URL* values (paths, bare filenames)
    # as image inputs here.
    if "://" in value:
        return False
    return True


def infer_kind(value: str) -> QueryKind | None:
    """Infer the :class:`QueryKind` of ``value``.

    Returns ``None`` only for empty/whitespace input. Every other input
    resolves to a kind (falling back to USERNAME) — this keeps the contract
    backward-compatible with cli.infer_kind, which never returns None.
    """
    v = value.strip()
    if not v:
        return None
    # IPv4 / IPv6 first (otherwise IPv6 like 2001:db8::1 → USERNAME).
    try:
        ipaddress.ip_address(v.split("/", 1)[0])
        return QueryKind.IP
    except ValueError:
        pass
    if _EMAIL_RE.match(v):
        return QueryKind.EMAIL
    # Wave C — wallet & image detection. Wallet checks run BEFORE username so an
    # ETH address (0x…) doesn't fall through to a 1000-site username probe.
    if _ETH_ADDR_RE.match(v) or _BTC_BECH32_RE.match(v) or _BTC_BASE58_RE.match(v):
        return QueryKind.WALLET
    # Hash IOC — before PHONE (a 32-hex string is all "digits-ish") and before
    # DOMAIN/USERNAME. ETH 0x… already returned WALLET above.
    if _is_hash(v):
        return QueryKind.HASH
    # Image — before DOMAIN so a relative `photo.jpg` is routed to the image
    # module instead of being accepted as a `name.tld` domain.
    if _looks_like_image(v):
        return QueryKind.IMAGE
    digits = re.sub(r"\D", "", v)
    if _PHONE_RE.match(v) and 6 <= len(digits) <= 16:
        return QueryKind.PHONE
    if v.startswith("@"):
        return QueryKind.USERNAME
    if "." in v and _DOMAIN_RE.match(v):
        return QueryKind.DOMAIN
    if _USERNAME_RE.match(v):
        return QueryKind.USERNAME
    return QueryKind.USERNAME
