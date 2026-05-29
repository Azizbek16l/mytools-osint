"""Query-kind inference — pure logic (no Qt, no network).

Extracted from app.ui.main_window so it can be imported (and unit-tested)
without pulling in the optional PySide6 GUI dependency.
"""
from __future__ import annotations

import ipaddress
import os
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

# Image: http(s) URL OR a filesystem path that ends in a common image extension.
_IMG_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".heic", ".tif", ".tiff")
_IMG_URL_RE = re.compile(r"^https?://\S+\.(?:jpg|jpeg|png|webp|heic|tiff?)(?:\?.*)?$",
                         re.IGNORECASE)


def _looks_like_image(value: str) -> bool:
    if _IMG_URL_RE.match(value):
        return True
    # absolute filesystem path with image extension (POSIX or Windows-style)
    lower = value.lower()
    if not lower.endswith(_IMG_EXTS):
        return False
    if os.path.isabs(value):
        return True
    # Windows drive-letter absolute paths (e.g. C:\photos\x.jpg) — os.path.isabs
    # already covers these on Windows; on POSIX accept the pattern explicitly.
    return bool(re.match(r"^[A-Za-z]:[\\/]", value))


def infer_kind(value: str) -> QueryKind | None:
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
