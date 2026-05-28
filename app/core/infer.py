"""Query-kind inference — pure logic (no Qt, no network).

Extracted from app.ui.main_window so it can be imported (and unit-tested)
without pulling in the optional PySide6 GUI dependency.
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
