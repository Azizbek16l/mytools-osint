"""Small test factories for OSINT core types.

Keeps test setup terse: `make_query("acme.com")` instead of repeating the
`Query(kind=..., value=...)` boilerplate everywhere, and `make_hit(...)` for
fabricating fixture Hits in engine tests where no real module runs.
"""
from __future__ import annotations

from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

__all__ = ["make_query", "make_hit"]


def make_query(value: str, kind: QueryKind = QueryKind.DOMAIN, **kw) -> Query:
    """Build a Query. Defaults to a DOMAIN query — the most common in these tests."""
    return Query(kind=kind, value=value, **kw)


def make_hit(
    *,
    module: str = "fake",
    source: str | None = None,
    status: HitStatus = HitStatus.FOUND,
    severity: Severity = Severity.INFO,
    detail: str = "",
    **kw,
) -> Hit:
    """Build a Hit with sensible defaults so callers only set what they assert on."""
    return Hit(
        module=module,
        source=source if source is not None else module,
        status=status,
        severity=severity,
        detail=detail,
        **kw,
    )
