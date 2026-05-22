"""Username/email pattern generation. Pure CPU — no network, no key.

Given an input (username, name, or email), generates plausible variations to
hand off to other modules. Acts as a 'seed' producer for parallel sweeps.

Why this matters: people pick consistent handles. A single 'azizbektopilboyev'
should expand into ['azizbek', 'aziz.bek', 'aziz_topilboyev', 'topilboyev_aziz',
'azizt', ...]. Each variation can then be cross-checked across the 1000-site
dataset.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator

from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "patterns"


def _split_camelsnake(s: str) -> list[str]:
    """Split a token on camelCase, snake_case, dot.case, and digits."""
    # split on non-alpha, then split camelCase
    parts: list[str] = []
    for chunk in re.split(r"[^A-Za-z0-9]+", s):
        if not chunk:
            continue
        # camelCase split
        camel = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+", chunk) or [chunk]
        parts.extend(p.lower() for p in camel if p)
    return parts


def username_variations(value: str, max_items: int = 25) -> list[str]:
    """Generate plausible username variations from a single seed."""
    seed = value.strip().lstrip("@").lower()
    if not seed:
        return []
    out: list[str] = []
    seen: set[str] = set()

    def add(v: str) -> None:
        v = v.strip("._-")
        if 3 <= len(v) <= 40 and v not in seen:
            out.append(v)
            seen.add(v)

    parts = _split_camelsnake(seed)
    add(seed)
    if not parts:
        return out

    # individual tokens
    for p in parts:
        add(p)
    # first + last forms (assuming first/last name in the seed)
    if len(parts) >= 2:
        f, l = parts[0], parts[-1]
        for sep in ("", ".", "_", "-"):
            add(f + sep + l)
            add(l + sep + f)
        for sep in ("", ".", "_"):
            add(f[0] + sep + l)
            add(f + sep + l[0])
        add(f + l[0])
        add(f[0] + l)
    # progressive abbreviations (azizbektopilboyev → azizbek, azizt, ...)
    if len(seed) > 6:
        for n in (4, 5, 6, 7, 8):
            if n < len(seed):
                add(seed[:n])
    # numeric suffix derivations (often paired with handles)
    for suffix in ("1", "01", "_", "_official", "_real"):
        add(seed + suffix)
    if len(parts) >= 2:
        add(parts[0] + parts[-1])
    return out[:max_items]


def email_pattern_guesses(name: str, domain: str, max_items: int = 20) -> list[str]:
    """Given a person's name and a target domain, produce common corporate-email formats."""
    parts = _split_camelsnake(name)
    if len(parts) < 1:
        return []
    f = parts[0]
    l = parts[-1] if len(parts) >= 2 else ""
    domain = domain.lower().strip(". ")
    out: list[str] = []
    seen: set[str] = set()

    def add(v: str) -> None:
        if v and v not in seen and "@" in v and "." in v.split("@", 1)[1]:
            out.append(v); seen.add(v)

    if l:
        templates = [
            f"{f}.{l}@{domain}", f"{f}{l}@{domain}",
            f"{f}_{l}@{domain}", f"{f}-{l}@{domain}",
            f"{f[0]}.{l}@{domain}", f"{f[0]}{l}@{domain}",
            f"{f}.{l[0]}@{domain}", f"{f}{l[0]}@{domain}",
            f"{l}.{f}@{domain}", f"{l}{f}@{domain}",
            f"{l}.{f[0]}@{domain}", f"{l}@{domain}", f"{f}@{domain}",
        ]
    else:
        templates = [f"{f}@{domain}"]
    for t in templates:
        add(t)
    return out[:max_items]


async def run(query: Query) -> AsyncIterator[Hit]:
    """Emit one Hit per generated candidate so the UI shows them as suggestions."""
    if query.kind == QueryKind.USERNAME:
        seeds = username_variations(query.value)
        for s in seeds:
            if s == query.value.lstrip("@").lower():
                continue
            yield Hit(
                module=NAME, source=f"variation:{s}",
                category="suggestion", status=HitStatus.FOUND,
                title=s,
                detail=f"-> {s}    (re-query: osint {s})",
                severity=Severity.INFO, extra={"candidate": s},
            )
    elif query.kind == QueryKind.EMAIL:
        local, _, dom = query.value.partition("@")
        if not dom:
            return
        for s in username_variations(local):
            cand = f"{s}@{dom}"
            yield Hit(
                module=NAME, source=f"variation:{s}",
                category="suggestion", status=HitStatus.FOUND,
                title=cand,
                detail=f"-> {cand}    (re-query: osint {cand})",
                severity=Severity.INFO, extra={"candidate": cand},
            )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.USERNAME, QueryKind.EMAIL], run)
