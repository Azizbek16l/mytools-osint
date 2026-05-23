"""Diff two QueryResults — set arithmetic over (source, url) keys + rich renderer.

Diff identity: two hits are the *same finding* iff their (source, url) is equal.
- added:     same key absent in old, present in new
- removed:   same key present in old, absent in new
- changed:   same key in both, but status OR title differs
- unchanged: same key in both, status + title identical

We intentionally ignore latency_ms, found_at, detail, extra — those drift
between runs without signaling a real change.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from rich.console import Console, Group
from rich.text import Text

from app.core.types import Hit, Query, QueryResult
from app.ui import tokens


@dataclass(slots=True)
class HitDiff:
    """Difference between two ordered hit collections.

    `changed` carries (old, new) pairs so the renderer can show transitions.
    """

    added: list[Hit] = field(default_factory=list)
    removed: list[Hit] = field(default_factory=list)
    changed: list[tuple[Hit, Hit]] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)


def _key(h: Hit) -> tuple[str, str]:
    """Identity for a hit. (source, url) is stable across runs; title may drift."""
    return (h.source, h.url)


def compute_diff(old_hits: list[Hit], new_hits: list[Hit]) -> HitDiff:
    """Pure set arithmetic. O(n + m) — single pass per collection."""
    old_map: dict[tuple[str, str], Hit] = {}
    for h in old_hits:
        old_map.setdefault(_key(h), h)  # first occurrence wins on dup keys
    new_map: dict[tuple[str, str], Hit] = {}
    for h in new_hits:
        new_map.setdefault(_key(h), h)

    diff = HitDiff()
    for k, h_new in new_map.items():
        h_old = old_map.get(k)
        if h_old is None:
            diff.added.append(h_new)
        elif h_old.status != h_new.status or h_old.title != h_new.title:
            diff.changed.append((h_old, h_new))
        else:
            diff.unchanged_count += 1
    for k, h_old in old_map.items():
        if k not in new_map:
            diff.removed.append(h_old)
    return diff


# ---- rendering -------------------------------------------------------------


def _fmt_when(qr: QueryResult) -> str:
    when = qr.finished_at or qr.query.started_at
    return when.strftime("%Y-%m-%d")


def _row(prefix: str, prefix_style: str, source: str, label: str, url: str,
         tail: str, tail_style: str) -> Text:
    """One diff row. Columns mimic the CLI's existing result rows."""
    t = Text()
    t.append(f"   {prefix} ", style=prefix_style)
    t.append(f"{source:<16}", style=tokens.FG)
    # label + url collapse intelligently — if no url, just label
    body = label
    if url:
        body = f"{label}  {url}" if label else url
    # truncate to keep one-line layout sane
    if len(body) > 64:
        body = body[:61] + "..."
    t.append(f" {body:<66}", style=tokens.DIM)
    t.append(f" {tail}", style=tail_style)
    return t


def render_diff(
    query: Query, old: QueryResult, new: QueryResult, console: Console
) -> None:
    """Print a unified diff using rich.Group (per Sprint 1 chrome convention).

    Colors:
      + (added)   -> tokens.OK
      Δ (changed) -> tokens.WARN
      - (removed) -> tokens.BAD (dim)
    """
    parts: list[Text] = []

    header = Text()
    header.append("   ── diff   ", style=tokens.DIM)
    header.append(query.value, style=f"bold {tokens.ACCENT}")
    header.append("   ", style=tokens.DIM)
    header.append(_fmt_when(old), style=tokens.FG)
    header.append(" → ", style=tokens.DIM)
    header.append(_fmt_when(new), style=tokens.FG)
    header.append(" " + ("─" * 30), style=tokens.DIM)
    parts.append(header)
    parts.append(Text(""))

    diff = compute_diff(old.hits, new.hits)

    if not diff.has_changes:
        parts.append(Text("   no changes between these two scans", style=tokens.DIM))
    else:
        for h in diff.added:
            parts.append(_row("+", f"bold {tokens.OK}", h.source,
                              h.title or h.detail, h.url,
                              h.severity.value.upper(), tokens.DIM))
        for h_old, h_new in diff.changed:
            change = f"status: {h_old.status.value.upper()} → {h_new.status.value.upper()}"
            if h_old.title != h_new.title:
                change = f"title: {h_old.title!r} → {h_new.title!r}"
            parts.append(_row("Δ", f"bold {tokens.WARN}", h_new.source,
                              h_new.title or h_new.detail, h_new.url,
                              change, tokens.WARN))
        for h in diff.removed:
            parts.append(_row("-", f"bold {tokens.BAD}", h.source,
                              h.title or h.detail, h.url,
                              "(gone)", f"dim {tokens.BAD}"))

    parts.append(Text(""))
    summary = Text()
    summary.append("   summary:  ", style=tokens.DIM)
    summary.append(f"+{len(diff.added)} new", style=f"bold {tokens.OK}")
    summary.append("   ", style=tokens.DIM)
    summary.append(f"Δ{len(diff.changed)} changed", style=f"bold {tokens.WARN}")
    summary.append("   ", style=tokens.DIM)
    summary.append(f"-{len(diff.removed)} removed", style=f"bold {tokens.BAD}")
    summary.append(f"   {diff.unchanged_count} unchanged", style=tokens.DIM)
    parts.append(summary)
    parts.append(Text("   " + ("─" * 73), style=tokens.DIM))

    console.print(Group(*parts))
