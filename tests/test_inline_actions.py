"""Tests for the per-hit inline actions sub-menu (Sprint 3, item 2).

The interactive flow itself uses ``questionary`` and is exercised by the
manual smoke test. These tests pin down the pure helpers + render outputs
that the menu depends on:

  * ``_copy_to_clipboard`` — soft pyperclip dependency, never raises.
  * ``_render_summary_card`` — emits the ``[N] open · [c] copy · [a] adjacent``
    keypress hint above the positives table.
  * Adjacency suggestion plumbing — when a Hit carries
    ``extra["suggested_kind"]`` + ``extra["suggested_value"]`` we can fish
    them back out.
"""
from __future__ import annotations

from datetime import UTC, datetime

from rich.console import Console

from app.core.types import Hit, HitStatus, Query, QueryKind
from app.ui.interactive import _copy_to_clipboard, _render_summary_card


def _make_positive(source: str, url: str) -> Hit:
    return Hit(
        module="username",
        source=source,
        category="social",
        status=HitStatus.FOUND,
        title=source,
        url=url,
        detail=f"profile at {source}",
        found_at=datetime.now(UTC),
    )


def test_copy_to_clipboard_handles_missing_module(monkeypatch) -> None:
    # Force ImportError even if pyperclip is installed in the runner env.
    import builtins
    real_import = builtins.__import__

    def _fail(name, *a, **kw):
        if name == "pyperclip":
            raise ImportError("forced missing")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", _fail)
    ok, msg = _copy_to_clipboard("https://example.com")
    assert ok is False
    assert "pyperclip" in msg


def test_copy_to_clipboard_surfaces_runtime_error(monkeypatch) -> None:
    # Inject a stub module whose copy() raises — verify we don't crash.
    import sys
    import types
    stub = types.ModuleType("pyperclip")

    class _PErr(Exception):
        pass

    def _bad_copy(text):
        raise _PErr("xclip not found")

    stub.copy = _bad_copy
    stub.PyperclipException = _PErr
    monkeypatch.setitem(sys.modules, "pyperclip", stub)
    ok, msg = _copy_to_clipboard("https://example.com")
    assert ok is False
    assert "xclip not found" in msg


def test_summary_card_emits_perhit_hint() -> None:
    query = Query(kind=QueryKind.USERNAME, value="torvalds")
    hits = [_make_positive("github.com", "https://github.com/torvalds")]
    card = _render_summary_card(query, hits, elapsed_ms=1234)
    console = Console(width=120, record=True)
    console.print(card)
    rendered = console.export_text()
    # The [N] open · [c] copy · [a] adjacent hint must be present.
    assert "[N]" in rendered
    assert "open" in rendered
    assert "[c]" in rendered
    assert "copy" in rendered
    assert "[a]" in rendered
    assert "adjacent" in rendered
    # The numbered positive row is still rendered.
    assert "github.com" in rendered


def test_summary_card_no_perhit_hint_when_empty() -> None:
    # No positives → no per-hit hint either (hint lives in the positives block).
    query = Query(kind=QueryKind.USERNAME, value="torvalds")
    card = _render_summary_card(query, [], elapsed_ms=200)
    console = Console(width=120, record=True)
    console.print(card)
    rendered = console.export_text()
    assert "[N] open" not in rendered  # hint section omitted


def test_hit_carries_adjacency_extra() -> None:
    # Sanity — Pydantic Hit happily round-trips the extra dict that Agent A's
    # adjacency module populates. Our per_hit_actions branch keys off these.
    h = Hit(
        module="username",
        source="github.com",
        status=HitStatus.FOUND,
        url="https://github.com/torvalds",
        extra={"suggested_kind": "email", "suggested_value": "torvalds@kernel.org"},
    )
    assert h.extra["suggested_kind"] == "email"
    assert h.extra["suggested_value"] == "torvalds@kernel.org"
    # And QueryKind round-trips from the string back into the enum.
    assert QueryKind(h.extra["suggested_kind"]) is QueryKind.EMAIL
