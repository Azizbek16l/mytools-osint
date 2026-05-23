"""Diff engine + renderer. Pure logic — no I/O, no network."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from rich.console import Console

from app.core.types import Hit, HitStatus, Query, QueryKind, QueryResult
from app.features.diff import compute_diff, render_diff


def _h(source: str, status: HitStatus = HitStatus.FOUND, *, url: str = "",
       title: str = "") -> Hit:
    return Hit(module="m", source=source, status=status, url=url, title=title)


def test_compute_diff_added_removed_changed_unchanged():
    old = [
        _h("GitHub", url="https://github.com/x", title="x"),
        _h("Reddit", url="https://reddit.com/u/x", title="x"),
        _h("Deprecated", url="https://gone.example/x"),
    ]
    new = [
        _h("GitHub", url="https://github.com/x", title="x"),                # unchanged
        _h("Reddit", url="https://reddit.com/u/x", status=HitStatus.UNCERTAIN, title="x"),  # changed (status)
        _h("GitLab", url="https://gitlab.com/x", title="x"),                # added
    ]
    diff = compute_diff(old, new)
    assert [h.source for h in diff.added] == ["GitLab"]
    assert [h.source for h in diff.removed] == ["Deprecated"]
    assert len(diff.changed) == 1
    old_h, new_h = diff.changed[0]
    assert old_h.status == HitStatus.FOUND
    assert new_h.status == HitStatus.UNCERTAIN
    assert diff.unchanged_count == 1
    assert diff.has_changes is True


def test_compute_diff_title_change_counts_as_changed():
    old = [_h("GH", url="https://github.com/x", title="old-title")]
    new = [_h("GH", url="https://github.com/x", title="new-title")]
    diff = compute_diff(old, new)
    assert diff.added == []
    assert diff.removed == []
    assert len(diff.changed) == 1
    assert diff.unchanged_count == 0


def test_compute_diff_empty_inputs():
    diff = compute_diff([], [])
    assert diff.added == [] and diff.removed == [] and diff.changed == []
    assert diff.unchanged_count == 0
    assert diff.has_changes is False

    diff = compute_diff([], [_h("GH", url="u")])
    assert [h.source for h in diff.added] == ["GH"]
    assert diff.removed == []


def test_compute_diff_dedupes_on_source_url():
    """Same (source, url) appearing twice in one side counts once."""
    old = [
        _h("GH", url="https://github.com/x"),
        _h("GH", url="https://github.com/x"),  # dup
    ]
    new = [_h("GH", url="https://github.com/x")]
    diff = compute_diff(old, new)
    assert diff.unchanged_count == 1
    assert diff.added == []
    assert diff.removed == []


def test_render_diff_does_not_raise():
    q = Query(kind=QueryKind.USERNAME, value="torvalds")
    old = QueryResult(query=q, hits=[
        _h("GitHub", url="https://github.com/torvalds", title="t"),
        _h("OldSite", url="https://old.example/torvalds"),
    ], finished_at=datetime(2026, 5, 1, tzinfo=UTC))
    new = QueryResult(query=q, hits=[
        _h("GitHub", url="https://github.com/torvalds", title="t"),
        _h("GitLab", url="https://gitlab.com/torvalds", title="t"),
    ], finished_at=datetime(2026, 5, 23, tzinfo=UTC))

    console = Console(record=True, force_terminal=False, color_system=None, width=120)
    render_diff(q, old, new, console)
    out = console.export_text()
    # Content sanity — header value present, summary line present.
    assert "torvalds" in out
    assert "2026-05-01" in out and "2026-05-23" in out
    assert "+1 new" in out
    assert "-1 removed" in out
    assert "unchanged" in out


def test_render_diff_no_changes_path():
    q = Query(kind=QueryKind.USERNAME, value="torvalds")
    h = _h("GitHub", url="https://github.com/torvalds", title="t")
    old = QueryResult(query=q, hits=[h], finished_at=datetime(2026, 1, 1, tzinfo=UTC))
    new = QueryResult(query=q, hits=[h], finished_at=datetime(2026, 1, 2, tzinfo=UTC))

    console = Console(record=True, force_terminal=False, color_system=None, width=120)
    render_diff(q, old, new, console)
    out = console.export_text()
    assert "no changes" in out
    assert "+0 new" in out


def test_find_queries_for_value_returns_newest_first(tmp_path):
    """Wired here because it's the DB helper that backs `osint diff <kind> <value>`."""
    import asyncio

    from app.core.db import Database

    async def go():
        db = Database(tmp_path / "diff.sqlite3")
        await db.connect()
        try:
            ids: list[int] = []
            for i in range(3):
                qr = QueryResult(
                    query=Query(kind=QueryKind.USERNAME, value="torvalds",
                                started_at=datetime(2026, 1, 1 + i, tzinfo=UTC)),
                    hits=[],
                    finished_at=datetime(2026, 1, 1 + i, tzinfo=UTC),
                    duration_ms=1,
                )
                ids.append(await db.save_result(qr))
            found = await db.find_queries_for_value("username", "torvalds")
            # newest first → reversed insertion order
            assert found == list(reversed(ids))
            # mismatched value → empty
            assert await db.find_queries_for_value("username", "linus") == []
            # respects limit
            assert len(await db.find_queries_for_value("username", "torvalds", limit=1)) == 1
        finally:
            await db.close()

    asyncio.run(go())


# silence pytest about pytestmark unused
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")
