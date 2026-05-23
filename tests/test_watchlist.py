"""Watchlist CRUD + due-detection + run_due diff semantics. Offline."""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest

from app.core.db import Database
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity
from app.features import watchlist as wl

# ---- helpers ---------------------------------------------------------------


def _hit(source: str, status: HitStatus = HitStatus.FOUND, *, url: str = "",
         title: str = "", severity: Severity = Severity.LOW) -> Hit:
    return Hit(
        module="test", source=source, status=status, url=url,
        title=title or source, severity=severity,
    )


def _make_runner(hits: list[Hit]) -> Runner:
    """Build a Runner whose single module yields the given hits for any USERNAME query."""
    r = Runner()

    async def producer(_q: Query) -> AsyncIterator[Hit]:
        for h in hits:
            yield h

    r.register("fake", [QueryKind.USERNAME], producer)
    return r


@pytest.fixture
async def db(tmp_path):
    db = Database(tmp_path / "wl.sqlite3")
    await db.connect()
    yield db
    await db.close()


# ---- CRUD ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_then_list_then_remove(db):
    e = await wl.add(db, kind="username", value="torvalds", label="linus", interval_h=12)
    assert e.id is not None
    assert e.kind == "username"
    assert e.value == "torvalds"
    assert e.label == "linus"
    assert e.interval_h == 12
    assert e.enabled is True
    assert e.last_run_at is None

    items = await wl.list_all(db)
    assert len(items) == 1
    assert items[0].label == "linus"

    # remove by label string
    assert await wl.remove(db, "linus") is True
    assert await wl.list_all(db) == []

    # remove on missing label is a clean False
    assert await wl.remove(db, "ghost") is False


@pytest.mark.asyncio
async def test_add_rejects_bad_kind_and_bad_interval(db):
    with pytest.raises(ValueError):
        await wl.add(db, kind="not-a-kind", value="x")
    with pytest.raises(ValueError):
        await wl.add(db, kind="username", value="x", interval_h=0)
    with pytest.raises(ValueError):
        await wl.add(db, kind="username", value="   ")


@pytest.mark.asyncio
async def test_unique_value_constraint(db):
    await wl.add(db, kind="username", value="torvalds")
    # second add for same (kind, value) raises IntegrityError up the stack
    import sqlite3
    with pytest.raises((sqlite3.IntegrityError, Exception)) as exc:
        await wl.add(db, kind="username", value="torvalds")
    assert "UNIQUE" in str(exc.value) or "unique" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_disable_then_enable(db):
    e = await wl.add(db, kind="username", value="torvalds")
    assert e.id is not None
    await wl.disable(db, e.id)
    items = await wl.list_all(db)
    assert items[0].enabled is False

    await wl.enable(db, e.id)
    items = await wl.list_all(db)
    assert items[0].enabled is True


# ---- due detection ---------------------------------------------------------


@pytest.mark.asyncio
async def test_is_due(db):
    e = await wl.add(db, kind="username", value="torvalds", interval_h=24)
    assert e.id is not None
    # fresh entry — last_run_at is None, always due
    assert e.is_due() is True

    # simulate a recent run by directly updating
    now = datetime.now(UTC)
    await db.watchlist_mark_run(e.id, 999, now.isoformat())
    items = await wl.list_all(db)
    assert items[0].is_due(now) is False
    assert items[0].is_due(now + timedelta(hours=25)) is True

    # disabled entries are never due
    await wl.disable(db, e.id)
    items = await wl.list_all(db)
    assert items[0].is_due(now + timedelta(hours=999)) is False


@pytest.mark.asyncio
async def test_list_only_due_filter(db):
    e1 = await wl.add(db, kind="username", value="alice")
    e2 = await wl.add(db, kind="username", value="bob")
    assert e1.id and e2.id
    # Mark e2 as just-run so it's NOT due
    await db.watchlist_mark_run(e2.id, 1, datetime.now(UTC).isoformat())

    due = await wl.list_all(db, only_due=True)
    assert [e.value for e in due] == ["alice"]


# ---- run_due + diff semantics ---------------------------------------------


@pytest.mark.asyncio
async def test_run_due_first_run_no_notification(db):
    """First run has no prior — but we treat that as 'baseline', not 'new'.

    Actually per the spec: "A 'new hit' is one whose ... did NOT appear in the
    prior scan." On the very first run there's no prior, so every FOUND hit IS
    new. Verify that.
    """
    e = await wl.add(db, kind="username", value="torvalds")
    assert e.id is not None

    runner = _make_runner([_hit("GitHub", url="https://github.com/torvalds")])
    captured: list[tuple[wl.WatchlistEntry, list[Hit]]] = []

    async def on_new(entry, hits):
        captured.append((entry, list(hits)))

    out = await wl.run_due(db, runner, on_new_finding=on_new)
    assert len(out) == 1
    assert out[0][0].id == e.id
    assert [h.source for h in out[0][1]] == ["GitHub"]
    assert len(captured) == 1

    # watchlist row was marked-run and now has a last_query_id
    after = (await wl.list_all(db))[0]
    assert after.last_run_at is not None
    assert after.last_query_id is not None


@pytest.mark.asyncio
async def test_run_due_diff_emits_only_new_hits(db):
    """Run twice, second run adds a hit — only the new one should fire."""
    e = await wl.add(db, kind="username", value="torvalds")
    assert e.id is not None

    # first run: GitHub
    runner1 = _make_runner([_hit("GitHub", url="https://github.com/torvalds")])
    await wl.run_due(db, runner1)

    # second run: GitHub (same) + GitLab (new)
    runner2 = _make_runner([
        _hit("GitHub", url="https://github.com/torvalds"),
        _hit("GitLab", url="https://gitlab.com/torvalds"),
    ])
    # Force-run since the just-marked entry isn't due yet
    out = await wl.run_due(db, runner2, force_all=True)
    assert len(out) == 1
    new_sources = [h.source for h in out[0][1]]
    assert new_sources == ["GitLab"]


@pytest.mark.asyncio
async def test_run_due_ignores_noise_statuses(db):
    """NOT_FOUND / NO_DATA / SKIPPED must never trigger a notification."""
    e = await wl.add(db, kind="username", value="torvalds")
    assert e.id is not None

    # baseline run with one FOUND
    await wl.run_due(db, _make_runner([_hit("GitHub", url="https://github.com/torvalds")]))

    # second run: same FOUND + a bunch of noise
    runner = _make_runner([
        _hit("GitHub", url="https://github.com/torvalds"),
        _hit("Reddit", status=HitStatus.NOT_FOUND),
        _hit("Twitter", status=HitStatus.SKIPPED),
        _hit("Mastodon", status=HitStatus.NO_DATA),
    ])
    out = await wl.run_due(db, runner, force_all=True)
    # No new informative-and-notifiable hits → no entries in out
    assert out == []


@pytest.mark.asyncio
async def test_run_due_on_new_finding_failure_does_not_abort(db):
    """An exception inside on_new_finding for one entry must not skip the next."""
    e1 = await wl.add(db, kind="username", value="alice")
    e2 = await wl.add(db, kind="username", value="bob")
    assert e1.id and e2.id

    runner = _make_runner([_hit("GitHub", url="https://github.com/x")])

    seen: list[str] = []

    async def on_new(entry, hits):
        seen.append(entry.value)
        if entry.value == "alice":
            raise RuntimeError("boom")

    out = await wl.run_due(db, runner, on_new_finding=on_new)
    assert len(out) == 2
    assert sorted(seen) == ["alice", "bob"]


@pytest.mark.asyncio
async def test_notifications_persisted(db):
    e = await wl.add(db, kind="username", value="torvalds")
    assert e.id is not None
    await wl.run_due(db, _make_runner([_hit("GitHub", url="https://github.com/torvalds")]))
    rows = await db.notifications_for(e.id)
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"
    assert rows[0]["channel"] == "telegram"
