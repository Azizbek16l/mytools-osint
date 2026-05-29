"""SQLite cache + history. Uses an isolated tmp_path DB."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.db import Database
from app.core.types import Hit, HitStatus, Query, QueryKind, QueryResult, Severity


@pytest.mark.asyncio
async def test_save_and_load(tmp_path):
    db = Database(tmp_path / "test.sqlite3")
    await db.connect()
    try:
        q = Query(kind=QueryKind.USERNAME, value="torvalds")
        hits = [
            Hit(module="username", source="GitHub", category="tech",
                status=HitStatus.FOUND, url="https://github.com/torvalds",
                title="GitHub", detail="HTTP 200", severity=Severity.MEDIUM,
                latency_ms=120),
            Hit(module="username", source="Reddit", category="social",
                status=HitStatus.NOT_FOUND, detail="HTTP 404"),
        ]
        result = QueryResult(
            query=q, hits=hits,
            finished_at=datetime.now(UTC), duration_ms=1234,
        )
        qid = await db.save_result(result)
        assert qid > 0

        hist = await db.list_history(10)
        assert any(row["id"] == qid for row in hist)
        the = next(row for row in hist if row["id"] == qid)
        assert the["found"] == 1
        assert the["total"] == 2

        roundtrip = await db.hits_for(qid)
        assert len(roundtrip) == 2
        assert {h.source for h in roundtrip} == {"GitHub", "Reddit"}

        await db.delete_query(qid)
        assert not any(row["id"] == qid for row in await db.list_history(10))
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_http_cache(tmp_path):
    db = Database(tmp_path / "c.sqlite3")
    await db.connect()
    try:
        await db.cache_put("k", 200, b"body", {"x": "1"}, ttl_sec=60)
        got = await db.cache_get("k")
        assert got is not None
        status, body, headers = got
        assert status == 200
        assert body == b"body"
        assert headers["x"] == "1"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_migration_idempotent_for_v4_cases(tmp_path):
    """connect() must be safe to call repeatedly; v4 tables exist exactly once."""
    db_path = tmp_path / "mig.sqlite3"
    # First open — applies v1..v4 fresh.
    db = Database(db_path)
    await db.connect()
    try:
        await db.migrate()       # re-run on already-applied is a no-op
        await db.migrate()
        assert db._conn is not None
        async with db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN ('cases','case_runs','case_notes','case_entities')"
        ) as cur:
            names = sorted(r["name"] for r in await cur.fetchall())
        assert names == ["case_entities", "case_notes", "case_runs", "cases"]
        # schema_version must contain version 4 exactly once
        async with db._conn.execute(
            "SELECT COUNT(*) AS n FROM schema_version WHERE version = 4"
        ) as cur:
            row = await cur.fetchone()
        assert row["n"] == 1
    finally:
        await db.close()

    # Re-open existing DB — connect() must NOT re-apply migrations.
    db2 = Database(db_path)
    await db2.connect()
    try:
        assert db2._conn is not None
        async with db2._conn.execute(
            "SELECT COUNT(*) AS n FROM schema_version WHERE version = 4"
        ) as cur:
            assert (await cur.fetchone())["n"] == 1
    finally:
        await db2.close()


@pytest.mark.asyncio
async def test_v4_cases_fk_cascade(tmp_path):
    """Deleting a case wipes its runs, notes, entities via ON DELETE CASCADE."""
    from datetime import UTC
    from datetime import datetime as _dt
    db = Database(tmp_path / "cascade.sqlite3")
    await db.connect()
    try:
        assert db._conn is not None
        # set up minimal cross-table rows
        await db._conn.execute(
            "INSERT INTO cases (slug, name, created_at, updated_at, status, kind, target, notes) "
            "VALUES ('x', 'X', ?, ?, 'open', '', '', '')",
            (_dt.now(UTC).isoformat(), _dt.now(UTC).isoformat()),
        )
        case_id = (await (await db._conn.execute("SELECT id FROM cases")).fetchone())["id"]
        # need a query row to satisfy the FK from case_runs
        q = Query(kind=QueryKind.USERNAME, value="x")
        qid = await db.save_result(QueryResult(query=q, hits=[]))
        await db._conn.execute(
            "INSERT INTO case_runs (case_id, query_id, started_at, profile, agent_used) "
            "VALUES (?, ?, ?, '', 0)",
            (case_id, qid, _dt.now(UTC).isoformat()),
        )
        await db._conn.execute(
            "INSERT INTO case_notes (case_id, ts, body) VALUES (?, ?, 'hello')",
            (case_id, _dt.now(UTC).isoformat()),
        )
        await db._conn.commit()
        await db._conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        await db._conn.commit()
        async with db._conn.execute(
            "SELECT COUNT(*) AS n FROM case_runs WHERE case_id = ?", (case_id,),
        ) as cur:
            assert (await cur.fetchone())["n"] == 0
        async with db._conn.execute(
            "SELECT COUNT(*) AS n FROM case_notes WHERE case_id = ?", (case_id,),
        ) as cur:
            assert (await cur.fetchone())["n"] == 0
    finally:
        await db.close()
