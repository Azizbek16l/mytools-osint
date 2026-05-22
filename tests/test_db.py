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
