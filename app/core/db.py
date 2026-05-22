"""SQLite cache + history (aiosqlite, WAL). Schema kept minimal on purpose."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiosqlite

from .types import Hit, Query, QueryResult

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    duration_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_queries_value ON queries(kind, value);
CREATE INDEX IF NOT EXISTS idx_queries_started ON queries(started_at DESC);

CREATE TABLE IF NOT EXISTS hits (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    query_id   INTEGER NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
    module     TEXT NOT NULL,
    source     TEXT NOT NULL,
    category   TEXT NOT NULL DEFAULT '',
    status     TEXT NOT NULL,
    title      TEXT NOT NULL DEFAULT '',
    url        TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',
    extra_json TEXT NOT NULL DEFAULT '{}',
    severity   TEXT NOT NULL DEFAULT 'info',
    found_at   TEXT NOT NULL,
    latency_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hits_query ON hits(query_id);
CREATE INDEX IF NOT EXISTS idx_hits_status ON hits(status);

CREATE TABLE IF NOT EXISTS http_cache (
    key        TEXT PRIMARY KEY,        -- module + url + payload digest
    status     INTEGER NOT NULL,
    body       BLOB,
    headers    TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    expires_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_http_cache_expires ON http_cache(expires_at);
"""


class Database:
    """Thin async SQLite wrapper. One Database per process."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        if self._conn is not None:
            return
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(_SCHEMA)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def _exec(self, sql: str, params: tuple[Any, ...] = ()) -> aiosqlite.Cursor:
        assert self._conn is not None, "Database not connected"
        return await self._conn.execute(sql, params)

    # ---- queries / hits ----

    async def save_result(self, result: QueryResult) -> int:
        assert self._conn is not None
        cur = await self._exec(
            """INSERT INTO queries (kind, value, note, started_at, finished_at, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                result.query.kind.value,
                result.query.value,
                result.query.note,
                result.query.started_at.isoformat(),
                result.finished_at.isoformat() if result.finished_at else None,
                result.duration_ms,
            ),
        )
        qid = cur.lastrowid or 0
        if result.hits:
            await self._conn.executemany(
                """INSERT INTO hits (query_id, module, source, category, status, title, url,
                                     detail, extra_json, severity, found_at, latency_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        qid,
                        h.module,
                        h.source,
                        h.category,
                        h.status.value,
                        h.title,
                        h.url,
                        h.detail,
                        json.dumps(h.extra, default=str),
                        h.severity.value,
                        h.found_at.isoformat(),
                        h.latency_ms,
                    )
                    for h in result.hits
                ],
            )
        await self._conn.commit()
        return qid

    async def history_heatmap(self, days: int = 28) -> list[int]:
        """Per-day query counts for the last N days. Index 0 = today, N-1 = oldest."""
        assert self._conn is not None
        async with self._conn.execute(
            """SELECT CAST(julianday('now') - julianday(started_at) AS INTEGER) AS d,
                      COUNT(*) AS n
               FROM queries
               WHERE julianday('now') - julianday(started_at) < ?
               GROUP BY d""",
            (days,),
        ) as cur:
            rows = await cur.fetchall()
        out = [0] * days
        for r in rows:
            i = int(r["d"])
            if 0 <= i < days:
                out[i] = r["n"]
        return out

    async def list_history(self, limit: int = 100) -> list[dict[str, Any]]:
        assert self._conn is not None
        async with self._conn.execute(
            """SELECT q.id, q.kind, q.value, q.note, q.started_at, q.duration_ms,
                      (SELECT COUNT(*) FROM hits h WHERE h.query_id = q.id AND h.status = 'found') AS found,
                      (SELECT COUNT(*) FROM hits h WHERE h.query_id = q.id) AS total
               FROM queries q
               ORDER BY q.started_at DESC
               LIMIT ?""",
            (limit,),
        ) as cur:
            return [dict(row) for row in await cur.fetchall()]

    async def hits_for(self, query_id: int) -> list[Hit]:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM hits WHERE query_id = ? ORDER BY status, source", (query_id,)
        ) as cur:
            rows = await cur.fetchall()
        out: list[Hit] = []
        for r in rows:
            d = dict(r)
            extra_json = d.pop("extra_json", "{}")
            d["extra"] = json.loads(extra_json or "{}")
            d.pop("id", None)
            d.pop("query_id", None)
            out.append(Hit.model_validate(d))
        return out

    async def get_query(self, query_id: int) -> Query | None:
        assert self._conn is not None
        async with self._conn.execute("SELECT * FROM queries WHERE id = ?", (query_id,)) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        return Query.model_validate(
            {"kind": row["kind"], "value": row["value"], "note": row["note"], "started_at": row["started_at"]}
        )

    async def delete_query(self, query_id: int) -> None:
        await self._exec("DELETE FROM queries WHERE id = ?", (query_id,))
        assert self._conn is not None
        await self._conn.commit()

    # ---- http cache ----

    async def cache_get(self, key: str) -> tuple[int, bytes, dict[str, str]] | None:
        assert self._conn is not None
        async with self._conn.execute(
            """SELECT status, body, headers FROM http_cache
               WHERE key = ? AND (expires_at IS NULL OR expires_at > datetime('now'))""",
            (key,),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        return row["status"], row["body"], json.loads(row["headers"] or "{}")

    async def cache_put(
        self, key: str, status: int, body: bytes, headers: dict[str, str], ttl_sec: int = 3600
    ) -> None:
        assert self._conn is not None
        await self._exec(
            """INSERT OR REPLACE INTO http_cache (key, status, body, headers, created_at, expires_at)
               VALUES (?, ?, ?, ?, datetime('now'), datetime('now', ?))""",
            (key, status, body, json.dumps(headers), f"+{ttl_sec} seconds"),
        )
        await self._conn.commit()
