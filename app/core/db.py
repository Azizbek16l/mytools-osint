"""SQLite cache + history (aiosqlite, WAL). Schema kept minimal on purpose."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import aiosqlite

from .types import Hit, Query, QueryResult

_PRAGMAS = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
"""

# Each migration MUST be idempotent on its own (CREATE TABLE IF NOT EXISTS,
# CREATE INDEX IF NOT EXISTS). We track applied versions in `schema_version`
# so future ALTER-style migrations only run once. Re-running connect() on
# either a fresh or already-populated DB must succeed.
_MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
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
            key        TEXT PRIMARY KEY,
            status     INTEGER NOT NULL,
            body       BLOB,
            headers    TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            expires_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_http_cache_expires ON http_cache(expires_at);
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS watchlist (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            kind          TEXT NOT NULL,
            value         TEXT NOT NULL,
            label         TEXT,
            interval_h    INTEGER NOT NULL DEFAULT 24,
            enabled       INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL,
            last_run_at   TEXT,
            last_query_id INTEGER,
            UNIQUE(kind, value)
        );
        CREATE INDEX IF NOT EXISTS idx_watchlist_due ON watchlist(enabled, last_run_at);

        CREATE TABLE IF NOT EXISTS notifications (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            watchlist_id  INTEGER NOT NULL REFERENCES watchlist(id) ON DELETE CASCADE,
            query_id      INTEGER NOT NULL,
            new_hits_json TEXT NOT NULL,
            sent_at       TEXT,
            channel       TEXT NOT NULL,
            status        TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_notifications_watch ON notifications(watchlist_id);
        CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status);
        """,
    ),
    (
        3,
        # v4.0 entity graph layer. Per the backend reviewer's recommendation:
        # two normalised tables, canonical column at insert time, JSON sidecar
        # for type-specific attributes, UNIQUE on (src,dst,rel,hit_id) so the
        # same (entity, entity, relationship) discovered by N hits records N
        # pieces of evidence (not N duplicate edges).
        """
        CREATE TABLE IF NOT EXISTS entities (
            id          TEXT PRIMARY KEY,        -- sha1(<type>:<canonical>)[:16]
            type        TEXT NOT NULL,
            value       TEXT NOT NULL,           -- canonical form
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            confidence  REAL NOT NULL DEFAULT 1.0,
            tags        TEXT NOT NULL DEFAULT '[]',
            extra_json  TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_entities_type   ON entities(type);
        CREATE INDEX IF NOT EXISTS idx_entities_value  ON entities(type, value);

        CREATE TABLE IF NOT EXISTS edges (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            src_id      TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            dst_id      TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            rel         TEXT NOT NULL,
            source      TEXT NOT NULL DEFAULT '',     -- module / data source
            hit_id      INTEGER REFERENCES hits(id) ON DELETE SET NULL,
            confidence  REAL NOT NULL DEFAULT 1.0,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            extra_json  TEXT NOT NULL DEFAULT '{}',
            UNIQUE(src_id, dst_id, rel, hit_id)
        );
        CREATE INDEX IF NOT EXISTS idx_edges_src_rel ON edges(src_id, rel);
        CREATE INDEX IF NOT EXISTS idx_edges_dst_rel ON edges(dst_id, rel);

        -- Persisted pivot-visited set (so re-running an --pivot scan resumes).
        CREATE TABLE IF NOT EXISTS pivot_visited (
            query_id   INTEGER NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
            entity_id  TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            depth      INTEGER NOT NULL DEFAULT 0,
            visited_at TEXT NOT NULL,
            PRIMARY KEY(query_id, entity_id)
        );
        """,
    ),
    (
        4,
        # Wave D — named cases / investigations. A case is a labelled bucket
        # that groups multiple scans + analyst notes + the entities each scan
        # discovered. The same QueryResult can belong to many cases (just adds
        # another row to case_runs). case_entities is the flat union used for
        # `case show` / `case resume` without re-walking the edges graph.
        """
        CREATE TABLE IF NOT EXISTS cases (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            slug       TEXT NOT NULL UNIQUE,
            name       TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'open',
            kind       TEXT NOT NULL DEFAULT '',
            target     TEXT NOT NULL DEFAULT '',
            notes      TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);

        CREATE TABLE IF NOT EXISTS case_runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            query_id    INTEGER NOT NULL REFERENCES queries(id) ON DELETE CASCADE,
            started_at  TEXT NOT NULL,
            finished_at TEXT,
            profile     TEXT NOT NULL DEFAULT '',
            agent_used  INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_case_runs_case ON case_runs(case_id, started_at DESC);

        CREATE TABLE IF NOT EXISTS case_notes (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            ts      TEXT NOT NULL,
            body    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_case_notes_case ON case_notes(case_id, ts DESC);

        CREATE TABLE IF NOT EXISTS case_entities (
            case_id    INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            entity_id  TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
            first_seen TEXT NOT NULL,
            PRIMARY KEY (case_id, entity_id)
        );
        CREATE INDEX IF NOT EXISTS idx_case_entities_case ON case_entities(case_id);
        """,
    ),
]


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
        await self._conn.executescript(_PRAGMAS)
        await self.migrate()

    async def migrate(self) -> None:
        """Apply pending schema migrations. Idempotent — safe to call twice.

        Tracks applied versions in `schema_version(version PK)`. Each migration
        in _MIGRATIONS uses CREATE ... IF NOT EXISTS, so reapplying is a no-op
        even if the version table is wiped.
        """
        assert self._conn is not None, "Database not connected"
        await self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version ("
            "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        async with self._conn.execute("SELECT version FROM schema_version") as cur:
            applied = {row["version"] for row in await cur.fetchall()}
        for version, ddl in _MIGRATIONS:
            if version in applied:
                continue
            await self._conn.executescript(ddl)
            await self._conn.execute(
                "INSERT OR IGNORE INTO schema_version (version, applied_at) "
                "VALUES (?, datetime('now'))",
                (version,),
            )
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

    async def find_queries_for_value(
        self, kind: str, value: str, limit: int = 10
    ) -> list[int]:
        """Most recent query IDs for this (kind, value), newest first."""
        assert self._conn is not None
        async with self._conn.execute(
            """SELECT id FROM queries
               WHERE kind = ? AND value = ?
               ORDER BY started_at DESC
               LIMIT ?""",
            (kind, value, limit),
        ) as cur:
            return [row["id"] for row in await cur.fetchall()]

    # ---- watchlist (row-level helpers; high-level API lives in app.features.watchlist) ----

    async def watchlist_insert(
        self,
        kind: str,
        value: str,
        label: str | None,
        interval_h: int,
        created_at: str,
    ) -> int:
        """Insert a watchlist row. Raises sqlite3.IntegrityError on UNIQUE conflict."""
        assert self._conn is not None
        cur = await self._exec(
            """INSERT INTO watchlist (kind, value, label, interval_h, enabled, created_at)
               VALUES (?, ?, ?, ?, 1, ?)""",
            (kind, value, label, interval_h, created_at),
        )
        await self._conn.commit()
        return cur.lastrowid or 0

    async def watchlist_get(self, id_: int) -> dict[str, Any] | None:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM watchlist WHERE id = ?", (id_,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def watchlist_get_by_label(self, label: str) -> dict[str, Any] | None:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM watchlist WHERE label = ?", (label,)
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def watchlist_list(self) -> list[dict[str, Any]]:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM watchlist ORDER BY id"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def watchlist_delete(self, id_: int) -> bool:
        assert self._conn is not None
        cur = await self._exec("DELETE FROM watchlist WHERE id = ?", (id_,))
        await self._conn.commit()
        return (cur.rowcount or 0) > 0

    async def watchlist_set_enabled(self, id_: int, enabled: bool) -> None:
        assert self._conn is not None
        await self._exec(
            "UPDATE watchlist SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, id_),
        )
        await self._conn.commit()

    async def watchlist_mark_run(
        self, id_: int, query_id: int, last_run_at: str
    ) -> None:
        assert self._conn is not None
        await self._exec(
            "UPDATE watchlist SET last_run_at = ?, last_query_id = ? WHERE id = ?",
            (last_run_at, query_id, id_),
        )
        await self._conn.commit()

    async def notifications_insert(
        self,
        watchlist_id: int,
        query_id: int,
        new_hits_json: str,
        channel: str,
        status: str,
        sent_at: str | None = None,
    ) -> int:
        assert self._conn is not None
        cur = await self._exec(
            """INSERT INTO notifications
               (watchlist_id, query_id, new_hits_json, channel, status, sent_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (watchlist_id, query_id, new_hits_json, channel, status, sent_at),
        )
        await self._conn.commit()
        return cur.lastrowid or 0

    async def notifications_for(self, watchlist_id: int) -> list[dict[str, Any]]:
        assert self._conn is not None
        async with self._conn.execute(
            "SELECT * FROM notifications WHERE watchlist_id = ? ORDER BY id DESC",
            (watchlist_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

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

    # ------------------------------------------------------------------ v4.0 entity graph

    async def entity_upsert(self, entity) -> None:
        """Insert or merge an Entity. Idempotent — same id updates last_seen."""
        assert self._conn is not None
        from app.core.entities import Entity  # noqa
        ent: Entity = entity
        now = ent.last_seen.isoformat()
        await self._exec(
            """INSERT INTO entities
               (id, type, value, first_seen, last_seen, confidence, tags, extra_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 last_seen = excluded.last_seen,
                 confidence = MAX(entities.confidence, excluded.confidence),
                 tags = excluded.tags,
                 extra_json = excluded.extra_json
            """,
            (ent.id, ent.type.value, ent.value, ent.first_seen.isoformat(),
             now, ent.confidence, json.dumps(ent.tags),
             json.dumps(ent.extra, default=str)),
        )
        await self._conn.commit()

    async def edge_upsert(self, edge) -> None:
        """Insert an Edge (uniq on (src,dst,rel,hit_id))."""
        assert self._conn is not None
        from app.core.entities import Edge  # noqa
        e: Edge = edge
        now = e.last_seen.isoformat()
        await self._exec(
            """INSERT INTO edges
               (src_id, dst_id, rel, source, hit_id, confidence,
                first_seen, last_seen, extra_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(src_id, dst_id, rel, hit_id) DO UPDATE SET
                 last_seen = excluded.last_seen,
                 confidence = MAX(edges.confidence, excluded.confidence)
            """,
            (e.src_id, e.dst_id, e.type.value, e.source, e.hit_id, e.confidence,
             e.first_seen.isoformat(), now, json.dumps(e.extra, default=str)),
        )
        await self._conn.commit()

    async def entity_get(self, type_: str, value: str):
        """Look up one entity by (type, canonical-value). Returns dict or None."""
        assert self._conn is not None
        from app.core.entities import EntityType, canonical_key
        canon = canonical_key(EntityType(type_), value)
        async with self._conn.execute(
            "SELECT * FROM entities WHERE type = ? AND value = ?",
            (type_, canon),
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def edges_from(self, entity_id: str) -> list[dict]:
        """All edges leaving this entity (id, dst_id, rel, source, confidence)."""
        assert self._conn is not None
        async with self._conn.execute(
            """SELECT src_id, dst_id, rel, source, confidence, first_seen, last_seen
               FROM edges WHERE src_id = ?""",
            (entity_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def edges_to(self, entity_id: str) -> list[dict]:
        """All edges arriving at this entity."""
        assert self._conn is not None
        async with self._conn.execute(
            """SELECT src_id, dst_id, rel, source, confidence, first_seen, last_seen
               FROM edges WHERE dst_id = ?""",
            (entity_id,),
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def neighbours_batch(self, entity_ids: list[str]) -> list[dict]:
        """Edges + dst-entity rows for a batch (used by BFS — backend reviewer's
        recommendation: chunk to 500 to avoid SQLite param limit)."""
        assert self._conn is not None
        if not entity_ids:
            return []
        out: list[dict] = []
        for i in range(0, len(entity_ids), 500):
            chunk = entity_ids[i:i + 500]
            # `placeholders` is only "?,?,?…" (one bound marker per id); the
            # ids themselves are bound via tuple(chunk), never interpolated.
            placeholders = ",".join("?" for _ in chunk)
            async with self._conn.execute(
                f"""SELECT e.src_id, e.dst_id, e.rel, e.source, e.confidence,
                          t.type AS dst_type, t.value AS dst_value
                   FROM edges e JOIN entities t ON e.dst_id = t.id
                   WHERE e.src_id IN ({placeholders})""",  # noqa: S608 — only ? placeholders interpolated, values bound
                tuple(chunk),
            ) as cur:
                rows = await cur.fetchall()
                out.extend(dict(r) for r in rows)
        return out

    async def entity_count(self) -> int:
        assert self._conn is not None
        async with self._conn.execute("SELECT COUNT(*) AS n FROM entities") as cur:
            row = await cur.fetchone()
        return row["n"] if row else 0

    async def edge_count(self) -> int:
        assert self._conn is not None
        async with self._conn.execute("SELECT COUNT(*) AS n FROM edges") as cur:
            row = await cur.fetchone()
        return row["n"] if row else 0

    async def entity_forget(self, type_: str, value: str) -> int:
        """GDPR-style erasure. Removes entity + cascading edges via FK."""
        assert self._conn is not None
        from app.core.entities import EntityType, canonical_key
        canon = canonical_key(EntityType(type_), value)
        cur = await self._conn.execute(
            "DELETE FROM entities WHERE type = ? AND value = ?",
            (type_, canon),
        )
        await self._conn.commit()
        return cur.rowcount or 0

    async def pivot_visited_add(self, query_id: int, entity_id: str, depth: int) -> bool:
        """Returns True if newly added (unseen for this scan), False if already seen."""
        assert self._conn is not None
        try:
            await self._exec(
                """INSERT INTO pivot_visited (query_id, entity_id, depth, visited_at)
                   VALUES (?, ?, ?, datetime('now'))""",
                (query_id, entity_id, depth),
            )
            await self._conn.commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    async def correlate_query(self, query_id: int) -> tuple[int, int]:
        """Run correlation.derive() over every hit of a saved query, upsert
        the resulting entities + edges. Returns (n_entities_seen, n_edges_seen).
        Idempotent — re-running just refreshes last_seen timestamps.
        """
        assert self._conn is not None
        from app.core.correlation import derive
        # Load query
        async with self._conn.execute(
            "SELECT * FROM queries WHERE id = ?", (query_id,),
        ) as cur:
            qrow = await cur.fetchone()
        if not qrow:
            return (0, 0)
        from datetime import datetime as _dt

        from app.core.types import Hit, HitStatus, Query, QueryKind, Severity
        query = Query(
            kind=QueryKind(qrow["kind"]),
            value=qrow["value"],
            note=qrow["note"],
            started_at=_dt.fromisoformat(qrow["started_at"]),
        )
        # Load all hits with their ids
        async with self._conn.execute(
            "SELECT * FROM hits WHERE query_id = ?", (query_id,),
        ) as cur:
            hit_rows = await cur.fetchall()
        seen_entities: set[str] = set()
        seen_edges: set[tuple[str, str, str]] = set()
        for hr in hit_rows:
            hit = Hit(
                module=hr["module"], source=hr["source"], category=hr["category"],
                status=HitStatus(hr["status"]), title=hr["title"], url=hr["url"],
                detail=hr["detail"], severity=Severity(hr["severity"]),
                extra=json.loads(hr["extra_json"] or "{}"),
                found_at=_dt.fromisoformat(hr["found_at"]),
                latency_ms=hr["latency_ms"],
            )
            entities, edges = derive(query, hit, hr["id"])
            for ent in entities:
                await self.entity_upsert(ent)
                seen_entities.add(ent.id)
            for e in edges:
                await self.edge_upsert(e)
                seen_edges.add((e.src_id, e.dst_id, e.type.value))
        return (len(seen_entities), len(seen_edges))
