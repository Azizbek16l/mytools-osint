"""Named cases / investigations (Wave D1).

A case is a labelled bucket that groups scans + analyst notes + the union of
every entity any of its scans discovered. It is opt-in — nothing existing
auto-attaches to a case; the user calls ``osint case new`` or passes
``--case <slug>`` to a scan.

Design notes:
  * Slug is the user-facing handle (URL-safe, unique). The integer ``id`` is
    purely internal so renaming a case (future) doesn't break foreign keys.
  * Status is a tiny enum: ``open`` / ``closed``. We deliberately don't model
    workflow states ("triage / investigating / report") — that's an analyst
    decision better expressed in a free-text note.
  * ``attach_run`` is the only path that ever writes ``case_runs`` /
    ``case_entities``. It saves the QueryResult first, then derives entities
    via the same correlation engine the rest of the app uses, then ingests
    the resulting entity ids into ``case_entities`` (idempotent — re-running
    against an already-seen entity is a no-op due to the composite PK).
  * Timeline is built by UNION ALL of (run rows, note rows) ordered by time —
    so notes show up interleaved with runs, the way an analyst expects.
  * Resume returns a tiny dataclass containing whatever the next-action
    machinery (agent loop, runner, CLI) needs to pick up where we left off.
    It does NOT itself rerun anything.

Schema lives in db.py migration v4.
"""
from __future__ import annotations

import builtins
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.db import Database
from app.core.types import QueryResult

log = logging.getLogger("osint.cases")

# Slug discipline: lowercase letters / digits / dash / underscore, 2..64
# chars. Keeps slugs URL-safe and filesystem-safe (we may persist exports
# later under a directory named after the slug).
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{1,63}$")

VALID_STATUSES = frozenset({"open", "closed"})


def _now() -> str:
    return datetime.now(UTC).isoformat()


def validate_slug(slug: str) -> str:
    """Return the normalised slug or raise ``ValueError``.

    Lowercase + strip; matches against ``_SLUG_RE``. This is the only allowed
    way to canonicalise a slug — keep callers calling it so we don't end up
    with mixed-case duplicates leaking into the DB.
    """
    if slug is None:
        raise ValueError("slug must be non-empty")
    s = slug.strip().lower()
    if not _SLUG_RE.match(s):
        raise ValueError(
            "slug must match [a-z0-9][a-z0-9_-]{1,63} "
            "(lowercase letters/digits/dash/underscore, 2..64 chars)"
        )
    return s


# ---------------------------------------------------------------------------
# ResumeContext
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ResumeContext:
    """Everything needed to re-run the most recent action of a case.

    Empty fields mean "no prior run" — the caller (CLI or agent) must decide
    what to do (e.g. fall back to the case's seed target).
    """

    case_slug: str
    last_query_id: int | None
    last_kind: str
    last_target: str
    last_profile: str
    last_agent_used: bool
    seed_kind: str
    seed_target: str
    entity_count: int
    last_entities: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Case dataclass
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Case:
    id: int
    slug: str
    name: str
    status: str
    kind: str
    target: str
    notes: str
    created_at: datetime
    updated_at: datetime

    # ---- constructors -----------------------------------------------------

    @classmethod
    def new(
        cls,
        db: Database,
        slug: str,
        name: str | None = None,
        kind: str | None = None,
        target: str | None = None,
    ) -> Case:
        """Async factory: create a new case row and return the model.

        Despite the ``@classmethod`` signature, this is an async method (the
        rest of the API is async; we keep ``new`` symmetric with the spec).
        """
        raise NotImplementedError  # see _new_impl — async path

    @staticmethod
    def get(db: Database, slug: str) -> Case | None:
        """Async — fetch a case by slug or return None. (see _get_impl)."""
        raise NotImplementedError

    @staticmethod
    def list(db: Database, *, status: str = "open") -> list[Case]:
        """Async — list cases. ``status='all'`` returns every row."""
        raise NotImplementedError

    # ---- instance methods (async) — see module-level _* helpers ----------

    async def add_note(self, db: Database, body: str) -> int:
        return await _add_note_impl(db, self, body)

    async def set_status(self, db: Database, status: str) -> None:
        await _set_status_impl(db, self, status)

    # NB: ``list`` is shadowed by the ``Case.list`` static method above, so the
    # builtin must be qualified here for the type checker.
    async def timeline(self, db: Database) -> builtins.list[dict[str, Any]]:
        return await _timeline_impl(db, self)

    async def attach_run(
        self,
        db: Database,
        query_result: QueryResult,
        profile: str = "",
        agent_used: bool = False,
    ) -> int:
        return await _attach_run_impl(db, self, query_result, profile, agent_used)

    async def resume(self, db: Database) -> ResumeContext:
        return await _resume_impl(db, self)


# ---------------------------------------------------------------------------
# Async implementations — kept module-level so they're easily mockable in tests
# ---------------------------------------------------------------------------


def _root_entity_id(query_result: QueryResult) -> str | None:
    """Entity id of the query root, or None if this kind has no root entity.

    Reuses the correlation engine's kind→type mapping + id derivation so the
    id we INSERT into case_entities matches exactly what ``correlate_query``
    upserts (otherwise the existence check would never hit). PASSWORD queries
    map to None (we never store passwords as entities).
    """
    from app.core.correlation import _query_root_entity

    root = _query_root_entity(query_result.query)
    return root.id if root is not None else None


def _row_to_case(row: dict[str, Any]) -> Case:
    return Case(
        id=int(row["id"]),
        slug=str(row["slug"]),
        name=str(row.get("name") or ""),
        status=str(row.get("status") or "open"),
        kind=str(row.get("kind") or ""),
        target=str(row.get("target") or ""),
        notes=str(row.get("notes") or ""),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


async def new(
    db: Database,
    slug: str,
    name: str | None = None,
    kind: str | None = None,
    target: str | None = None,
) -> Case:
    """Create a new case row. Raises ValueError on bad slug; sqlite IntegrityError on dup."""
    s = validate_slug(slug)
    assert db._conn is not None
    now = _now()
    cur = await db._conn.execute(
        """INSERT INTO cases (slug, name, created_at, updated_at, status, kind, target, notes)
           VALUES (?, ?, ?, ?, 'open', ?, ?, '')""",
        (s, (name or "").strip(), now, now, (kind or "").strip(), (target or "").strip()),
    )
    await db._conn.commit()
    cid = cur.lastrowid or 0
    return await _get_by_id(db, cid)  # type: ignore[return-value]


async def get(db: Database, slug: str) -> Case | None:
    """Return the case with this slug or None."""
    try:
        s = validate_slug(slug)
    except ValueError:
        return None
    assert db._conn is not None
    async with db._conn.execute("SELECT * FROM cases WHERE slug = ?", (s,)) as cur:
        row = await cur.fetchone()
    return _row_to_case(dict(row)) if row else None


async def _get_by_id(db: Database, case_id: int) -> Case | None:
    assert db._conn is not None
    async with db._conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)) as cur:
        row = await cur.fetchone()
    return _row_to_case(dict(row)) if row else None


async def list_cases(db: Database, *, status: str = "open") -> list[Case]:
    """List cases. ``status='all'`` returns every row; otherwise filters by status."""
    assert db._conn is not None
    if status == "all":
        async with db._conn.execute(
            "SELECT * FROM cases ORDER BY updated_at DESC"
        ) as cur:
            rows = await cur.fetchall()
    else:
        if status not in VALID_STATUSES:
            raise ValueError(f"unknown status {status!r}; valid: {sorted(VALID_STATUSES)} or 'all'")
        async with db._conn.execute(
            "SELECT * FROM cases WHERE status = ? ORDER BY updated_at DESC",
            (status,),
        ) as cur:
            rows = await cur.fetchall()
    return [_row_to_case(dict(r)) for r in rows]


async def remove(db: Database, slug: str) -> bool:
    """Hard delete a case (cascades to runs/notes/entities). Returns True if removed."""
    try:
        s = validate_slug(slug)
    except ValueError:
        return False
    assert db._conn is not None
    cur = await db._conn.execute("DELETE FROM cases WHERE slug = ?", (s,))
    await db._conn.commit()
    return (cur.rowcount or 0) > 0


# ---- instance ops ----------------------------------------------------------


async def _add_note_impl(db: Database, case: Case, body: str) -> int:
    if not body or not body.strip():
        raise ValueError("note body must be non-empty")
    assert db._conn is not None
    now = _now()
    cur = await db._conn.execute(
        "INSERT INTO case_notes (case_id, ts, body) VALUES (?, ?, ?)",
        (case.id, now, body.strip()),
    )
    await db._conn.execute(
        "UPDATE cases SET updated_at = ? WHERE id = ?", (now, case.id)
    )
    await db._conn.commit()
    case.updated_at = datetime.fromisoformat(now)
    return cur.lastrowid or 0


async def _set_status_impl(db: Database, case: Case, status: str) -> None:
    if status not in VALID_STATUSES:
        raise ValueError(f"unknown status {status!r}; valid: {sorted(VALID_STATUSES)}")
    assert db._conn is not None
    now = _now()
    await db._conn.execute(
        "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
        (status, now, case.id),
    )
    await db._conn.commit()
    case.status = status
    case.updated_at = datetime.fromisoformat(now)


async def _timeline_impl(db: Database, case: Case) -> list[dict[str, Any]]:
    """Interleaved (run, note) events ordered chronologically."""
    assert db._conn is not None
    out: list[dict[str, Any]] = []
    async with db._conn.execute(
        """SELECT r.id, r.query_id, r.started_at, r.finished_at,
                  r.profile, r.agent_used,
                  q.kind, q.value,
                  (SELECT COUNT(*) FROM hits h WHERE h.query_id = r.query_id) AS hits,
                  (SELECT COUNT(*) FROM hits h WHERE h.query_id = r.query_id
                    AND h.status = 'found') AS found
           FROM case_runs r
           JOIN queries q ON q.id = r.query_id
           WHERE r.case_id = ?
           ORDER BY r.started_at ASC""",
        (case.id,),
    ) as cur:
        for r in await cur.fetchall():
            row = dict(r)
            out.append({
                "type": "run",
                "ts": row["started_at"],
                "run_id": row["id"],
                "query_id": row["query_id"],
                "kind": row["kind"],
                "target": row["value"],
                "profile": row["profile"],
                "agent_used": bool(row["agent_used"]),
                "hits": int(row["hits"] or 0),
                "found": int(row["found"] or 0),
                "finished_at": row["finished_at"],
            })
    async with db._conn.execute(
        "SELECT id, ts, body FROM case_notes WHERE case_id = ? ORDER BY ts ASC",
        (case.id,),
    ) as cur:
        for r in await cur.fetchall():
            row = dict(r)
            out.append({
                "type": "note",
                "ts": row["ts"],
                "note_id": row["id"],
                "body": row["body"],
            })
    out.sort(key=lambda e: e["ts"])
    return out


async def _attach_run_impl(
    db: Database,
    case: Case,
    query_result: QueryResult,
    profile: str,
    agent_used: bool,
) -> int:
    """Save the QueryResult, derive entities, link both into this case.

    Returns the ``case_runs.id`` row id (not the underlying query_id).
    """
    assert db._conn is not None
    qid = await db.save_result(query_result)
    try:
        await db.correlate_query(qid)
    except Exception as exc:
        # Correlation failure must not lose the run row — log + continue.
        log.warning("case[%s]: correlate failed for q=%s: %s", case.slug, qid, exc)

    started = (
        query_result.query.started_at.isoformat()
        if query_result.query.started_at
        else _now()
    )
    finished = (
        query_result.finished_at.isoformat() if query_result.finished_at else None
    )
    cur = await db._conn.execute(
        """INSERT INTO case_runs
           (case_id, query_id, started_at, finished_at, profile, agent_used)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (case.id, qid, started, finished, (profile or "").strip(), 1 if agent_used else 0),
    )
    run_id = cur.lastrowid or 0

    # Ingest the entity ids this query produced into case_entities. We pull
    # them from the edges table — that's the same source of truth pivot uses,
    # and it gives us the discovered union (everything derived as an edge).
    async with db._conn.execute(
        """SELECT DISTINCT e.id FROM entities e
           JOIN edges ed ON ed.dst_id = e.id OR ed.src_id = e.id
           WHERE ed.hit_id IN (SELECT id FROM hits WHERE query_id = ?)""",
        (qid,),
    ) as ecur:
        ent_ids = {r["id"] for r in await ecur.fetchall()}

    # The edge-join misses root-only entities: some derivers emit the query
    # root with NO edges (e.g. internetdb against a non-IP, or the generic
    # fallback when no sub-entity is extractable). correlate_query still
    # upsert()s that root into `entities`, so link it directly here — but only
    # if it actually exists (it won't for PASSWORD queries, which have no root
    # entity, or when no FOUND hit produced one).
    root_id = _root_entity_id(query_result)
    if root_id is not None:
        async with db._conn.execute(
            "SELECT 1 FROM entities WHERE id = ? LIMIT 1", (root_id,)
        ) as rcur:
            if await rcur.fetchone() is not None:
                ent_ids.add(root_id)

    if ent_ids:
        now = _now()
        await db._conn.executemany(
            """INSERT OR IGNORE INTO case_entities (case_id, entity_id, first_seen)
               VALUES (?, ?, ?)""",
            [(case.id, eid, now) for eid in sorted(ent_ids)],
        )

    await db._conn.execute(
        "UPDATE cases SET updated_at = ? WHERE id = ?", (_now(), case.id)
    )
    await db._conn.commit()
    case.updated_at = datetime.now(UTC)
    return run_id


async def _resume_impl(db: Database, case: Case) -> ResumeContext:
    """Build a snapshot of the case's last action for an analyst/agent to continue."""
    assert db._conn is not None
    last_qid: int | None = None
    last_kind = case.kind
    last_target = case.target
    last_profile = ""
    last_agent = False
    async with db._conn.execute(
        """SELECT r.query_id, r.profile, r.agent_used, q.kind, q.value
           FROM case_runs r
           JOIN queries q ON q.id = r.query_id
           WHERE r.case_id = ?
           ORDER BY r.started_at DESC LIMIT 1""",
        (case.id,),
    ) as cur:
        row = await cur.fetchone()
    if row:
        d = dict(row)
        last_qid = int(d["query_id"])
        last_kind = str(d["kind"])
        last_target = str(d["value"])
        last_profile = str(d["profile"] or "")
        last_agent = bool(d["agent_used"])

    async with db._conn.execute(
        """SELECT COUNT(*) AS n FROM case_entities WHERE case_id = ?""",
        (case.id,),
    ) as cur:
        count_row = await cur.fetchone()
        n = count_row["n"] if count_row else 0

    # Cheap snapshot of entities from the latest run (cap 50 — analyst preview).
    last_ents: list[dict[str, Any]] = []
    if last_qid is not None:
        async with db._conn.execute(
            """SELECT DISTINCT e.id, e.type, e.value
               FROM entities e
               JOIN edges ed ON ed.dst_id = e.id OR ed.src_id = e.id
               WHERE ed.hit_id IN (SELECT id FROM hits WHERE query_id = ?)
               LIMIT 50""",
            (last_qid,),
        ) as cur:
            last_ents = [dict(r) for r in await cur.fetchall()]

    return ResumeContext(
        case_slug=case.slug,
        last_query_id=last_qid,
        last_kind=last_kind,
        last_target=last_target,
        last_profile=last_profile,
        last_agent_used=last_agent,
        seed_kind=case.kind,
        seed_target=case.target,
        entity_count=int(n or 0),
        last_entities=last_ents,
    )


# Patch Case classmethods to dispatch to module-level async impls. The
# `@classmethod` signatures above are placeholders so type-checkers see the
# right shape; the actual callable is the async function below.
Case.new = staticmethod(new)            # type: ignore[assignment]
Case.get = staticmethod(get)            # type: ignore[assignment]
Case.list = staticmethod(list_cases)    # type: ignore[assignment]
