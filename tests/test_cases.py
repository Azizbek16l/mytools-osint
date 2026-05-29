"""Wave D1 — cases lifecycle.

Offline only. Uses an isolated tmp_path SQLite per test.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.db import Database
from app.core.types import Hit, HitStatus, Query, QueryKind, QueryResult, Severity
from app.features import cases as cases_mod


@pytest.fixture
async def db(tmp_path):
    db = Database(tmp_path / "cases.sqlite3")
    await db.connect()
    yield db
    await db.close()


def _result(target: str) -> QueryResult:
    q = Query(kind=QueryKind.DOMAIN, value=target)
    hits = [
        Hit(module="domain", source=f"sub1.{target}", category="dns",
            status=HitStatus.FOUND, title=f"sub1.{target}",
            severity=Severity.MEDIUM, url=f"https://sub1.{target}"),
        Hit(module="domain", source=f"sub2.{target}", category="dns",
            status=HitStatus.FOUND, title=f"sub2.{target}",
            severity=Severity.LOW),
        Hit(module="internetdb", source="shodan", status=HitStatus.NOT_FOUND),
    ]
    return QueryResult(query=q, hits=hits,
                       finished_at=datetime.now(UTC), duration_ms=42)


# -------- slug validation ---------------------------------------------------


def test_validate_slug_accepts_basic_forms():
    assert cases_mod.validate_slug("acme-2026") == "acme-2026"
    assert cases_mod.validate_slug("Phish_01") == "phish_01"
    assert cases_mod.validate_slug("   Mixed-Case_2  ") == "mixed-case_2"


def test_validate_slug_rejects_bad_input():
    for bad in ("", "  ", "a", "-leading", "_x", "Has Spaces", "x" * 65,
                "café", "/slash"):
        with pytest.raises(ValueError):
            cases_mod.validate_slug(bad)


# -------- CRUD --------------------------------------------------------------


@pytest.mark.asyncio
async def test_new_and_get(db):
    c = await cases_mod.new(db, "acme-2026", name="ACME phish",
                            kind="domain", target="acme.example")
    assert c.id > 0
    assert c.slug == "acme-2026"
    assert c.status == "open"
    assert c.kind == "domain"
    assert c.target == "acme.example"

    got = await cases_mod.get(db, "acme-2026")
    assert got is not None
    assert got.id == c.id
    assert got.name == "ACME phish"

    assert await cases_mod.get(db, "ghost") is None
    assert await cases_mod.get(db, "BAD SLUG") is None  # slug invalid → None


@pytest.mark.asyncio
async def test_list_filters_by_status(db):
    a = await cases_mod.new(db, "alpha")
    b = await cases_mod.new(db, "beta")
    await b.set_status(db, "closed")
    open_ = await cases_mod.list_cases(db, status="open")
    closed = await cases_mod.list_cases(db, status="closed")
    all_ = await cases_mod.list_cases(db, status="all")
    assert {c.slug for c in open_} == {"alpha"}
    assert {c.slug for c in closed} == {"beta"}
    assert {c.slug for c in all_} == {"alpha", "beta"}
    with pytest.raises(ValueError):
        await cases_mod.list_cases(db, status="weird")
    # silence ruff "assigned but never used"
    assert a.slug == "alpha"


@pytest.mark.asyncio
async def test_add_note_and_timeline(db):
    c = await cases_mod.new(db, "obs")
    with pytest.raises(ValueError):
        await c.add_note(db, "   ")
    n1 = await c.add_note(db, "starting triage")
    n2 = await c.add_note(db, "found suspicious cert")
    assert n2 > n1
    tl = await c.timeline(db)
    assert [e["type"] for e in tl] == ["note", "note"]
    assert [e["body"] for e in tl] == ["starting triage", "found suspicious cert"]


@pytest.mark.asyncio
async def test_set_status_validates(db):
    c = await cases_mod.new(db, "checkstat")
    with pytest.raises(ValueError):
        await c.set_status(db, "archived")
    await c.set_status(db, "closed")
    assert c.status == "closed"


@pytest.mark.asyncio
async def test_new_rejects_bad_slug(db):
    with pytest.raises(ValueError):
        await cases_mod.new(db, "Has Spaces")


@pytest.mark.asyncio
async def test_duplicate_slug_raises(db):
    import sqlite3
    await cases_mod.new(db, "dup")
    with pytest.raises(sqlite3.IntegrityError):
        await cases_mod.new(db, "dup")


# -------- attach_run / resume ----------------------------------------------


@pytest.mark.asyncio
async def test_attach_run_links_query_and_entities(db):
    c = await cases_mod.new(db, "attach-test",
                            kind="domain", target="acme.example")
    qr = _result("acme.example")
    run_id = await c.attach_run(db, qr, profile="domain-recon")
    assert run_id > 0

    tl = await c.timeline(db)
    runs = [e for e in tl if e["type"] == "run"]
    assert len(runs) == 1
    assert runs[0]["kind"] == "domain"
    assert runs[0]["target"] == "acme.example"
    assert runs[0]["profile"] == "domain-recon"
    assert runs[0]["found"] == 2
    assert runs[0]["agent_used"] is False

    # case_entities populated from derived graph
    assert db._conn is not None
    async with db._conn.execute(
        "SELECT COUNT(*) AS n FROM case_entities WHERE case_id = ?", (c.id,),
    ) as cur:
        n = (await cur.fetchone())["n"]
    # The two FOUND subdomain hits should derive at least the root + 2 subs.
    assert n >= 2


@pytest.mark.asyncio
async def test_attach_run_idempotent_entity_ingest(db):
    c = await cases_mod.new(db, "idem", kind="domain", target="acme.example")
    await c.attach_run(db, _result("acme.example"), profile="quick")
    await c.attach_run(db, _result("acme.example"), profile="quick")
    # No duplicates in case_entities (primary key enforces it)
    assert db._conn is not None
    async with db._conn.execute(
        "SELECT entity_id, COUNT(*) AS n FROM case_entities WHERE case_id = ? GROUP BY entity_id",
        (c.id,),
    ) as cur:
        rows = await cur.fetchall()
    assert all(int(r["n"]) == 1 for r in rows)


@pytest.mark.asyncio
async def test_resume_returns_last_action(db):
    c = await cases_mod.new(db, "resu", kind="domain", target="seed.example")
    rc0 = await c.resume(db)
    assert rc0.last_query_id is None
    assert rc0.seed_target == "seed.example"

    await c.attach_run(db, _result("seed.example"), profile="quick",
                       agent_used=True)
    rc1 = await c.resume(db)
    assert rc1.last_query_id is not None
    assert rc1.last_target == "seed.example"
    assert rc1.last_profile == "quick"
    assert rc1.last_agent_used is True
    assert rc1.entity_count >= 2


@pytest.mark.asyncio
async def test_remove_cascades(db):
    c = await cases_mod.new(db, "doomed")
    await c.add_note(db, "soon to be gone")
    await c.attach_run(db, _result("doomed.example"))
    ok = await cases_mod.remove(db, "doomed")
    assert ok is True
    assert db._conn is not None
    async with db._conn.execute("SELECT COUNT(*) AS n FROM cases") as cur:
        assert (await cur.fetchone())["n"] == 0
    async with db._conn.execute("SELECT COUNT(*) AS n FROM case_notes") as cur:
        assert (await cur.fetchone())["n"] == 0
    async with db._conn.execute("SELECT COUNT(*) AS n FROM case_runs") as cur:
        assert (await cur.fetchone())["n"] == 0
    async with db._conn.execute("SELECT COUNT(*) AS n FROM case_entities") as cur:
        assert (await cur.fetchone())["n"] == 0


@pytest.mark.asyncio
async def test_remove_nonexistent_returns_false(db):
    assert await cases_mod.remove(db, "neverwas") is False
    assert await cases_mod.remove(db, "BAD SLUG") is False
