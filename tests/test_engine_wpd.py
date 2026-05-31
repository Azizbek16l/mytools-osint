"""WP-D engine + correctness regression tests.

Covers:
  * ransomware.live apex match — exact registrable-domain equality, not the
    old naive substring (no false-positive CRITICAL victim hits).
  * the agent ACTION parser — multi-line / pretty-printed JSON and JSON with
    trailing prose must parse (first balanced object).
  * cases attach_run — root-only entities (no edge) get linked.
  * cross_kind direction qualifier — `end: src` excludes high-fanout dst.
  * runner per-run module scope override — overlapping scans don't corrupt
    each other's selection.

Offline + hermetic: no network, no LLM, isolated tmp_path SQLite.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.db import Database
from app.core.entities import Edge, EdgeType, Entity, EntityType, entity_id
from app.core.types import Hit, HitStatus, Query, QueryKind, QueryResult, Severity
from app.features import cases as cases_mod
from app.features.agent import _first_json_object, _parse_step
from app.features.correlation import Rule, run_rules
from app.modules.leaks import _host_apexes

# --------------------------------------------------------------------------- #
# ransomware.live apex match (app/modules/leaks.py)
# --------------------------------------------------------------------------- #


def test_ransomware_apex_exact_match_only():
    """`acme.io` must match only records whose apex IS acme.io — not
    `notacme.io`, not `acme.io.evil.com`, not a `realacme.io` mention."""
    apex = "acme.io"
    # True positive — exact apex appears as a token / url.
    assert apex in _host_apexes("acme.io leaked database for sale")
    assert apex in _host_apexes("https://acme.io/dump")
    assert apex in _host_apexes("victim: ACME.IO")  # case-insensitive
    # subdomain of the apex still resolves to the apex.
    assert apex in _host_apexes("mail.acme.io was breached")

    # False positives the old substring match produced — must NOT match now.
    assert apex not in _host_apexes("notacme.io")
    assert apex not in _host_apexes("acme.io.evil.com")
    assert apex not in _host_apexes("realacme.io competitor")
    assert apex not in _host_apexes("acmecorp.com")


def test_ransomware_apex_handles_empty_and_garbage():
    assert _host_apexes("") == set()
    assert _host_apexes("   ") == set()
    assert _host_apexes("no-host-here") == set()


# --------------------------------------------------------------------------- #
# agent ACTION parser (app/features/agent.py)
# --------------------------------------------------------------------------- #


def test_action_parser_single_line():
    kind, name, args, _ = _parse_step('ACTION: {"tool": "scan", "args": {"profile": "quick"}}')
    assert kind == "action"
    assert name == "scan"
    assert args == {"profile": "quick"}


def test_action_parser_pretty_printed_multiline():
    """Pretty-printed JSON (the common qwen2.5:3b output) used to stop at the
    inner `}` of args and fail json.loads. The balanced scan fixes it."""
    reply = (
        "THOUGHT: I will scan.\n"
        "ACTION: {\n"
        '  "tool": "scan",\n'
        '  "args": {\n'
        '    "profile": "deep"\n'
        "  }\n"
        "}\n"
    )
    kind, name, args, _ = _parse_step(reply)
    assert kind == "action"
    assert name == "scan"
    assert args == {"profile": "deep"}


def test_action_parser_trailing_prose():
    """Trailing text after the JSON object must not break the match."""
    reply = 'ACTION: {"tool": "finalize", "args": {"summary": "done"}}  // wrap up'
    kind, name, args, _ = _parse_step(reply)
    assert kind == "action"
    assert name == "finalize"
    assert args == {"summary": "done"}


def test_action_parser_braces_inside_strings():
    """A `}` inside a string literal must not be treated as the closing brace."""
    obj, _ = _first_json_object('{"tool": "scan", "args": {"note": "a } brace"}}')
    assert obj == {"tool": "scan", "args": {"note": "a } brace"}}


def test_action_parser_answer_wins_over_action():
    kind, text, _, _ = _parse_step("ANSWER: verdict is benign")
    assert kind == "answer"
    assert text == "verdict is benign"


# --------------------------------------------------------------------------- #
# cases attach_run — root-only entity linking (app/features/cases.py)
# --------------------------------------------------------------------------- #


@pytest.fixture
async def db(tmp_path):
    db = Database(tmp_path / "wpd.sqlite3")
    await db.connect()
    yield db
    await db.close()


def _root_only_result() -> QueryResult:
    """A FOUND hit from a module with NO custom deriver and NO extractable
    sub-entity → _fallback_derive returns ([root], []): the root entity is
    upserted but has no edge, so the old edge-join missed it entirely.
    """
    q = Query(kind=QueryKind.USERNAME, value="solo_handle")
    hits = [
        Hit(module="telegram", source="solo_handle", category="messaging",
            status=HitStatus.FOUND, title="solo_handle", severity=Severity.LOW),
    ]
    return QueryResult(query=q, hits=hits,
                       finished_at=datetime.now(UTC), duration_ms=10)


async def test_attach_run_links_root_only_entity(db):
    c = await cases_mod.new(db, "root-only", kind="username", target="solo_handle")
    await c.attach_run(db, _root_only_result(), profile="quick")

    assert db._conn is not None
    # The root USERNAME entity must be linked even though it has no edge.
    async with db._conn.execute(
        "SELECT COUNT(*) AS n FROM case_entities WHERE case_id = ?", (c.id,),
    ) as cur:
        n = (await cur.fetchone())["n"]
    assert n >= 1, "root-only entity was not linked into case_entities"

    # And it is the username root specifically.
    root_id = entity_id(EntityType.USERNAME, "solo_handle")
    async with db._conn.execute(
        "SELECT 1 FROM case_entities WHERE case_id = ? AND entity_id = ?",
        (c.id, root_id),
    ) as cur:
        assert await cur.fetchone() is not None


async def test_attach_run_root_link_idempotent(db):
    c = await cases_mod.new(db, "root-idem", kind="username", target="solo_handle")
    await c.attach_run(db, _root_only_result(), profile="quick")
    await c.attach_run(db, _root_only_result(), profile="quick")
    assert db._conn is not None
    async with db._conn.execute(
        "SELECT entity_id, COUNT(*) AS n FROM case_entities "
        "WHERE case_id = ? GROUP BY entity_id",
        (c.id,),
    ) as cur:
        rows = await cur.fetchall()
    assert rows, "expected at least the root entity"
    assert all(int(r["n"]) == 1 for r in rows)


# --------------------------------------------------------------------------- #
# cross_kind direction qualifier (app/features/correlation.py)
# --------------------------------------------------------------------------- #


async def _add_entity(db: Database, type_: EntityType, value: str) -> Entity:
    e = Entity(type=type_, value=value,
               first_seen=datetime.now(UTC), last_seen=datetime.now(UTC))
    await db.entity_upsert(e)
    return e


async def _add_edge(db: Database, src: Entity, dst: Entity, rel: EdgeType) -> None:
    await db.edge_upsert(Edge(
        src_id=src.id, dst_id=dst.id, type=rel,
        first_seen=datetime.now(UTC), last_seen=datetime.now(UTC),
        source="test",
    ))


async def _seed_cross_kind_graph(db: Database) -> None:
    """apex.example is the DST of mx_for (it's the domain, not the mail host)
    and the SRC of resolves_to. Direction-agnostic matching wrongly flags it.
    """
    apex = await _add_entity(db, EntityType.DOMAIN, "apex.example")
    mail = await _add_entity(db, EntityType.DOMAIN, "mail.provider.example")
    ip = await _add_entity(db, EntityType.IP, "1.2.3.4")
    await _add_edge(db, mail, apex, EdgeType.MX_FOR)        # apex is dst
    await _add_edge(db, apex, ip, EdgeType.RESOLVES_TO)     # apex is src


async def test_cross_kind_direction_agnostic_back_compat(db):
    """Bare string rels keep the historical (direction-agnostic) behaviour —
    apex.example qualifies because it touches both relations on some end."""
    await _seed_cross_kind_graph(db)
    rule = Rule.from_dict({
        "id": "ck-loose", "severity": "high",
        "match": {"cross_kind": {"rels": ["mx_for", "resolves_to"]}},
        "output": {"title": "both: {value}"},
    })
    hits = await run_rules(db, rules=[rule])
    values = {h.extra["evidence"]["value"] for h in hits}
    assert "apex.example" in values


async def test_cross_kind_direction_qualifier_excludes_false_positive(db):
    """With `end: src` on both rels, apex.example no longer qualifies: it is
    the SRC of resolves_to but only the DST of mx_for."""
    await _seed_cross_kind_graph(db)
    rule = Rule.from_dict({
        "id": "ck-strict", "severity": "high",
        "match": {"cross_kind": {"rels": [
            {"rel": "mx_for", "end": "src"},
            {"rel": "resolves_to", "end": "src"},
        ]}},
        "output": {"title": "both: {value}"},
    })
    hits = await run_rules(db, rules=[rule])
    values = {h.extra["evidence"]["value"] for h in hits}
    assert "apex.example" not in values


# --------------------------------------------------------------------------- #
# runner per-run module scope override (app/core/runner.py)
# --------------------------------------------------------------------------- #


async def test_runner_per_run_module_override():
    from collections.abc import AsyncIterator

    from app.core.runner import Runner

    r = Runner()

    def _mk(name: str):
        async def producer(_q: Query) -> AsyncIterator[Hit]:
            yield Hit(module=name, source=name, status=HitStatus.FOUND,
                      severity=Severity.INFO)
        return producer

    r.register("alpha", [QueryKind.DOMAIN], _mk("alpha"))
    r.register("beta", [QueryKind.DOMAIN], _mk("beta"))

    q = Query(kind=QueryKind.DOMAIN, value="x.example")

    # Per-run override: only alpha runs, regardless of the global enabled flag.
    res = await r.run(q, modules=frozenset({"alpha"}))
    assert {h.module for h in res.hits} == {"alpha"}

    # A concurrent run with a different scope is independent — beta only.
    res2 = await r.run(q, modules=frozenset({"beta"}))
    assert {h.module for h in res2.hits} == {"beta"}

    # No override → global enabled default (both run).
    res3 = await r.run(q)
    assert {h.module for h in res3.hits} == {"alpha", "beta"}
