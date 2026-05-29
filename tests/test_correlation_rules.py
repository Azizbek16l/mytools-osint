"""Wave D2 — correlation rules engine.

Exercises Rule loading + each of the 4 builtin rules with hand-crafted
entities/edges. We bypass module derivation by directly upserting via the
DB DAO methods — keeps the tests offline and deterministic.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.db import Database
from app.core.entities import Edge, EdgeType, Entity, EntityType
from app.features.correlation import (
    _BUILTIN_DIR,
    Rule,
    load_rules,
    run_rules,
)


@pytest.fixture
async def db(tmp_path):
    db = Database(tmp_path / "rules.sqlite3")
    await db.connect()
    yield db
    await db.close()


# ---------------- helpers --------------------------------------------------


async def _add_entity(db: Database, type_: EntityType, value: str,
                      tags: list[str] | None = None) -> Entity:
    e = Entity(type=type_, value=value, tags=list(tags or []),
               first_seen=datetime.now(UTC), last_seen=datetime.now(UTC))
    await db.entity_upsert(e)
    return e


async def _add_edge(db: Database, src: Entity, dst: Entity, rel: EdgeType) -> None:
    await db.edge_upsert(Edge(
        src_id=src.id, dst_id=dst.id, type=rel,
        first_seen=datetime.now(UTC), last_seen=datetime.now(UTC),
        source="test",
    ))


# ---------------- Rule.from_dict ------------------------------------------


def test_rule_loads_minimal_valid():
    r = Rule.from_dict({
        "id": "xy", "name": "Y", "severity": "medium",
        "match": {"entities": {"type": "ip"}},
    })
    assert r.id == "xy"
    assert r.severity == "medium"


def test_rule_rejects_missing_id():
    with pytest.raises(ValueError):
        Rule.from_dict({"name": "x", "severity": "info", "match": {"entities": {"type": "ip"}}})


def test_rule_rejects_bad_severity():
    with pytest.raises(ValueError):
        Rule.from_dict({"id": "xy", "severity": "extreme",
                        "match": {"entities": {"type": "ip"}}})


def test_rule_rejects_unknown_match_predicate():
    with pytest.raises(ValueError):
        Rule.from_dict({"id": "xy", "severity": "low",
                        "match": {"by_color": {"type": "ip"}}})


def test_rule_rejects_empty_match():
    with pytest.raises(ValueError):
        Rule.from_dict({"id": "xy", "severity": "low", "match": {}})


def test_rule_rejects_bad_id_chars():
    with pytest.raises(ValueError):
        Rule.from_dict({"id": "BAD ID", "severity": "low",
                        "match": {"entities": {"type": "ip"}}})


# ---------------- load_rules + builtins ------------------------------------


def test_builtin_rules_load_and_parse():
    """Every shipped builtin YAML must load cleanly with the right ids."""
    rules = load_rules()
    ids = {r.id for r in rules}
    assert {"shared-ip", "password-reuse", "dangling-cname-takeover",
            "exposed-admin"} <= ids


def test_load_rules_skips_user_dir_if_missing(tmp_path):
    rules = load_rules(builtins=False, user_dir=tmp_path / "nope")
    assert rules == []


def test_load_rules_user_overrides_builtin(tmp_path):
    """A user file with the same id as a builtin wins."""
    custom = tmp_path / "custom.yaml"
    custom.write_text(
        "id: shared-ip\nname: My override\nseverity: low\n"
        "match:\n  entities:\n    type: ip\n",
        encoding="utf-8",
    )
    rules = {r.id: r for r in load_rules(user_dir=tmp_path)}
    assert rules["shared-ip"].name == "My override"
    assert rules["shared-ip"].severity == "low"


def test_load_rules_skips_malformed_files(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: 'has space'\nseverity: nope\nmatch: {}\n", encoding="utf-8")
    rules = load_rules(builtins=False, user_dir=tmp_path)
    assert rules == []
    assert _BUILTIN_DIR.exists()


# ---------------- shared-ip rule ------------------------------------------


@pytest.mark.asyncio
async def test_rule_shared_ip_matches(db):
    """Three subdomains resolving to the same IP → one finding."""
    ip_entity = await _add_entity(db, EntityType.IP, "203.0.113.7")
    for n in ("a", "b", "c"):
        sub = await _add_entity(db, EntityType.SUBDOMAIN, f"{n}.acme.example")
        await _add_edge(db, sub, ip_entity, EdgeType.RESOLVES_TO)
    rules = [r for r in load_rules() if r.id == "shared-ip"]
    hits = await run_rules(db, rules=rules)
    assert len(hits) == 1
    h = hits[0]
    assert h.severity.value == "medium"
    assert h.source == "shared-ip"
    assert "subdomains" in h.extra["evidence"]
    assert len(h.extra["evidence"]["subdomains"]) == 3


@pytest.mark.asyncio
async def test_rule_shared_ip_skips_below_threshold(db):
    """Two subdomains is below min_group_size=3 → no finding."""
    ip_entity = await _add_entity(db, EntityType.IP, "203.0.113.7")
    for n in ("a", "b"):
        sub = await _add_entity(db, EntityType.SUBDOMAIN, f"{n}.acme.example")
        await _add_edge(db, sub, ip_entity, EdgeType.RESOLVES_TO)
    rules = [r for r in load_rules() if r.id == "shared-ip"]
    hits = await run_rules(db, rules=rules)
    assert hits == []


# ---------------- exposed-admin rule --------------------------------------


@pytest.mark.asyncio
async def test_rule_exposed_admin_value_regex(db):
    await _add_entity(db, EntityType.SUBDOMAIN, "admin.acme.example")
    await _add_entity(db, EntityType.SUBDOMAIN, "www.acme.example")
    await _add_entity(db, EntityType.SUBDOMAIN, "login.acme.example")
    rules = [r for r in load_rules() if r.id == "exposed-admin"]
    hits = await run_rules(db, rules=rules)
    values = sorted(h.extra["evidence"]["subdomain"] for h in hits)
    assert values == ["admin.acme.example", "login.acme.example"]


# ---------------- dangling-cname-takeover --------------------------------


@pytest.mark.asyncio
async def test_rule_dangling_cname_takeover(db):
    sub = await _add_entity(db, EntityType.SUBDOMAIN, "promo.acme.example")
    root = await _add_entity(db, EntityType.DOMAIN, "acme.example")
    await _add_edge(db, sub, root, EdgeType.TAKEOVER_CANDIDATE)
    rules = [r for r in load_rules() if r.id == "dangling-cname-takeover"]
    hits = await run_rules(db, rules=rules)
    assert len(hits) == 1
    assert hits[0].severity.value == "high"
    assert hits[0].extra["evidence"]["subdomain"] == "promo.acme.example"


# ---------------- password-reuse ------------------------------------------


@pytest.mark.asyncio
async def test_rule_password_reuse_across_emails(db):
    """Two emails sharing a HASH entity via SEEN_IN_BREACH → one finding."""
    e1 = await _add_entity(db, EntityType.EMAIL, "alice@example.com")
    e2 = await _add_entity(db, EntityType.EMAIL, "bob@example.com")
    h = await _add_entity(db, EntityType.HASH, "deadbeef" * 8)
    await _add_edge(db, e1, h, EdgeType.SEEN_IN_BREACH)
    await _add_edge(db, e2, h, EdgeType.SEEN_IN_BREACH)
    rules = [r for r in load_rules() if r.id == "password-reuse"]
    hits = await run_rules(db, rules=rules)
    assert len(hits) == 1
    assert hits[0].severity.value == "high"
    assert sorted(hits[0].extra["evidence"]["emails"]) == [
        "alice@example.com", "bob@example.com",
    ]


@pytest.mark.asyncio
async def test_rule_password_reuse_skips_single_email(db):
    e1 = await _add_entity(db, EntityType.EMAIL, "lone@example.com")
    h = await _add_entity(db, EntityType.HASH, "cafef00d" * 8)
    await _add_edge(db, e1, h, EdgeType.SEEN_IN_BREACH)
    rules = [r for r in load_rules() if r.id == "password-reuse"]
    hits = await run_rules(db, rules=rules)
    assert hits == []


# ---------------- case_id scoping -----------------------------------------


@pytest.mark.asyncio
async def test_rules_scoped_to_case(db):
    """When case_id is given, only entities in case_entities should match."""
    from app.features import cases as cases_mod

    # Two cases each with one admin subdomain; only one is attached to caseA.
    a = await _add_entity(db, EntityType.SUBDOMAIN, "admin.in.example")
    await _add_entity(db, EntityType.SUBDOMAIN, "admin.out.example")
    case_a = await cases_mod.new(db, "case-a")
    case_b = await cases_mod.new(db, "case-b")
    assert db._conn is not None
    await db._conn.execute(
        "INSERT INTO case_entities (case_id, entity_id, first_seen) VALUES (?, ?, ?)",
        (case_a.id, a.id, datetime.now(UTC).isoformat()),
    )
    await db._conn.commit()
    rules = [r for r in load_rules() if r.id == "exposed-admin"]
    hits_a = await run_rules(db, case_id=case_a.id, rules=rules)
    hits_b = await run_rules(db, case_id=case_b.id, rules=rules)
    hits_all = await run_rules(db, rules=rules)
    assert len(hits_a) == 1
    assert hits_a[0].extra["evidence"]["subdomain"] == "admin.in.example"
    assert hits_b == []
    assert len(hits_all) == 2


# ---------------- cross_kind rule -----------------------------------------


@pytest.mark.asyncio
async def test_cross_kind_match(db):
    """Custom rule: entity has both MX_FOR and RESOLVES_TO."""
    rule = Rule.from_dict({
        "id": "mx-and-a",
        "name": "Same host is MX and A record",
        "severity": "low",
        "match": {"cross_kind": {"rels": ["mx_for", "resolves_to"]}},
    })
    ip = await _add_entity(db, EntityType.IP, "198.51.100.4")
    apex = await _add_entity(db, EntityType.DOMAIN, "ex.example")
    sub = await _add_entity(db, EntityType.SUBDOMAIN, "alt.ex.example")
    await _add_edge(db, ip, apex, EdgeType.MX_FOR)
    await _add_edge(db, sub, ip, EdgeType.RESOLVES_TO)
    hits = await run_rules(db, rules=[rule])
    assert len(hits) >= 1
    assert any(h.extra["evidence"]["value"] == "198.51.100.4" for h in hits)
