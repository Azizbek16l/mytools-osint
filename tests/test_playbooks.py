"""Wave D3 — playbook DSL + execution.

The DSL must reject any expression outside the tiny whitelist. The runner
must use a stub runner (no real network) and step `when`/`target_from`
must drive execution.
"""
from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from app.core.db import Database
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity
from app.features.playbooks import (
    Playbook,
    Step,
    UnsafeExpression,
    _ExprCtx,
    eval_expr,
    load_playbooks,
    run_playbook,
)

# ---------------- DSL safety ------------------------------------------------


def test_eval_safe_simple_compare():
    ctx = _ExprCtx(kind="email", hits=[])
    assert eval_expr("kind == 'email'", ctx) is True
    assert eval_expr("kind == 'domain'", ctx) is False
    assert eval_expr("kind != 'email'", ctx) is False


def test_eval_severity_lexico_promoted_to_rank():
    ctx = _ExprCtx(kind="email", hits=[
        Hit(module="m", source="s", status=HitStatus.FOUND, severity=Severity.HIGH),
    ])
    assert eval_expr("any_severity >= 'medium'", ctx) is True
    assert eval_expr("any_severity >= 'critical'", ctx) is False
    assert eval_expr("any_severity == 'high'", ctx) is True


def test_eval_count_buckets():
    hits = [
        Hit(module="m", source="s", status=HitStatus.FOUND, severity=Severity.LOW),
        Hit(module="m", source="s", status=HitStatus.FOUND, severity=Severity.HIGH),
        Hit(module="m", source="s", status=HitStatus.ERROR),
    ]
    ctx = _ExprCtx(kind="domain", hits=hits)
    assert eval_expr("count('found') == 2", ctx) is True
    assert eval_expr("count('high') == 1", ctx) is True
    assert eval_expr("count('error') == 1", ctx) is True
    assert eval_expr("count('found') > 0", ctx) is True


def test_eval_hits_subscript():
    hits = [
        Hit(module="m", source="s", status=HitStatus.FOUND, url="https://a"),
    ]
    ctx = _ExprCtx(kind="domain", hits=hits)
    assert eval_expr("hits[0].url == 'https://a'", ctx) is True
    # out-of-range subscript returns None → comparison is False
    assert eval_expr("hits[5].url == 'x'", ctx) is False


def test_eval_empty_expr_is_true():
    ctx = _ExprCtx(kind="x", hits=[])
    assert eval_expr("", ctx) is True
    assert eval_expr("   ", ctx) is True


def test_eval_rejects_arbitrary_call():
    ctx = _ExprCtx(kind="x", hits=[])
    with pytest.raises(UnsafeExpression):
        eval_expr("len(kind)", ctx)
    with pytest.raises(UnsafeExpression):
        eval_expr("open('/etc/passwd')", ctx)


def test_eval_rejects_dunder_and_imports():
    ctx = _ExprCtx(kind="x", hits=[])
    with pytest.raises(UnsafeExpression):
        eval_expr("__import__('os')", ctx)
    with pytest.raises(UnsafeExpression):
        eval_expr("import os", ctx)


def test_eval_rejects_attribute_walk():
    ctx = _ExprCtx(kind="x", hits=[])
    with pytest.raises(UnsafeExpression):
        eval_expr("kind.upper()", ctx)
    with pytest.raises(UnsafeExpression):
        eval_expr("kind.real", ctx)


def test_eval_rejects_unknown_name():
    ctx = _ExprCtx(kind="x", hits=[])
    with pytest.raises(UnsafeExpression):
        eval_expr("secret == 'value'", ctx)


def test_eval_rejects_arithmetic():
    """Plain arithmetic is not in our DSL — keeps the surface tight."""
    ctx = _ExprCtx(kind="x", hits=[])
    with pytest.raises(UnsafeExpression):
        eval_expr("1 + 1 == 2", ctx)


def test_eval_rejects_unknown_count_bucket():
    ctx = _ExprCtx(kind="x", hits=[])
    with pytest.raises(UnsafeExpression):
        eval_expr("count('mystery') > 0", ctx)


def test_eval_rejects_non_int_subscript():
    ctx = _ExprCtx(kind="x", hits=[])
    with pytest.raises(UnsafeExpression):
        eval_expr("hits['x'].url == 'y'", ctx)


def test_eval_rejects_subscript_on_other_name():
    ctx = _ExprCtx(kind="x", hits=[])
    with pytest.raises(UnsafeExpression):
        eval_expr("kind[0] == 'x'", ctx)


# ---------------- Playbook.from_dict --------------------------------------


def test_playbook_minimal():
    pb = Playbook.from_dict({
        "id": "minimal",
        "steps": [{"id": "s1", "run": "quick"}],
    })
    assert pb.id == "minimal"
    assert pb.steps[0].id == "s1"


def test_playbook_rejects_duplicate_step_ids():
    with pytest.raises(ValueError):
        Playbook.from_dict({
            "id": "dup", "steps": [
                {"id": "x", "run": "quick"}, {"id": "x", "run": "deep"},
            ],
        })


def test_playbook_rejects_missing_run():
    with pytest.raises(ValueError):
        Playbook.from_dict({
            "id": "p", "steps": [{"id": "s1", "run": ""}],
        })


def test_playbook_rejects_empty_steps():
    with pytest.raises(ValueError):
        Playbook.from_dict({"id": "p", "steps": []})


def test_builtin_playbooks_load():
    pbs = {p.id: p for p in load_playbooks()}
    assert "phish-triage" in pbs
    assert "subdomain-deepdive" in pbs
    assert len(pbs["phish-triage"].steps) >= 3


# ---------------- run_playbook execution ----------------------------------


def _make_runner(hits_by_module: dict[str, list[Hit]]) -> Runner:
    """Runner with two fake modules — `quick_mod` and `deep_mod`. Each
    yields its mapped hit list whenever invoked for any QueryKind.
    """
    r = Runner()

    def _make_producer(name: str):
        async def producer(_q: Query) -> AsyncIterator[Hit]:
            for h in hits_by_module.get(name, []):
                yield h
        return producer

    for name in hits_by_module:
        r.register(name, list(QueryKind), _make_producer(name))
    return r


@pytest.fixture
async def db(tmp_path):
    db = Database(tmp_path / "pb.sqlite3")
    await db.connect()
    yield db
    await db.close()


@pytest.mark.asyncio
async def test_run_playbook_skips_unknown_module(db):
    """An unknown step name fails cleanly without breaking the run."""
    pb = Playbook(id="t", name="t", steps=[
        Step(id="s1", run="ghost-module"),
    ])
    runner = _make_runner({"real-module": [
        Hit(module="m", source="x", status=HitStatus.FOUND),
    ]})
    pr = await run_playbook(db, pb, "acme.example",
                            kind=QueryKind.DOMAIN, runner=runner)
    assert pr.steps[0].skipped is True
    assert "unknown" in pr.steps[0].skipped_reason


@pytest.mark.asyncio
async def test_run_playbook_when_skip(db):
    """when=false skips the step entirely."""
    pb = Playbook(id="t", name="t", steps=[
        Step(id="never", run="modA", when="kind == 'email'"),
        Step(id="always", run="modA"),
    ])
    runner = _make_runner({"modA": [
        Hit(module="modA", source="x", status=HitStatus.FOUND,
            severity=Severity.LOW),
    ]})
    pr = await run_playbook(db, pb, "acme.example",
                            kind=QueryKind.DOMAIN, runner=runner)
    assert pr.steps[0].skipped is True
    assert pr.steps[1].skipped is False
    assert pr.steps[1].result is not None
    assert pr.steps[1].result.found == 1


@pytest.mark.asyncio
async def test_run_playbook_unsafe_when_marks_skipped(db):
    pb = Playbook(id="t", name="t", steps=[
        Step(id="bad", run="modA", when="__import__('os')"),
    ])
    runner = _make_runner({"modA": []})
    pr = await run_playbook(db, pb, "x",
                            kind=QueryKind.DOMAIN, runner=runner)
    assert pr.steps[0].skipped is True
    assert "unsafe" in pr.steps[0].skipped_reason


@pytest.mark.asyncio
async def test_run_playbook_target_from(db):
    """The second step's target_from picks the first step's hit url."""
    pb = Playbook(id="t", name="t", steps=[
        Step(id="first", run="modA"),
        Step(id="second", run="modA",
             when="count('found') > 0",
             target_from="hits[0].url"),
    ])
    runner = _make_runner({"modA": [
        Hit(module="modA", source="x", status=HitStatus.FOUND,
            url="example.org"),
    ]})
    pr = await run_playbook(db, pb, "first.example",
                            kind=QueryKind.DOMAIN, runner=runner)
    assert all(not s.skipped for s in pr.steps)
    # First step ran against the original target, second against the url
    assert pr.steps[0].result.query.value == "first.example"
    assert pr.steps[1].result.query.value == "example.org"


@pytest.mark.asyncio
async def test_run_playbook_skips_when_target_from_empty(db):
    pb = Playbook(id="t", name="t", steps=[
        Step(id="first", run="modA"),
        Step(id="second", run="modA",
             target_from="hits[0].url"),
    ])
    runner = _make_runner({"modA": [
        # url is empty
        Hit(module="modA", source="x", status=HitStatus.FOUND, url=""),
    ]})
    pr = await run_playbook(db, pb, "acme.example",
                            kind=QueryKind.DOMAIN, runner=runner)
    assert pr.steps[0].skipped is False
    assert pr.steps[1].skipped is True
    assert "target_from empty" in pr.steps[1].skipped_reason


@pytest.mark.asyncio
async def test_run_playbook_agent_stub_called(db):
    """`run: agent` invokes the supplied agent_runner."""
    pb = Playbook(id="t", name="t", steps=[
        Step(id="ai", run="agent"),
    ])
    runner = _make_runner({})

    called = {}

    async def stub_agent(q: Query):
        called["q"] = q
        from app.core.types import QueryResult
        return QueryResult(query=q, hits=[
            Hit(module="agent", source="ai", status=HitStatus.FOUND,
                severity=Severity.MEDIUM),
        ])

    pr = await run_playbook(db, pb, "tgt.example",
                            kind=QueryKind.DOMAIN, runner=runner,
                            agent_runner=stub_agent)
    assert called["q"].value == "tgt.example"
    assert pr.steps[0].skipped is False
    assert pr.steps[0].result.found == 1
