"""Wave B — ReAct agent loop.

Hermetic: every test injects a ``FakeProvider`` (scripted replies) and either
a fake ``Runner`` or the real registered one. No network, no model files, no
processes spawned.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest

from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity
from app.features.agent import (
    AGENT_STATE,
    AgentLoop,
    cmd_agent,
)
from app.features.ai import LLMUnavailable

# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #

class FakeProvider:
    """Scripted LLM. ``replies`` is consumed in order; ``raise_after`` lets a
    test drive the provider into LLMUnavailable mid-loop."""

    name = "fake"

    def __init__(self, replies: list[str], *, raise_after: int | None = None) -> None:
        self._replies = list(replies)
        self._raise_after = raise_after
        self.calls: list[list[dict[str, str]]] = []

    def available(self) -> bool:
        return True

    async def stream(self, messages, *, max_tokens=800, on_token=None):
        self.calls.append(list(messages))
        if self._raise_after is not None and len(self.calls) > self._raise_after:
            raise LLMUnavailable("fake exhausted")
        if not self._replies:
            return ""
        return self._replies.pop(0)


def _fake_runner_with(hits: list[Hit]) -> Runner:
    """Build a Runner with one module yielding ``hits`` for any query.

    We register under the name ``internetdb`` because that name is in every
    real profile preset — so when the agent's ``scan`` action calls
    ``apply_profile``, our fake module survives the toggle and actually runs.
    """
    r = Runner()

    async def producer(_q: Query) -> AsyncIterator[Hit]:
        for h in hits:
            yield h

    r.register(
        "internetdb",
        list(QueryKind),
        producer,
    )
    return r


def _q(value: str = "acme.com", kind: QueryKind = QueryKind.DOMAIN) -> Query:
    return Query(kind=kind, value=value)


# --------------------------------------------------------------------------- #
# 1. Plan + finalize happy path
# --------------------------------------------------------------------------- #

async def test_finalize_terminates_within_budget():
    fp = FakeProvider([
        "PLAN: triage acme.com",
        'THOUGHT: start with quick scan\nACTION: {"tool":"scan","args":{"profile":"quick"}}',
        'ACTION: {"tool":"finalize","args":{"summary":"low risk — only public records"}}',
    ])
    fr = _fake_runner_with([])
    loop = AgentLoop(provider=fp, runner=fr)
    result = await loop.run(_q(), max_steps=8)
    assert result.status == "done"
    assert "low risk" in result.answer
    # Plan was captured.
    assert "triage" in result.plan
    # Step kinds streamed in order.
    kinds = [s.kind for s in result.steps]
    assert "plan" in kinds
    assert "action" in kinds
    assert "answer" in kinds


async def test_finalize_only_no_intermediate_action():
    """An eager model can call finalize on the first turn — must still exit cleanly."""
    fp = FakeProvider([
        "PLAN: just answer",
        'ACTION: {"tool":"finalize","args":{"summary":"nothing to do"}}',
    ])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))
    result = await loop.run(_q(), max_steps=4)
    assert result.status == "done"
    assert result.answer == "nothing to do"


# --------------------------------------------------------------------------- #
# 2. Budget exhaustion
# --------------------------------------------------------------------------- #

async def test_max_steps_exhausted_returns_partial():
    # Model keeps emitting THOUGHTs and never finalizes.
    fp = FakeProvider([
        "PLAN: dig",
        *[f"THOUGHT: step {i}" for i in range(50)],
    ])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))
    result = await loop.run(_q(), max_steps=3, max_tokens=99999)
    assert result.status == "budget_exhausted"
    # Plan + 3 thought steps recorded.
    assert any(s.kind == "thought" for s in result.steps)
    # Never set an answer.
    assert result.answer == ""


async def test_max_tokens_exhausted():
    # Long reply burns the token budget after the plan.
    big = "THOUGHT: " + ("x" * 20000)
    fp = FakeProvider(["PLAN: hi", big, big, big])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))
    result = await loop.run(_q(), max_steps=10, max_tokens=500)
    assert result.status == "budget_exhausted"
    assert result.tokens["in"] >= 0
    assert result.tokens["out"] >= 500 or result.tokens["in"] + result.tokens["out"] >= 500


# --------------------------------------------------------------------------- #
# 3. Plan approval gate
# --------------------------------------------------------------------------- #

async def test_plan_rejection_short_circuits():
    fp = FakeProvider(["PLAN: do something risky",
                       'ACTION: {"tool":"finalize","args":{"summary":"x"}}'])
    fr = _fake_runner_with([])
    loop = AgentLoop(provider=fp, runner=fr)

    async def reject(_plan: str) -> bool:
        return False

    result = await loop.run(_q(), approve=reject)
    assert result.status == "rejected"
    # Only one provider call (the plan turn) — the second reply was never consumed.
    assert len(fp.calls) == 1


async def test_plan_approval_proceeds():
    fp = FakeProvider(["PLAN: ok",
                       'ACTION: {"tool":"finalize","args":{"summary":"done"}}'])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))
    captured: list[str] = []

    async def approve(plan: str) -> bool:
        captured.append(plan)
        return True

    result = await loop.run(_q(), approve=approve)
    assert result.status == "done"
    assert captured == ["ok"]


async def test_approve_exception_treated_as_rejection():
    fp = FakeProvider(["PLAN: ok"])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))

    async def boom(_plan: str) -> bool:
        raise RuntimeError("operator died")

    result = await loop.run(_q(), approve=boom)
    assert result.status == "rejected"


# --------------------------------------------------------------------------- #
# 4. Cancellation
# --------------------------------------------------------------------------- #

async def test_cancellation_reraises_cleanly():
    class HangingProvider:
        name = "hang"

        def available(self) -> bool:
            return True

        async def stream(self, *_a, **_k):
            await asyncio.Event().wait()  # hang forever
            return ""

    loop = AgentLoop(provider=HangingProvider(), runner=_fake_runner_with([]))
    task = asyncio.create_task(loop.run(_q(), max_steps=3))
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # State must be cleaned up by the finally block.
    assert AGENT_STATE["running"] is False


# --------------------------------------------------------------------------- #
# 5. Tool: scan
# --------------------------------------------------------------------------- #

async def test_scan_invokes_runner_with_profile():
    hit = Hit(module="internetdb", source="example.com",
              status=HitStatus.FOUND, severity=Severity.LOW,
              detail="seen")
    fp = FakeProvider([
        "PLAN: probe",
        'ACTION: {"tool":"scan","args":{"profile":"quick"}}',
        'ACTION: {"tool":"finalize","args":{"summary":"ok"}}',
    ])
    fr = _fake_runner_with([hit])
    loop = AgentLoop(provider=fp, runner=fr)
    result = await loop.run(_q(), max_steps=5)
    assert result.status == "done"
    # The accumulator should have absorbed the runner's hit.
    assert any(h.source == "example.com" for h in result.hits)
    # Observation appears on the scan action step.
    scan_step = next(s for s in result.steps
                     if s.kind == "action" and s.tool == "scan")
    assert scan_step.observation is not None
    assert "new_hits" in scan_step.observation


async def test_scan_unknown_profile_emits_error_obs_but_loop_continues():
    fp = FakeProvider([
        "PLAN: probe",
        'ACTION: {"tool":"scan","args":{"profile":"bogus"}}',
        'ACTION: {"tool":"finalize","args":{"summary":"abort"}}',
    ])
    fr = _fake_runner_with([])
    loop = AgentLoop(provider=fp, runner=fr)
    result = await loop.run(_q(), max_steps=5)
    assert result.status == "done"
    scan_step = next(s for s in result.steps
                     if s.kind == "action" and s.tool == "scan")
    assert "unknown profile" in (scan_step.observation or "")


# --------------------------------------------------------------------------- #
# 6. Tool: read_hits + pivot
# --------------------------------------------------------------------------- #

async def test_read_hits_filters_and_exposes_entities():
    hits = [
        Hit(module="internetdb", source="api.example.com",
            status=HitStatus.FOUND, severity=Severity.HIGH),
        Hit(module="other", source="noise.example.com",
            status=HitStatus.NOT_FOUND, severity=Severity.INFO),
    ]
    fp = FakeProvider([
        "PLAN: triage",
        'ACTION: {"tool":"scan","args":{"profile":"quick"}}',
        'ACTION: {"tool":"read_hits","args":{"severity":"high","status":"found"}}',
        'ACTION: {"tool":"finalize","args":{"summary":"got it"}}',
    ])
    fr = _fake_runner_with(hits)
    loop = AgentLoop(provider=fp, runner=fr)
    result = await loop.run(_q(), max_steps=6)
    assert result.status == "done"
    read_step = next(s for s in result.steps
                     if s.kind == "action" and s.tool == "read_hits")
    # Filtered out the NOT_FOUND/INFO row → only the high/found one survives.
    assert "api.example.com" in (read_step.observation or "")
    assert "noise.example.com" not in (read_step.observation or "")


async def test_pivot_runs_once_per_entity():
    """pivot(entity_id=…) hits the runner again with profile-mapped kind."""
    seen_kinds: list[QueryKind] = []
    seen_values: list[str] = []
    r = Runner()

    async def producer(q: Query) -> AsyncIterator[Hit]:
        seen_kinds.append(q.kind)
        seen_values.append(q.value)
        # On first call, surface a domain entity so the model can pivot to it.
        if q.value == "acme.com":
            yield Hit(module="internetdb", source="ns1.acme.com",
                      status=HitStatus.FOUND, severity=Severity.LOW)

    # `internetdb` is in every default profile preset, so apply_profile()
    # inside the agent's scan/pivot tools won't disable our test module.
    r.register("internetdb", list(QueryKind), producer)

    # First scan, then read_hits to populate entity_map, then pivot.
    # We need to know the id deterministically; entity_id of ns1.acme.com:
    from app.core.entities import EntityType, entity_id
    eid = entity_id(EntityType.DOMAIN, "ns1.acme.com")

    fp = FakeProvider([
        "PLAN: pivot",
        'ACTION: {"tool":"scan","args":{"profile":"quick"}}',
        'ACTION: {"tool":"read_hits","args":{}}',
        f'ACTION: {{"tool":"pivot","args":{{"entity_id":"{eid}"}}}}',
        'ACTION: {"tool":"finalize","args":{"summary":"ok"}}',
    ])
    loop = AgentLoop(provider=fp, runner=r)
    result = await loop.run(_q(), max_steps=10)
    assert result.status == "done"
    # Pivot must have called the runner with the discovered subdomain.
    assert "ns1.acme.com" in seen_values
    pivot_step = next(s for s in result.steps
                      if s.kind == "action" and s.tool == "pivot")
    # observation contains the new_hits count + entity_id.
    assert eid in (pivot_step.observation or "")


async def test_pivot_unknown_entity_returns_error_obs():
    fp = FakeProvider([
        "PLAN: pivot blind",
        'ACTION: {"tool":"pivot","args":{"entity_id":"deadbeef"}}',
        'ACTION: {"tool":"finalize","args":{"summary":"abort"}}',
    ])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))
    result = await loop.run(_q(), max_steps=5)
    assert result.status == "done"
    pivot_step = next(s for s in result.steps
                      if s.kind == "action" and s.tool == "pivot")
    assert "unknown entity_id" in (pivot_step.observation or "")


# --------------------------------------------------------------------------- #
# 7. Streaming callback
# --------------------------------------------------------------------------- #

async def test_on_step_called_for_each_kind():
    fp = FakeProvider([
        "PLAN: stream",
        'THOUGHT: think first\nACTION: {"tool":"scan","args":{"profile":"quick"}}',
        'ACTION: {"tool":"finalize","args":{"summary":"end"}}',
    ])
    fr = _fake_runner_with([Hit(module="internetdb", source="x.example.com",
                                status=HitStatus.FOUND)])
    loop = AgentLoop(provider=fp, runner=fr)
    streamed: list[tuple[str, str]] = []

    def cb(kind, text, _tok):
        streamed.append((kind, text[:30]))

    result = await loop.run(_q(), on_step=cb)
    assert result.status == "done"
    kinds = [k for k, _ in streamed]
    assert "plan" in kinds
    assert "action" in kinds
    assert "observation" in kinds
    assert "answer" in kinds


async def test_on_step_callback_errors_are_swallowed():
    """Buggy UI callbacks must NOT poison the agent loop."""
    fp = FakeProvider([
        "PLAN: x",
        'ACTION: {"tool":"finalize","args":{"summary":"ok"}}',
    ])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))

    def evil(*_a):
        raise RuntimeError("UI exploded")

    result = await loop.run(_q(), on_step=evil)
    assert result.status == "done"


# --------------------------------------------------------------------------- #
# 8. Unparseable / drifting model
# --------------------------------------------------------------------------- #

async def test_unparseable_reply_does_not_crash():
    fp = FakeProvider([
        "PLAN: ok",
        "this is just prose, no THOUGHT or ACTION",
        'ACTION: {"tool":"finalize","args":{"summary":"recovered"}}',
    ])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))
    result = await loop.run(_q(), max_steps=5)
    assert result.status == "done"
    assert result.answer == "recovered"
    # An error step was recorded for the unparseable middle turn.
    assert any(s.kind == "error" for s in result.steps)


async def test_action_json_with_bad_shape_is_treated_as_unparseable():
    fp = FakeProvider([
        "PLAN: drift",
        'ACTION: "not an object"',
        'ACTION: {"tool":"finalize","args":{"summary":"caught"}}',
    ])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))
    result = await loop.run(_q(), max_steps=5)
    assert result.status == "done"


# --------------------------------------------------------------------------- #
# 9. Token accounting
# --------------------------------------------------------------------------- #

async def test_tokens_tracked_per_step():
    fp = FakeProvider([
        "PLAN: hi",
        'ACTION: {"tool":"finalize","args":{"summary":"done"}}',
    ])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))
    result = await loop.run(_q())
    assert result.tokens["in"] > 0
    assert result.tokens["out"] > 0
    assert len(result.tokens["by_step"]) >= 2


# --------------------------------------------------------------------------- #
# 10. Provider hard-down at first turn
# --------------------------------------------------------------------------- #

async def test_provider_unavailable_at_plan_returns_error_status():
    class Dead:
        name = "dead"
        def available(self):
            return True
        async def stream(self, *_a, **_k):
            raise LLMUnavailable("no daemon")

    loop = AgentLoop(provider=Dead(), runner=_fake_runner_with([]))
    result = await loop.run(_q())
    assert result.status == "error"
    assert "no daemon" in result.answer


async def test_provider_unavailable_mid_loop_marks_budget_exhausted():
    fp = FakeProvider(
        ["PLAN: probe", 'THOUGHT: continue'],
        raise_after=2,
    )
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))
    result = await loop.run(_q(), max_steps=5)
    # The plan + one thought turn succeeded; the next stream() raises.
    assert result.status == "budget_exhausted"


# --------------------------------------------------------------------------- #
# 11. AGENT_STATE for the toolbar
# --------------------------------------------------------------------------- #

async def test_agent_state_cleared_after_run():
    fp = FakeProvider([
        "PLAN: ok",
        'ACTION: {"tool":"finalize","args":{"summary":"done"}}',
    ])
    loop = AgentLoop(provider=fp, runner=_fake_runner_with([]))
    await loop.run(_q())
    assert AGENT_STATE["running"] is False


async def test_agent_state_updates_during_run():
    """The toolbar reads AGENT_STATE — ensure it's set while the loop runs."""
    seen_running: list[bool] = []

    class WatchedProvider:
        name = "watch"
        calls = 0
        def available(self):
            return True
        async def stream(self, *_a, **_k):
            seen_running.append(bool(AGENT_STATE.get("running")))
            WatchedProvider.calls += 1
            if WatchedProvider.calls == 1:
                return "PLAN: peek"
            return 'ACTION: {"tool":"finalize","args":{"summary":"x"}}'

    loop = AgentLoop(provider=WatchedProvider(), runner=_fake_runner_with([]))
    await loop.run(_q())
    assert all(seen_running)
    assert AGENT_STATE["running"] is False


# --------------------------------------------------------------------------- #
# 12. cmd_agent CLI shim
# --------------------------------------------------------------------------- #

def test_cmd_agent_no_args_prints_usage(capsys):
    rc = cmd_agent([])
    assert rc == 2
    # usage went to stderr.
    err = capsys.readouterr().err
    assert "usage:" in err


def test_cmd_agent_help_exits_zero(capsys):
    rc = cmd_agent(["--help"])
    assert rc == 0


def test_cmd_agent_no_approve_flag_runs(monkeypatch, capsys):
    """`--no-approve` skips the prompt; we mock the provider so the run is hermetic."""
    fp = FakeProvider([
        "PLAN: hi",
        'ACTION: {"tool":"finalize","args":{"summary":"done"}}',
    ])

    def _fake_select():
        return fp

    monkeypatch.setattr("app.features.agent.select_provider", _fake_select)
    # Stub the post-run explain so it doesn't hit any provider.
    async def _fake_explain(*_a, **_k):
        return "(stub)"
    monkeypatch.setattr("app.features.ai.explain", _fake_explain)
    rc = cmd_agent(["acme.com", "--no-approve"])
    # done → 0
    assert rc == 0
