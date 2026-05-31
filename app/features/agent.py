"""ReAct-style investigation loop — Wave B (opt-in).

Default OFF. Adding this module must NOT change any existing CLI path; it is
only reached via the new ``osint agent`` subcommand or the ``/agent`` slash.

Why ReAct (THOUGHT → ACTION → OBSERVATION → ANSWER) rather than
plan-and-execute? Small local models (qwen2.5:3b on a laptop) are better at
incrementally choosing one next step than at producing a multi-step plan up
front. ReAct also degrades gracefully when the model drifts: any unparseable
turn becomes an OBSERVATION carrying the parse error and the loop continues.

Constraints baked in here:

* Local-first — the LLM is whatever ``select_provider()`` resolves to. No
  hard dep on a specific model; the system prompt is kept under ~700 tokens
  and the tool schema is one tiny JSON object per call.
* Budget-bounded — both ``max_steps`` and ``max_tokens`` are hard walls; on
  either, the loop returns a ``AgentResult.status = "budget_exhausted"`` with
  any partial findings rather than raising.
* Cancellable — ``asyncio.CancelledError`` is re-raised cleanly. We never
  swallow it.
* Plan-approval — the model is asked to emit a one-line ``PLAN:`` *before*
  its first tool call. The caller-supplied ``approve(plan)`` decides whether
  to proceed. ``None`` means "auto-approve" (CLI ``--no-approve``).

Tool surface (kept to four — small models lose track of more):

* ``scan(profile: str)`` — runs the active profile against the original
  query via the existing :class:`Runner`.
* ``pivot(entity_id: str)`` — runs a follow-up scan on a discovered entity
  (wraps the same auto-pivot routing table — never duplicates the logic).
* ``read_hits(filter: dict)`` — queries the in-memory hit accumulator with
  ``severity>=``, ``status=``, ``module=`` filters. Returns compact JSON.
* ``finalize(summary: str)`` — exits the loop with a final summary that the
  CLI renders via the ``exec-summary`` Wave A pattern.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from app.core.entities import PIVOT_PROFILE, EntityType, canonical_key, entity_id
from app.core.infer import infer_kind
from app.core.profiles import PROFILES, apply_profile
from app.core.runner import Runner
from app.core.runner import runner as _default_runner
from app.core.types import Hit, HitStatus, Query, QueryKind
from app.features.ai import LLMProvider, LLMUnavailable, select_provider

log = logging.getLogger("osint.agent")


# --------------------------------------------------------------------------- #
# Public state for the chat-shell toolbar
# --------------------------------------------------------------------------- #
#
# The interactive bottom toolbar polls this dict to show progress while an
# agent loop is running ("[agent N/8 steps · 1.2k tok]"). It is intentionally
# a module-level dict (not a queue or signal) so the toolbar's read path is
# the cheapest possible thing — one dict lookup per refresh.
AGENT_STATE: dict[str, Any] = {
    "running": False,
    "step": 0,
    "max_steps": 0,
    "tokens": 0,
}


def _state_begin(max_steps: int) -> None:
    AGENT_STATE["running"] = True
    AGENT_STATE["step"] = 0
    AGENT_STATE["max_steps"] = max_steps
    AGENT_STATE["tokens"] = 0


def _state_tick(step: int, tokens: int) -> None:
    AGENT_STATE["step"] = step
    AGENT_STATE["tokens"] = tokens


def _state_end() -> None:
    AGENT_STATE["running"] = False


# --------------------------------------------------------------------------- #
# Data types
# --------------------------------------------------------------------------- #

# Step kinds streamed via on_step.
StepKind = str  # "plan" | "thought" | "action" | "observation" | "answer" | "error"

OnStep = Callable[[StepKind, str, int], None]
ApproveFn = Callable[[str], Awaitable[bool]]


@dataclass(slots=True)
class AgentStep:
    """One iteration of the ReAct loop."""

    kind: StepKind
    text: str
    tokens_in: int = 0
    tokens_out: int = 0
    tool: str | None = None
    tool_args: dict[str, Any] = field(default_factory=dict)
    observation: str | None = None


@dataclass(slots=True)
class AgentResult:
    """Outcome of one ``AgentLoop.run`` invocation.

    ``status`` is one of:
      * ``"done"`` — the model called ``finalize``.
      * ``"budget_exhausted"`` — hit max_steps or max_tokens before finalize.
      * ``"rejected"`` — operator rejected the plan; no tools ran.
      * ``"error"`` — provider unavailable or some other fatal init failure.
    """

    query: Query
    status: str
    plan: str = ""
    answer: str = ""
    steps: list[AgentStep] = field(default_factory=list)
    hits: list[Hit] = field(default_factory=list)
    tokens: dict[str, Any] = field(default_factory=lambda: {"in": 0, "out": 0, "by_step": []})
    elapsed_ms: int = 0


# --------------------------------------------------------------------------- #
# Tool catalogue (kept tiny — small models can't juggle more)
# --------------------------------------------------------------------------- #

TOOLS_DOC = """TOOLS:
- scan(profile): run profile (one of: quick, deep, person, ioc, domain-recon, leak-hunt) against the original target. Returns counts.
- pivot(entity_id): run a follow-up scan on a discovered entity_id from prior hits. Returns counts.
- read_hits(filter): inspect accumulated hits. filter is {"severity": "low|medium|high|critical", "status": "found|error|...", "module": "<name>"} (all optional). Returns compact JSON.
- finalize(summary): END the loop. summary is one-line verdict + 1-3 sentence rationale."""


SYSTEM_PROMPT = """You are a careful OSINT investigator running locally on a laptop. Be terse. Be decisive. No filler.

Loop: emit exactly ONE block per turn.
First turn ONLY: emit a single line `PLAN: <one sentence>` then STOP and wait.
Every turn after: emit either
  THOUGHT: <one short sentence>
  ACTION: {"tool": "<name>", "args": {...}}
OR
  ANSWER: <use finalize tool instead>

Rules:
- Always start with `scan(profile="quick")` for first action unless the user clearly needs deep/leak-hunt/etc.
- Use `read_hits` to inspect before deciding to `pivot`.
- Call `finalize` as soon as you have a verdict. Do not over-investigate.
- ACTION must be ONE JSON object on ONE line. No markdown fences, no prose after it.
- Never invent entity_ids — only use ones returned by read_hits.

""" + TOOLS_DOC


# --------------------------------------------------------------------------- #
# Heuristics for parsing the (small-model-friendly) reply format
# --------------------------------------------------------------------------- #

_PLAN_RE = re.compile(r"(?im)^\s*PLAN\s*:\s*(.+?)\s*$")
_THOUGHT_RE = re.compile(r"(?im)^\s*THOUGHT\s*:\s*(.+?)\s*$")
# Match only up to (and including) the ACTION: marker; the JSON object after it
# is extracted by balancing braces (see _first_json_object) so multi-line /
# pretty-printed JSON and trailing prose are tolerated.
_ACTION_MARKER_RE = re.compile(r"(?im)^\s*ACTION\s*:\s*")
_ANSWER_RE = re.compile(r"(?im)^\s*ANSWER\s*:\s*(.+?)\s*$", re.DOTALL)


def _first_json_object(text: str) -> tuple[dict[str, Any] | None, str]:
    """Extract the first balanced ``{...}`` JSON object from ``text``.

    Walks from the first ``{``, tracking brace depth while honouring string
    literals and escapes so braces inside strings don't fool the counter.
    Returns ``(parsed_obj, raw_slice)`` — ``(None, "")`` if no balanced
    object parses. Trailing text after the closing brace is ignored, so
    pretty-printed JSON and ``ACTION: {...}  // comment`` both work.
    """
    start = text.find("{")
    if start == -1:
        return None, ""
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                raw = text[start:i + 1]
                try:
                    obj = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    return None, ""
                if isinstance(obj, dict):
                    return obj, raw
                return None, ""
    return None, ""


def _estimate_tokens(text: str) -> int:
    """Cheap stand-in when a provider doesn't expose token counts.

    The 4-chars-per-token rule of thumb is rough but consistent; we only use
    it to bound a budget, never to bill anyone.
    """
    if not text:
        return 0
    return max(1, len(text) // 4)


def _parse_step(reply: str) -> tuple[str, str, dict[str, Any] | None, str]:
    """Return ``(kind, text, tool_args, raw_action)`` for one LLM reply.

    Order matters — ANSWER wins over ACTION wins over THOUGHT, because a
    drifting model often emits both and we'd rather honour the most-final.
    """
    if m := _ANSWER_RE.search(reply):
        return "answer", m.group(1).strip(), None, ""
    if m := _ACTION_MARKER_RE.search(reply):
        # Extract the first balanced JSON object after the ACTION: marker —
        # tolerant of multi-line/pretty-printed JSON and trailing prose.
        obj, raw = _first_json_object(reply[m.end():])
        if isinstance(obj, dict) and "tool" in obj:
            args = obj.get("args") or {}
            if not isinstance(args, dict):
                args = {}
            return "action", str(obj["tool"]), args, raw
    if m := _THOUGHT_RE.search(reply):
        return "thought", m.group(1).strip(), None, ""
    # Unparseable — surface the raw reply as an observation so the loop can
    # recover (the next THOUGHT typically corrects the format).
    return "unparsed", reply.strip(), None, ""


# --------------------------------------------------------------------------- #
# The loop
# --------------------------------------------------------------------------- #

class AgentLoop:
    """A small ReAct loop. Default OFF; constructed only when invoked.

    The loop is generic in the provider — anything implementing the Wave A
    :class:`LLMProvider` Protocol works. Tests substitute a FakeProvider.
    """

    def __init__(
        self,
        provider: LLMProvider | None = None,
        runner: Runner | None = None,
    ) -> None:
        self._provider = provider or select_provider()
        self._runner = runner or _default_runner()

    # ---- public entry point ------------------------------------------------

    async def run(
        self,
        query: Query,
        *,
        max_steps: int = 8,
        max_tokens: int = 4000,
        on_step: OnStep | None = None,
        approve: ApproveFn | None = None,
    ) -> AgentResult:
        """Drive the loop. Never raises for budget / parse / tool issues.

        Re-raises ``asyncio.CancelledError`` so callers can cancel the loop
        with their normal cancellation primitives.
        """
        started = time.perf_counter()
        result = AgentResult(query=query, status="error")
        accumulated: list[Hit] = []
        # entity_id → (EntityType, raw_value) discovered via read_hits, so the
        # model can refer to them by id when calling pivot().
        entity_map: dict[str, tuple[EntityType, str]] = {}

        _state_begin(max_steps)
        tokens_in_total = 0
        tokens_out_total = 0

        try:
            # ---- conversation transcript shared with the provider ---------
            messages: list[dict[str, str]] = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"TARGET: kind={query.kind.value} value={query.value}\n"
                        "First, output one line `PLAN: <…>` and STOP."
                    ),
                },
            ]

            # ---- 1. Plan turn ------------------------------------------------
            try:
                reply = await self._provider.stream(messages, max_tokens=160)
            except LLMUnavailable as e:
                result.status = "error"
                result.answer = f"agent unavailable: {e}"
                return result

            t_in = _estimate_tokens(messages[-1]["content"]) + _estimate_tokens(messages[0]["content"])
            t_out = _estimate_tokens(reply)
            tokens_in_total += t_in
            tokens_out_total += t_out
            plan_text = ""
            if m := _PLAN_RE.search(reply):
                plan_text = m.group(1).strip()
            elif reply.strip():
                # Model skipped the keyword; use the first non-empty line.
                plan_text = reply.strip().splitlines()[0][:240]
            result.plan = plan_text
            step = AgentStep(kind="plan", text=plan_text, tokens_in=t_in, tokens_out=t_out)
            result.steps.append(step)
            result.tokens["by_step"].append({"kind": "plan", "in": t_in, "out": t_out})
            _state_tick(1, tokens_in_total + tokens_out_total)
            if on_step:
                with contextlib.suppress(Exception):
                    on_step("plan", plan_text, t_in + t_out)
            messages.append({"role": "assistant", "content": reply})

            # ---- 2. Approval -------------------------------------------------
            if approve is not None:
                try:
                    ok = await approve(plan_text)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    ok = False
                if not ok:
                    result.status = "rejected"
                    return result

            # ---- 3. ReAct iterations ----------------------------------------
            messages.append({
                "role": "user",
                "content": "OK proceed. Emit THOUGHT then ACTION (one JSON line). Use finalize when done.",
            })

            for step_no in range(1, max_steps + 1):
                # Hard token budget — leave room for the next reply.
                if tokens_in_total + tokens_out_total >= max_tokens:
                    result.status = "budget_exhausted"
                    break

                try:
                    reply = await self._provider.stream(messages, max_tokens=320)
                except LLMUnavailable as e:
                    err = AgentStep(kind="error", text=f"provider: {e}")
                    result.steps.append(err)
                    if on_step:
                        with contextlib.suppress(Exception):
                            on_step("error", err.text, 0)
                    result.status = "budget_exhausted"
                    break

                # The provider re-sends the WHOLE transcript each call, so the
                # input cost grows O(steps). Count the full messages list (not
                # just the last two) or the max_tokens wall fires far too late.
                t_in = sum(_estimate_tokens(m["content"]) for m in messages)
                t_out = _estimate_tokens(reply)
                tokens_in_total += t_in
                tokens_out_total += t_out

                kind, text, tool_args, raw_action = _parse_step(reply)
                if kind == "answer":
                    step = AgentStep(kind="answer", text=text,
                                     tokens_in=t_in, tokens_out=t_out)
                    result.steps.append(step)
                    result.tokens["by_step"].append({"kind": "answer", "in": t_in, "out": t_out})
                    if on_step:
                        with contextlib.suppress(Exception):
                            on_step("answer", text, t_in + t_out)
                    result.status = "done"
                    result.answer = text
                    break

                if kind == "thought":
                    thought = AgentStep(kind="thought", text=text,
                                        tokens_in=t_in, tokens_out=t_out)
                    result.steps.append(thought)
                    result.tokens["by_step"].append({"kind": "thought", "in": t_in, "out": t_out})
                    if on_step:
                        with contextlib.suppress(Exception):
                            on_step("thought", text, t_in + t_out)
                    messages.append({"role": "assistant", "content": reply})
                    messages.append({
                        "role": "user",
                        "content": "OK. Now ACTION (one JSON line) or ANSWER.",
                    })
                    _state_tick(step_no, tokens_in_total + tokens_out_total)
                    continue

                if kind == "action":
                    tool_name = text  # _parse_step packs the name into `text`
                    args = tool_args or {}
                    action_step = AgentStep(
                        kind="action",
                        text=raw_action,
                        tool=tool_name,
                        tool_args=args,
                        tokens_in=t_in,
                        tokens_out=t_out,
                    )
                    result.steps.append(action_step)
                    result.tokens["by_step"].append({
                        "kind": "action", "tool": tool_name,
                        "in": t_in, "out": t_out,
                    })
                    if on_step:
                        with contextlib.suppress(Exception):
                            on_step("action", f"{tool_name} {json.dumps(args)}", t_in + t_out)

                    # Special-case finalize — exits without an OBSERVATION.
                    if tool_name == "finalize":
                        summary = str(args.get("summary") or "").strip()
                        result.status = "done"
                        result.answer = summary or "(no summary)"
                        ans = AgentStep(kind="answer", text=result.answer)
                        result.steps.append(ans)
                        if on_step:
                            with contextlib.suppress(Exception):
                                on_step("answer", result.answer, 0)
                        break

                    obs = await self._run_tool(
                        tool_name, args, query=query,
                        hits=accumulated, entity_map=entity_map,
                    )
                    action_step.observation = obs
                    obs_tokens = _estimate_tokens(obs)
                    tokens_out_total += obs_tokens  # observation cost feeds budget
                    if on_step:
                        with contextlib.suppress(Exception):
                            on_step("observation", obs, obs_tokens)
                    messages.append({"role": "assistant", "content": reply})
                    messages.append({"role": "user", "content": f"OBSERVATION: {obs}"})
                    _state_tick(step_no, tokens_in_total + tokens_out_total)
                    continue

                # Unparseable — feed the parse error back so the model retries.
                bad = AgentStep(kind="error", text="unparseable reply",
                                tokens_in=t_in, tokens_out=t_out)
                result.steps.append(bad)
                if on_step:
                    with contextlib.suppress(Exception):
                        on_step("error", "unparseable reply", t_in + t_out)
                messages.append({"role": "assistant", "content": reply})
                messages.append({
                    "role": "user",
                    "content": "Reply was unparseable. Emit ONE of: `THOUGHT: ...` then `ACTION: {...}` JSON, OR `ANSWER: ...`",
                })
                _state_tick(step_no, tokens_in_total + tokens_out_total)
            else:
                # for-else: ran the full range without break → out of steps
                result.status = "budget_exhausted"

            result.hits = accumulated
            result.tokens["in"] = tokens_in_total
            result.tokens["out"] = tokens_out_total
            return result
        except asyncio.CancelledError:
            # Mark cleanly + re-raise — never swallow.
            result.status = "cancelled"
            result.hits = accumulated
            result.tokens["in"] = tokens_in_total
            result.tokens["out"] = tokens_out_total
            raise
        finally:
            result.elapsed_ms = int((time.perf_counter() - started) * 1000)
            _state_end()

    # ---- tool dispatcher --------------------------------------------------

    async def _run_tool(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        query: Query,
        hits: list[Hit],
        entity_map: dict[str, tuple[EntityType, str]],
    ) -> str:
        """Run one tool and return the observation string (compact JSON or text)."""
        if tool == "scan":
            return await self._tool_scan(args, query=query, hits=hits, entity_map=entity_map)
        if tool == "pivot":
            return await self._tool_pivot(args, hits=hits, entity_map=entity_map)
        if tool == "read_hits":
            return self._tool_read_hits(args, hits=hits, entity_map=entity_map)
        return json.dumps({"error": f"unknown tool {tool!r}"})

    async def _tool_scan(
        self,
        args: dict[str, Any],
        *,
        query: Query,
        hits: list[Hit],
        entity_map: dict[str, tuple[EntityType, str]],
    ) -> str:
        profile = str(args.get("profile") or "quick").strip().lower()
        if profile not in PROFILES:
            return json.dumps({"error": f"unknown profile {profile!r}",
                               "valid": sorted(PROFILES.keys())})
        try:
            enabled, _ = apply_profile(self._runner, profile)
        except ValueError as e:
            return json.dumps({"error": str(e)})
        try:
            # Thread the resolved module set in per-run so a concurrent agent /
            # scan on the shared singleton Runner can't change our scope mid-run.
            result = await self._runner.run(query, modules=frozenset(enabled))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return json.dumps({"error": f"runner failed: {type(e).__name__}: {e}"})
        added = self._absorb_hits(result.hits, hits, entity_map)
        return json.dumps({
            "profile": profile,
            "modules": len(enabled),
            "new_hits": added,
            "total_hits": len(hits),
            "found": sum(1 for h in hits if h.status == HitStatus.FOUND),
        })

    async def _tool_pivot(
        self,
        args: dict[str, Any],
        *,
        hits: list[Hit],
        entity_map: dict[str, tuple[EntityType, str]],
    ) -> str:
        eid = str(args.get("entity_id") or "").strip()
        if not eid:
            return json.dumps({"error": "entity_id required"})
        if eid not in entity_map:
            return json.dumps({"error": f"unknown entity_id {eid!r}",
                               "hint": "call read_hits first to enumerate"})
        etype, raw_value = entity_map[eid]
        if etype not in PIVOT_PROFILE:
            return json.dumps({"error": f"no pivot for entity type {etype.value!r}"})
        kind_str, profile_name = PIVOT_PROFILE[etype]
        try:
            qkind = QueryKind(kind_str)
        except ValueError:
            return json.dumps({"error": f"no QueryKind for {kind_str!r}"})
        try:
            enabled, _ = apply_profile(self._runner, profile_name)
        except ValueError as e:
            return json.dumps({"error": str(e)})
        sub_q = Query(kind=qkind, value=raw_value, note=f"agent-pivot:{eid}")
        try:
            result = await self._runner.run(sub_q, modules=frozenset(enabled))
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return json.dumps({"error": f"pivot failed: {type(e).__name__}: {e}"})
        added = self._absorb_hits(result.hits, hits, entity_map)
        return json.dumps({
            "entity_id": eid,
            "kind": qkind.value,
            "value": raw_value[:80],
            "profile": profile_name,
            "modules": len(enabled),
            "new_hits": added,
            "found": sum(1 for h in hits if h.status == HitStatus.FOUND),
        })

    def _tool_read_hits(
        self,
        args: dict[str, Any],
        *,
        hits: list[Hit],
        entity_map: dict[str, tuple[EntityType, str]],
    ) -> str:
        sev_min = str(args.get("severity") or "").strip().lower() or None
        status_eq = str(args.get("status") or "").strip().lower() or None
        module_eq = str(args.get("module") or "").strip() or None

        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        floor = sev_rank.get(sev_min or "", 0)

        rows: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for h in hits:
            if status_eq and h.status.value != status_eq:
                continue
            if module_eq and h.module != module_eq:
                continue
            if sev_min and sev_rank.get(h.severity.value, 0) < floor:
                continue
            # Try to surface a stable entity_id for any URL/host/IP/email we
            # can extract from the hit; this is what `pivot` then accepts.
            for et, val in _entities_from_hit(h):
                eid = entity_id(et, val)
                entity_map[eid] = (et, val)
                if eid in seen_ids:
                    continue
                seen_ids.add(eid)
                rows.append({
                    "id": eid,
                    "type": et.value,
                    "value": canonical_key(et, val)[:80],
                    "module": h.module,
                    "severity": h.severity.value,
                    "status": h.status.value,
                })
                if len(rows) >= 20:
                    break
            if len(rows) >= 20:
                break

        return json.dumps({"count": len(rows), "entities": rows})

    def _absorb_hits(
        self,
        new: list[Hit],
        bucket: list[Hit],
        entity_map: dict[str, tuple[EntityType, str]],
    ) -> int:
        added = 0
        for h in new:
            bucket.append(h)
            added += 1
            for et, val in _entities_from_hit(h):
                entity_map[entity_id(et, val)] = (et, val)
        return added


def _entities_from_hit(h: Hit) -> list[tuple[EntityType, str]]:
    """Best-effort extraction of pivotable entities from a hit.

    Intentionally conservative — we only mine the source/url fields the
    runner already populates. Heavy NLP belongs upstream in correlation.
    """
    import ipaddress

    out: list[tuple[EntityType, str]] = []
    src = (h.source or "").strip()
    if not src:
        return out
    if "@" in src and "." in src:
        out.append((EntityType.EMAIL, src))
        return out
    # IP-first (mirror infer.py ordering): an IP literal like `1.2.3.4` would
    # otherwise be classified as DOMAIN, and PIVOT_PROFILE[DOMAIN] runs DNS /
    # subdomain recon — which is meaningless against a raw IP. Strip a CIDR
    # suffix before parsing so `1.2.3.4/24` still resolves to IP.
    try:
        ipaddress.ip_address(src.split("/", 1)[0])
        out.append((EntityType.IP, src))
        return out
    except ValueError:
        pass
    if "." in src and " " not in src:
        # Looks like a host or domain.
        out.append((EntityType.DOMAIN, src))
    elif not any(c in src for c in " /:@"):
        # Bare token — treat as username.
        out.append((EntityType.USERNAME, src))
    return out


# --------------------------------------------------------------------------- #
# CLI entrypoint — wired from cli.py
# --------------------------------------------------------------------------- #

async def _interactive_approve(plan: str, *, timeout_s: float = 5.0) -> bool:
    """CLI default approver — print the plan, ask y/N, fall back to reject.

    Kept tiny on purpose: a 5s timeout means a non-interactive shell auto-rejects
    rather than hanging the run.
    """
    import sys
    print(f"\n  agent plan: {plan}", file=sys.stderr)
    print("  approve? [y/N] ", end="", file=sys.stderr, flush=True)
    try:
        line = await asyncio.wait_for(
            asyncio.to_thread(sys.stdin.readline), timeout=timeout_s,
        )
    except (TimeoutError, RuntimeError):
        print("(timeout → rejected)", file=sys.stderr)
        return False
    return line.strip().lower() in ("y", "yes")


def _render_step_to_stdout(kind: str, text: str, tokens: int) -> None:
    """Default streaming callback used by ``osint agent``."""
    import sys
    badge = {
        "plan":        "  · plan       ",
        "thought":     "  · thought    ",
        "action":      "  · action     ",
        "observation": "  · observation",
        "answer":      "  · answer     ",
        "error":       "  · error      ",
    }.get(kind, f"  · {kind:11s}")
    snippet = text.strip().splitlines()[0] if text.strip() else ""
    if len(snippet) > 200:
        snippet = snippet[:197] + "…"
    suffix = f"  [{tokens} tok]" if tokens else ""
    print(f"{badge} {snippet}{suffix}", file=sys.stderr, flush=True)


async def _run_agent(target: str, *, no_approve: bool) -> int:
    """Implementation of ``osint agent <target>``."""
    import sys

    from app.core.config import load_settings
    load_settings()
    kind = infer_kind(target) or QueryKind.USERNAME
    query = Query(kind=kind, value=target)

    loop = AgentLoop()

    approve: ApproveFn | None
    if no_approve or not sys.stdout.isatty():
        approve = None
    else:
        approve = _interactive_approve  # type: ignore[assignment]

    try:
        result = await loop.run(
            query, max_steps=8, max_tokens=4000,
            on_step=_render_step_to_stdout, approve=approve,
        )
    except asyncio.CancelledError:
        print("\n  agent cancelled.", file=sys.stderr)
        return 130

    if result.status == "rejected":
        print("  plan rejected — no tools ran.", file=sys.stderr)
        return 1
    if result.status == "error":
        print(f"  agent error: {result.answer}", file=sys.stderr)
        return 2

    # Render the final answer via the Wave A exec-summary pattern if we have
    # a payload to summarise; otherwise just print the answer text.
    try:
        from app.features.ai import explain
        # Build a tiny JSON payload of the strongest hits so the pattern has
        # something to chew on.
        payload_rows = [
            {
                "module": h.module, "src": h.source, "sev": h.severity.value,
                "title": h.title or "", "detail": (h.detail or "")[:160],
                "url": h.url[:160] if h.url else "",
            }
            for h in result.hits[:40] if h.status == HitStatus.FOUND
        ]
        if payload_rows:
            payload = json.dumps(payload_rows, indent=2, default=str)
            print(file=sys.stderr)
            summary = await explain(
                f"TARGET: {query.kind.value}={query.value}\n"
                f"AGENT ANSWER: {result.answer}\n"
                f"FINDINGS:\n```json\n{payload}\n```\n",
                pattern="exec-summary",
            )
            print("\n" + summary + "\n")
        else:
            print(f"\n  agent answer: {result.answer}\n")
    except Exception as e:
        log.debug("exec-summary render failed: %s", e)
        print(f"\n  agent answer: {result.answer}\n")

    print(
        f"  status={result.status}  steps={len(result.steps)}  "
        f"tokens(in/out)={result.tokens['in']}/{result.tokens['out']}  "
        f"elapsed={result.elapsed_ms}ms",
        file=sys.stderr,
    )
    return 0 if result.status == "done" else 1


def cmd_agent(argv: list[str]) -> int:
    """Dispatch for ``osint agent ...`` — opt-in only."""
    import sys
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage: osint agent <target> [--no-approve]\n\n"
            "  Runs a local ReAct agent loop against <target>. Default OFF —\n"
            "  this command is the only way to invoke it. The loop is bounded\n"
            "  by max_steps=8 and max_tokens=4000.\n\n"
            "  --no-approve   skip the y/N plan-approval prompt (auto-approve)",
            file=sys.stderr,
        )
        return 0 if argv else 2
    rest = list(argv)
    no_approve = "--no-approve" in rest
    rest = [a for a in rest if a != "--no-approve"]
    if not rest:
        print("usage: osint agent <target> [--no-approve]", file=sys.stderr)
        return 2
    target = rest[0]
    return asyncio.run(_run_agent(target, no_approve=no_approve))
