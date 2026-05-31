"""Conditional playbooks (Wave D3).

A *playbook* is a tiny DAG of steps. Each step says "run X (a profile or a
single module name, or the agent), maybe only when this condition holds,
maybe re-target from a previous step's findings". Linear profiles cover
the "do these N modules" case; playbooks cover the "if the breach probe
found something, then chase the owner" case.

Why not a real workflow engine? Because the user runs this on a laptop in
seconds — not a Temporal cluster. The DSL is intentionally tiny so the
common cases are obvious in the YAML and unusual ones are pushed back to
Python.

Expression DSL — supported names inside ``when`` / ``target_from``:

  Reading state:
    kind                      — the target query's QueryKind value (str)
    any_severity              — highest severity seen across all steps so far
                                (str: 'info' < 'low' < 'medium' < 'high' < 'critical')
    count('found')            — total FOUND hits across all completed steps
    count('high')             — total HIGH-or-above hits
    count('error')            — total ERROR hits
    hits[i].url               — N-th hit's url (list-style; only ``hits[N]``
                                accessors with integer literal are allowed)
    hits[i].kind              — N-th hit's QueryKind (alias for ``hits[i].module``)
    hits[i].module / source / title / detail / severity / status

  Operators: == != >= <= > < and or not in
  Literals: strings, ints, lists, tuples — via ``ast.literal_eval``.

  Everything else (calls except ``count(...)``, attribute access except the
  whitelisted ``hits[N].field``, imports, ``__`` names, etc.) is rejected.

Two builtins ship:

  * ``phish-triage`` — DNS → SSL → email-extras → if anything high, run agent.
  * ``subdomain-deepdive`` — domain-recon → if subdomain count > 0, run
    domain-recon again from the first.
"""
from __future__ import annotations

import ast
import asyncio
import logging
import operator as _op
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.core.db import Database
from app.core.profiles import PROFILES, apply_profile
from app.core.runner import Runner
from app.core.runner import runner as _default_runner
from app.core.types import Hit, HitStatus, Query, QueryKind, QueryResult, Severity

log = logging.getLogger("osint.playbooks")

# Builtin playbook directory inside the package — bundled with the wheel.
_BUILTIN_DIR = Path(__file__).resolve().parent / "playbooks_builtin"

_SEV_RANK = {
    Severity.INFO.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Step:
    id: str
    run: str
    when: str | None = None
    target_from: str | None = None


@dataclass(slots=True)
class Playbook:
    id: str
    name: str
    steps: list[Step] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Playbook:
        if not isinstance(raw, dict):
            raise ValueError("playbook must be a mapping")
        pid = str(raw.get("id") or "").strip()
        if not pid:
            raise ValueError("playbook id is required")
        steps_raw = raw.get("steps") or []
        if not isinstance(steps_raw, list) or not steps_raw:
            raise ValueError(f"playbook {pid!r}: steps must be a non-empty list")
        steps: list[Step] = []
        seen_ids: set[str] = set()
        for s in steps_raw:
            if not isinstance(s, dict):
                raise ValueError(f"playbook {pid!r}: each step must be a mapping")
            sid = str(s.get("id") or "").strip()
            srun = str(s.get("run") or "").strip()
            if not sid or not srun:
                raise ValueError(f"playbook {pid!r}: step needs both id and run")
            if sid in seen_ids:
                raise ValueError(f"playbook {pid!r}: duplicate step id {sid!r}")
            seen_ids.add(sid)
            steps.append(Step(
                id=sid,
                run=srun,
                when=(str(s["when"]) if s.get("when") is not None else None),
                target_from=(str(s["target_from"]) if s.get("target_from") is not None else None),
            ))
        return cls(id=pid, name=str(raw.get("name") or pid), steps=steps)


def load_playbooks(*, builtins: bool = True, user_dir: Path | str | None = None) -> list[Playbook]:
    """Load playbooks from disk. Same precedence rule as rules: user wins."""
    books: dict[str, Playbook] = {}
    dirs: list[Path] = []
    if builtins:
        dirs.append(_BUILTIN_DIR)
    if user_dir:
        dirs.append(Path(user_dir))
    for d in dirs:
        if not d.exists() or not d.is_dir():
            continue
        for p in sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml")):
            try:
                raw = yaml.safe_load(p.read_text(encoding="utf-8"))
                pb = Playbook.from_dict(raw)
            except (yaml.YAMLError, ValueError, OSError) as exc:
                log.warning("playbook load skipped %s: %s", p, exc)
                continue
            books[pb.id] = pb
    return list(books.values())


# ---------------------------------------------------------------------------
# Tiny expression DSL — safe walker over an AST subset
# ---------------------------------------------------------------------------


class UnsafeExpression(ValueError):
    """Raised when an expression contains a disallowed node or name."""


_ALLOWED_BINOPS = {
    ast.Eq: _op.eq, ast.NotEq: _op.ne,
    ast.Lt: _op.lt, ast.LtE: _op.le,
    ast.Gt: _op.gt, ast.GtE: _op.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}
_ALLOWED_BOOLOPS = {ast.And: all, ast.Or: any}
_ALLOWED_NAMES = {"kind", "any_severity", "True", "False", "None"}
_ALLOWED_HIT_FIELDS = {"url", "module", "source", "title", "detail",
                       "severity", "status", "kind"}


@dataclass(slots=True)
class _ExprCtx:
    kind: str
    hits: list[Hit]

    def any_severity(self) -> str:
        best = "info"
        for h in self.hits:
            if _SEV_RANK.get(h.severity.value, 0) > _SEV_RANK.get(best, 0):
                best = h.severity.value
        return best


def _hit_field(h: Hit, field: str) -> str:
    if field == "url":
        return h.url or ""
    if field == "module":
        return h.module
    if field == "source":
        return h.source
    if field == "title":
        return h.title or ""
    if field == "detail":
        return h.detail or ""
    if field == "severity":
        return h.severity.value
    if field == "status":
        return h.status.value
    if field == "kind":
        return h.module
    raise UnsafeExpression(f"unknown hit field {field!r}")


def _eval(node: ast.AST, ctx: _ExprCtx) -> Any:
    if isinstance(node, ast.Expression):
        return _eval(node.body, ctx)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval(node.operand, ctx)
    if isinstance(node, ast.BoolOp):
        agg = _ALLOWED_BOOLOPS.get(type(node.op))
        if agg is None:
            raise UnsafeExpression(f"bad boolop {type(node.op).__name__}")
        return agg(_eval(v, ctx) for v in node.values)
    if isinstance(node, ast.Compare):
        left = _eval(node.left, ctx)
        for op, right_node in zip(node.ops, node.comparators, strict=False):
            fn = _ALLOWED_BINOPS.get(type(op))
            if fn is None:
                raise UnsafeExpression(f"bad compare op {type(op).__name__}")
            right = _eval(right_node, ctx)
            if op.__class__ in (ast.Lt, ast.LtE, ast.Gt, ast.GtE):
                # Lexicographic on severity is meaningless; promote to rank.
                if isinstance(left, str) and isinstance(right, str) \
                        and left in _SEV_RANK and right in _SEV_RANK:
                    left, right = _SEV_RANK[left], _SEV_RANK[right]
            if not fn(left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.Name):
        if node.id == "kind":
            return ctx.kind
        if node.id == "any_severity":
            return ctx.any_severity()
        if node.id == "True":
            return True
        if node.id == "False":
            return False
        if node.id == "None":
            return None
        raise UnsafeExpression(f"unknown name {node.id!r}")
    if isinstance(node, ast.Call):
        # Only ``count('found' | 'high' | 'error')`` is allowed.
        if not isinstance(node.func, ast.Name) or node.func.id != "count":
            raise UnsafeExpression("only count(...) is allowed as a call")
        if node.keywords:
            raise UnsafeExpression("count(...) takes positional args only")
        if len(node.args) != 1 or not isinstance(node.args[0], ast.Constant):
            raise UnsafeExpression("count(...) takes one string literal")
        what = node.args[0].value
        if what == "found":
            return sum(1 for h in ctx.hits if h.status == HitStatus.FOUND)
        if what == "high":
            return sum(
                1 for h in ctx.hits
                if _SEV_RANK.get(h.severity.value, 0) >= _SEV_RANK[Severity.HIGH.value]
            )
        if what == "error":
            return sum(1 for h in ctx.hits if h.status == HitStatus.ERROR)
        raise UnsafeExpression(f"count(): unknown bucket {what!r}")
    if isinstance(node, ast.Subscript):
        # Only ``hits[<int>]`` is allowed.
        if not isinstance(node.value, ast.Name) or node.value.id != "hits":
            raise UnsafeExpression("only hits[N] subscript is allowed")
        # py3.9+ — Subscript.slice is the index node directly
        idx_node = node.slice
        if not isinstance(idx_node, ast.Constant) or not isinstance(idx_node.value, int):
            raise UnsafeExpression("hits[N] index must be an integer literal")
        i = idx_node.value
        if i < 0 or i >= len(ctx.hits):
            return None
        return ctx.hits[i]
    if isinstance(node, ast.Attribute):
        obj = _eval(node.value, ctx)
        if obj is None:
            # Out-of-range hits[N] returned None — propagate as None so the
            # surrounding compare degrades to False instead of raising.
            return None
        if isinstance(obj, Hit):
            if node.attr not in _ALLOWED_HIT_FIELDS:
                raise UnsafeExpression(f"hit attr {node.attr!r} not allowed")
            return _hit_field(obj, node.attr)
        raise UnsafeExpression(f"attr access on {type(obj).__name__} not allowed")
    raise UnsafeExpression(f"node {type(node).__name__} not allowed")


def eval_expr(expr: str, ctx: _ExprCtx) -> Any:
    """Evaluate ``expr`` against ``ctx`` using only the whitelisted AST nodes.

    Raises :class:`UnsafeExpression` on anything outside the DSL. Empty /
    whitespace expressions evaluate to True (matches "no when clause").
    """
    if not expr or not expr.strip():
        return True
    # Block obviously-bad strings before parsing — saves CPU on malformed input.
    if "__" in expr or "import" in expr.split():
        raise UnsafeExpression("forbidden token")
    try:
        tree = ast.parse(expr.strip(), mode="eval")
    except SyntaxError as exc:
        raise UnsafeExpression(f"syntax error: {exc.msg}") from exc
    return _eval(tree, ctx)


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class StepResult:
    step_id: str
    run: str
    skipped: bool
    skipped_reason: str = ""
    result: QueryResult | None = None


@dataclass(slots=True)
class PlaybookResult:
    playbook_id: str
    target: str
    kind: str
    steps: list[StepResult] = field(default_factory=list)

    @property
    def all_hits(self) -> list[Hit]:
        out: list[Hit] = []
        for s in self.steps:
            if s.result is not None:
                out.extend(s.result.hits)
        return out


def _resolve_run_target(
    spec: str, ctx: _ExprCtx
) -> tuple[QueryKind | None, str | None]:
    """Evaluate a ``target_from`` expression and split into (kind, value).

    Returns (None, None) if the expression evaluates to something we can't
    use (e.g. an empty URL). The caller will then SKIP the step.
    """
    val = eval_expr(spec, ctx)
    if not val:
        return None, None
    if isinstance(val, Hit):
        # Default to that hit's URL, but fall back to any host-bearing field so
        # a urlless FOUND hit (e.g. domain.py's `DNS:A` hits, which set title
        # but no url) doesn't silently skip the step.
        return None, (val.url or val.title or val.source or None)
    if isinstance(val, str):
        return None, val
    return None, None


def _infer_kind_from_value(v: str) -> QueryKind:
    # Single canonical inference lives in app.core.infer; importing it (not
    # cli.py) avoids the CLI/feature layering inversion + import cycle.
    from app.core.infer import infer_kind  # local import keeps load cheap
    return infer_kind(v) or QueryKind.USERNAME


async def run_playbook(
    db: Database | None,
    pb: Playbook,
    target: str,
    *,
    kind: QueryKind | None = None,
    runner: Runner | None = None,
    on_event: Callable[[str, str], None] | None = None,
    agent_runner: Callable[[Query], Awaitable[QueryResult]] | None = None,
) -> PlaybookResult:
    """Execute a playbook. ``db`` is optional — when set, each step's
    QueryResult is persisted via ``db.save_result`` so it shows up in
    ``osint diff`` and the graph.

    ``agent_runner`` is the hook used when a step says ``run: agent`` — by
    default we lazily import the agent loop. Tests can pass a stub.
    """
    if kind is None:
        kind = _infer_kind_from_value(target)
    r = runner or _default_runner()
    initial_query = Query(kind=kind, value=target)
    pb_result = PlaybookResult(playbook_id=pb.id, target=target, kind=kind.value)
    cumulative_hits: list[Hit] = []

    def _emit(level: str, msg: str) -> None:
        if on_event is not None:
            try:
                on_event(level, msg)
            except Exception:
                pass

    for step in pb.steps:
        ctx = _ExprCtx(kind=kind.value, hits=list(cumulative_hits))
        # Evaluate `when`
        if step.when:
            try:
                cond = bool(eval_expr(step.when, ctx))
            except UnsafeExpression as exc:
                pb_result.steps.append(StepResult(
                    step_id=step.id, run=step.run, skipped=True,
                    skipped_reason=f"unsafe when: {exc}",
                ))
                _emit("error", f"step {step.id}: bad when expression: {exc}")
                continue
            if not cond:
                pb_result.steps.append(StepResult(
                    step_id=step.id, run=step.run, skipped=True,
                    skipped_reason="when=false",
                ))
                _emit("info", f"step {step.id}: skipped (when=false)")
                continue

        # Resolve target (target_from overrides)
        step_query: Query
        if step.target_from:
            try:
                _, new_target = _resolve_run_target(step.target_from, ctx)
            except UnsafeExpression as exc:
                pb_result.steps.append(StepResult(
                    step_id=step.id, run=step.run, skipped=True,
                    skipped_reason=f"unsafe target_from: {exc}",
                ))
                _emit("error", f"step {step.id}: bad target_from: {exc}")
                continue
            if not new_target:
                pb_result.steps.append(StepResult(
                    step_id=step.id, run=step.run, skipped=True,
                    skipped_reason="target_from empty",
                ))
                _emit("info", f"step {step.id}: skipped (target_from empty)")
                continue
            step_query = Query(kind=_infer_kind_from_value(new_target), value=new_target)
        else:
            step_query = Query(kind=initial_query.kind, value=initial_query.value)

        # Execute
        if step.run == "agent":
            if agent_runner is None:
                # Lazy import to avoid pulling LLM provider at module load
                from app.features.agent import AgentLoop

                async def _default_agent(q: Query) -> QueryResult:
                    loop = AgentLoop()
                    ar = await loop.run(q, max_steps=4, max_tokens=2000, approve=None)
                    return QueryResult(query=q, hits=list(ar.hits))

                agent_runner = _default_agent
            _emit("info", f"step {step.id}: agent({step_query.value})")
            try:
                qr = await agent_runner(step_query)
            except Exception as exc:
                pb_result.steps.append(StepResult(
                    step_id=step.id, run=step.run, skipped=True,
                    skipped_reason=f"agent failed: {exc}",
                ))
                _emit("error", f"step {step.id}: agent failed: {exc}")
                continue
        elif step.run in PROFILES:
            try:
                enabled, _ = apply_profile(r, step.run)
            except ValueError as exc:
                pb_result.steps.append(StepResult(
                    step_id=step.id, run=step.run, skipped=True,
                    skipped_reason=f"profile error: {exc}",
                ))
                _emit("error", f"step {step.id}: {exc}")
                continue
            _emit("info", f"step {step.id}: profile={step.run} target={step_query.value}")
            # Per-run scope so a concurrent run on the shared Runner can't change
            # this step's module set mid-flight.
            qr = await r.run(step_query, modules=frozenset(enabled))
        else:
            # Treat ``run`` as a single module name. Scope the run to just it.
            mods = {m.name for m in r.all_modules()}
            if step.run not in mods:
                pb_result.steps.append(StepResult(
                    step_id=step.id, run=step.run, skipped=True,
                    skipped_reason=f"unknown profile/module {step.run!r}",
                ))
                _emit("error", f"step {step.id}: unknown {step.run!r}")
                continue
            _emit("info", f"step {step.id}: module={step.run} target={step_query.value}")
            qr = await r.run(step_query, modules=frozenset({step.run}))

        cumulative_hits.extend(qr.hits)
        if db is not None:
            try:
                await db.save_result(qr)
            except Exception as exc:
                _emit("error", f"step {step.id}: save failed: {exc}")
        pb_result.steps.append(StepResult(
            step_id=step.id, run=step.run, skipped=False, result=qr,
        ))

    return pb_result


# ---------------------------------------------------------------------------
# CLI dispatch — `osint playbook ...`
# ---------------------------------------------------------------------------


def cmd_playbook(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage: osint playbook <list|run> [opts]\n\n"
            "  list                  show loaded playbooks\n"
            "  run <id> <target> [--case SLUG]\n"
            "                        run playbook against target; attach to case if --case",
            file=sys.stderr,
        )
        return 0 if argv else 2

    sub = argv[0]

    if sub == "list":
        books = load_playbooks()
        if not books:
            print("  (no playbooks loaded)")
            return 0
        print()
        print(f"  {'ID':<24} {'NAME':<32}  STEPS")
        print("  " + "─" * 64)
        for b in books:
            print(f"  {b.id:<24} {b.name[:32]:<32}  {len(b.steps)}")
        print()
        return 0

    if sub == "run":
        if len(argv) < 3:
            print("usage: osint playbook run <id> <target> [--case SLUG]", file=sys.stderr)
            return 2
        pb_id = argv[1]
        target = argv[2]
        rest = argv[3:]
        case_slug: str | None = None
        i = 0
        while i < len(rest):
            if rest[i] == "--case" and i + 1 < len(rest):
                case_slug = rest[i + 1]; i += 2; continue
            i += 1

        async def _run() -> int:
            from app.core.config import load_settings, settings
            from app.features import cases as cases_mod
            load_settings()
            books = {b.id: b for b in load_playbooks()}
            pb = books.get(pb_id)
            if pb is None:
                print(f"  no playbook {pb_id!r}", file=sys.stderr)
                return 1
            db = Database(settings().db_path)
            await db.connect()
            try:
                case_obj = None
                if case_slug:
                    case_obj = await cases_mod.get(db, case_slug)
                    if case_obj is None:
                        print(f"  case {case_slug!r} not found", file=sys.stderr)
                        return 1

                def _emit(level: str, msg: str) -> None:
                    prefix = "  ! " if level == "error" else "  · "
                    print(prefix + msg, file=sys.stderr)

                pb_result = await run_playbook(
                    db, pb, target, on_event=_emit,
                )
                # When --case, attach every executed step's QueryResult.
                if case_obj is not None:
                    for sr in pb_result.steps:
                        if sr.skipped or sr.result is None:
                            continue
                        await case_obj.attach_run(db, sr.result, profile=sr.run)
                # Summary
                n_run = sum(1 for s in pb_result.steps if not s.skipped)
                n_skip = sum(1 for s in pb_result.steps if s.skipped)
                print(
                    f"  playbook {pb.id} done: {n_run} step(s) ran, "
                    f"{n_skip} skipped, "
                    f"{sum(1 for h in pb_result.all_hits if h.status == HitStatus.FOUND)} positive hit(s)"
                )
                return 0
            finally:
                await db.close()

        return asyncio.run(_run())

    print(f"unknown playbook subcommand: {sub!r}", file=sys.stderr)
    return 2
