"""Entry point — runs all daily tasks in order, best-effort.

A single task failure does not stop the others. Each task is responsible for
its own logging, retries, and side-effect persistence (PR, issue, channel
post). The runner just sequences them and reports a summary at the end.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import traceback
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# repo root on sys.path so `import app`, `import agent.tasks.*` works
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agent.tasks import (  # noqa: E402
    badge_update,
    canary_probe,
    changelog_update,
    claude_improvements,
    issue_triage,
    ollama_improvements,
    sync_datasets,
    telegram_announce,
)


@dataclass
class TaskOutcome:
    name: str
    ok: bool
    duration_s: float
    summary: str
    error: str = ""


@dataclass
class RunSummary:
    started_at: datetime
    outcomes: list[TaskOutcome] = field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return sum(1 for o in self.outcomes if o.ok)

    @property
    def fail_count(self) -> int:
        return sum(1 for o in self.outcomes if not o.ok)


TASKS: dict[str, Callable[[], Awaitable[str]]] = {
    "sync_datasets":      sync_datasets.run,
    "canary_probe":       canary_probe.run,
    "changelog_update":   changelog_update.run,
    "telegram_announce":   telegram_announce.run,
    "badge_update":        badge_update.run,
    "issue_triage":        issue_triage.run,
    # Use the user's Claude Code subscription (OAuth-backed, no extra cost).
    # Falls back to Ollama if the SDK / CLI aren't installed.
    "claude_improvements": claude_improvements.run,
    "ollama_improvements": ollama_improvements.run,
}


async def _run_one(name: str, fn: Callable[[], Awaitable[str]]) -> TaskOutcome:
    started = datetime.now(UTC)
    try:
        summary = await asyncio.wait_for(fn(), timeout=600)
        ok = True
        err = ""
    except TimeoutError:
        summary, ok, err = "timed out (10 min)", False, "TimeoutError"
    except Exception as e:
        summary, ok, err = f"crashed: {e}", False, traceback.format_exc()[:2000]
    return TaskOutcome(
        name=name, ok=ok,
        duration_s=(datetime.now(UTC) - started).total_seconds(),
        summary=summary, error=err,
    )


def _print_outcome(o: TaskOutcome) -> None:
    mark = "OK " if o.ok else "FAIL"
    print(f"[{mark}] {o.name:24} {o.duration_s:6.1f}s  {o.summary}", flush=True)
    if o.error:
        print(o.error, flush=True)


async def main(only: list[str] | None = None) -> int:
    print(f"Bluetm Agent — run started at {datetime.now(UTC).isoformat()}",
          flush=True)
    summary = RunSummary(started_at=datetime.now(UTC))
    names = only if only else list(TASKS.keys())
    for name in names:
        fn = TASKS.get(name)
        if fn is None:
            print(f"[SKIP] {name}: unknown task", flush=True)
            continue
        outcome = await _run_one(name, fn)
        summary.outcomes.append(outcome)
        _print_outcome(outcome)
    print("", flush=True)
    print(f"DONE  ok={summary.ok_count}  fail={summary.fail_count}  "
          f"total_tasks={len(summary.outcomes)}", flush=True)
    return 0 if summary.fail_count == 0 else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", action="append",
                    help="run only this task (repeatable)")
    args = ap.parse_args()
    raise SystemExit(asyncio.run(main(only=args.task)))
