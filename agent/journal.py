"""Episodic JSONL memory — what was tried, what shipped, what was rejected.

Read by `claude_improvements.py` at the top of each daily run so the agent's
prompt includes recent outcomes — kills the "rejection blindness" failure mode
documented in Sweep.dev's 2024 post-mortem.

Append-only single file `agent/data/journal.jsonl`. Each line is one event:

  {ts, event, summary, outcome, files_touched, rationale, sha, branch}

Events:
  proposed   — claude wrote a diff (not yet committed)
  shipped    — diff passed all gates and was pushed
  reverted   — diff failed a gate; git restore done
  pr_closed  — a previous agent PR was closed without merge (with reason)
  pr_merged  — a previous agent PR was merged (success signal)
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JOURNAL = ROOT / "agent" / "data" / "journal.jsonl"


def append(event: str, **kwargs) -> None:
    JOURNAL.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ts": datetime.now(UTC).isoformat(),
        "event": event,
        **kwargs,
    }
    with JOURNAL.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")


def recent(days: int = 30, max_entries: int = 80) -> list[dict]:
    """Return the last N entries (newest last) within `days`."""
    if not JOURNAL.exists():
        return []
    cutoff = datetime.now(UTC).timestamp() - days * 86400
    out: list[dict] = []
    for line in JOURNAL.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
            ts = datetime.fromisoformat(row.get("ts", "")).timestamp()
            if ts >= cutoff:
                out.append(row)
        except Exception:
            continue
    return out[-max_entries:]


def summary_for_prompt(days: int = 30) -> str:
    """Compact markdown summary suitable for inclusion in the agent prompt.

    Caps at ~2500 chars so it doesn't blow the model's context budget.
    Groups by event for legibility.
    """
    rows = recent(days=days)
    if not rows:
        return "_journal empty (first run or recently cleared)_"

    shipped = [r for r in rows if r["event"] == "shipped"]
    reverted = [r for r in rows if r["event"] == "reverted"]
    closed = [r for r in rows if r["event"] == "pr_closed"]
    merged = [r for r in rows if r["event"] == "pr_merged"]

    lines: list[str] = []
    if merged:
        lines.append(f"## Recently MERGED ({len(merged)}) — these directions worked")
        for r in merged[-5:]:
            lines.append(f"- {r.get('summary', '?')}  (`{r.get('sha', '')[:7]}`)")
        lines.append("")
    if closed:
        lines.append(f"## Recently CLOSED-WITHOUT-MERGE ({len(closed)}) — avoid these")
        for r in closed[-8:]:
            why = r.get("rationale") or "no reason recorded"
            lines.append(f"- {r.get('summary', '?')} — closed because: {why[:160]}")
        lines.append("")
    if reverted:
        lines.append(f"## Recently REVERTED ({len(reverted)}) — gate failures")
        for r in reverted[-8:]:
            why = r.get("outcome") or "unknown gate"
            lines.append(f"- {r.get('summary', '?')[:100]} — {why}")
        lines.append("")
    if shipped:
        lines.append(f"## Recently SHIPPED but not yet reviewed ({len(shipped)})")
        for r in shipped[-5:]:
            lines.append(f"- {r.get('summary', '?')}  ({r.get('branch', '?')})")
        lines.append("")

    md = "\n".join(lines)
    if len(md) > 2500:
        md = md[:2400] + "\n…(truncated)"
    return md
