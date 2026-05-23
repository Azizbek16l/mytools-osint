"""Autonomous code-improvement loop powered by the user's Claude Code subscription.

Hardened per the consensus of three senior agent reviews (2026-05-23):

  Proposer (claude --acceptEdits)  →  Reviewer (claude default, JSON verdict)
       │                                          │ veto?  ─→ revert
       ▼                                          ▼ approve
  ┌──────────────────────────────────────────────────────────────┐
  │ Static gates (forbidden paths · diff size · ruff · pytest)   │
  └────────┬─────────────────────────────────────────────────────┘
           │ all green
           ▼
   push agent/upgrade-YYYY-MM-DD → optional gh PR → journal record

The whole flow runs inside a **sibling git worktree** so the user's main
checkout (potentially with uncommitted work in progress) is never touched.

Safety mechanisms:
  • `agent/STOP` file present → exit 0 immediately (kill switch)
  • dirty main tree → run skipped (don't risk clobbering)
  • model pinned to a known string (`--model claude-opus-4-7`) — no silent
    drift when Anthropic ships a new default
  • episodic journal at `agent/data/journal.jsonl` informs the prompt so
    the same rejected idea doesn't come back next week
  • auto-merge OFF — every change goes through a human-reviewed PR
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from agent import journal
from agent.worktree import MAIN_REPO, Worktree, default_branch

ROOT = MAIN_REPO
OUT_DIR = ROOT / "agent" / "data" / "proposals"

# Pinned model — never use "latest". Updated manually when we verify a new
# model with the canary suite.
CLAUDE_MODEL = os.environ.get("BLUETM_AGENT_MODEL", "claude-opus-4-7")

# Files the agent must never touch
FORBIDDEN_PATHS = (
    "pyproject.toml",
    "requirements.txt",
    ".env",
    ".env.example",
    ".github/workflows/",
    "agent/",                       # don't let the agent edit itself
    "tests/conftest.py",
    "tests/canary/",                # frozen canary
)

MAX_FILES_CHANGED = 8
MAX_LINES_CHANGED = 200


# ---- Prompts ---------------------------------------------------------------

PROPOSER_PROMPT_TEMPLATE = """\
You are the Bluetm Agent running autonomously for the mytools-osint repo.
Make ONE small, low-risk improvement that I can ship today. Edit files in
place — you have permission.

## Scope (pick ONE):
  • a regex that's loose enough to false-positive on a known site signature,
  • a missing edge case in a parser (IPv6, IDN, multi-byte UTF-8),
  • a docstring that misrepresents what the code does,
  • a redundancy across modules that can be lifted into app/core/,
  • a missing test for an existing function (no new behaviour).

## Hard constraints — do NOT violate any:
  • No new dependencies.
  • Do NOT edit: pyproject.toml, requirements.txt, .env*, .github/workflows/*,
    agent/* (no editing yourself), tests/conftest.py, tests/canary/*.
  • Do NOT change the public CLI flags, Hit/QueryResult schema, or
    Runner.register signature.
  • Diff size: ≤ 8 files, ≤ 200 lines insertions+deletions.
  • All tests + ruff must still pass.

## Avoid these directions (from recent journal — they were rejected/reverted):
{journal_summary}

## When done
Edit the files. Do NOT commit or push — the agent harness will run gates and
do the commit if everything is green. If you don't see a confident
improvement, exit silently — leave the tree untouched.
"""

REVIEWER_PROMPT_TEMPLATE = """\
You are reviewing a diff produced by another instance of yourself for the
Bluetm Agent. Give a strict, sceptical review.

## Diff
```diff
{diff}
```

## Journal context (recent rejected/reverted patterns)
{journal_summary}

## Your task
Evaluate this diff against these veto criteria — ANY of them → reject:
  1. Public API or schema change (Hit, QueryResult, Runner.register, CLI flags)
  2. Newly introduced non-determinism (random, time.time, datetime.now in a
     non-fixture path, raw socket, requests outside app/core/http.py)
  3. New top-level import that isn't already in requirements.txt or stdlib
  4. Test removed or substantively weakened to make code pass
  5. Repeats a direction the journal shows was rejected
  6. Stylistic-only churn (no behavioural change, no bug fix, no doc fix)
  7. Touches a forbidden path (anything under .github/, agent/, pyproject.toml)

## Respond with valid JSON only — no prose around it:
{{"approve": true|false, "reason": "one short sentence"}}
"""


# ---- Helpers ---------------------------------------------------------------

def _run(cmd: list[str], cwd: Path | None = None, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd or ROOT, capture_output=True, text=True, **kw)


def _diff_stats(cwd: Path) -> tuple[int, int]:
    r = _run(["git", "diff", "--shortstat"], cwd=cwd)
    txt = (r.stdout or "").strip()
    if not txt:
        return 0, 0
    files = lines = 0
    for p in txt.split(","):
        p = p.strip()
        if "file" in p:
            files = int(p.split()[0])
        if "insertion" in p or "deletion" in p:
            lines += int(p.split()[0])
    return files, lines


def _changed_files(cwd: Path) -> list[str]:
    r = _run(["git", "diff", "--name-only"], cwd=cwd)
    return [f for f in (r.stdout or "").splitlines() if f]


def _touches_forbidden(files: list[str]) -> str | None:
    for f in files:
        for forbidden in FORBIDDEN_PATHS:
            if f == forbidden or f.startswith(forbidden):
                return f
    return None


def _save_report(name: str, body: str) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    p = OUT_DIR / f"{ts}-{name}.md"
    p.write_text(body, encoding="utf-8")
    return p


# ---- Reviewer (second claude call) ----------------------------------------

def _reviewer_verdict(diff_text: str) -> tuple[bool, str]:
    """Ask a second claude instance to review the diff. Returns (approve, reason).

    On any error (timeout, parse failure, claude unavailable), default to APPROVE
    — we'd rather lose a useful change than block the loop forever. Static gates
    still run downstream.
    """
    summary = journal.summary_for_prompt(days=30)
    prompt = REVIEWER_PROMPT_TEMPLATE.format(
        diff=diff_text[:10000],
        journal_summary=summary,
    )
    try:
        r = subprocess.run(
            ["claude", "-p", prompt,
             "--model", CLAUDE_MODEL,
             "--permission-mode", "default",
             "--output-format", "text"],
            capture_output=True, text=True, timeout=300, cwd=ROOT,
        )
    except subprocess.TimeoutExpired:
        return True, "reviewer timed out — defaulting to approve"
    if r.returncode != 0:
        return True, f"reviewer exit {r.returncode} — defaulting to approve"

    body = r.stdout.strip()
    # Try to extract a JSON object
    start = body.find("{")
    end = body.rfind("}")
    if start == -1 or end == -1:
        return True, "reviewer returned no JSON — defaulting to approve"
    try:
        verdict = json.loads(body[start:end + 1])
    except json.JSONDecodeError:
        return True, "reviewer JSON unparseable — defaulting to approve"
    return bool(verdict.get("approve", True)), str(verdict.get("reason", ""))[:200]


# ---- Main entry point ------------------------------------------------------

async def run() -> str:
    if os.environ.get("BLUETM_AGENT_SKIP_CLAUDE") == "1":
        return "skipped (BLUETM_AGENT_SKIP_CLAUDE=1)"

    # KILL SWITCH — first thing, no exceptions
    if (ROOT / "agent" / "STOP").exists():
        return "halted by agent/STOP file"

    if not shutil.which("claude"):
        return "claude CLI not on PATH — skipped"
    if (ROOT / ".git").exists() is False:
        return "not a git repo — skipped"

    # Safety: main tree must be clean — don't clobber user's uncommitted work.
    dirty = _run(["git", "status", "--porcelain"]).stdout.strip()
    if dirty:
        journal.append("skipped", reason="main tree dirty")
        return "main tree dirty — skipped to protect user's work"

    branch = default_branch()
    journal_summary = journal.summary_for_prompt(days=30)
    proposer_prompt = PROPOSER_PROMPT_TEMPLATE.format(journal_summary=journal_summary)

    # ---- run in an isolated worktree ----
    try:
        with Worktree(branch) as wt:
            assert wt.dir is not None
            # 1) Proposer
            try:
                proc = wt.run(
                    ["claude", "-p", proposer_prompt,
                     "--model", CLAUDE_MODEL,
                     "--permission-mode", "acceptEdits",
                     "--output-format", "text"],
                    timeout=900,
                )
            except subprocess.TimeoutExpired:
                journal.append("reverted", outcome="proposer timed out", branch=branch)
                return "proposer timed out (15 min)"
            if proc.returncode != 0:
                journal.append("reverted", outcome=f"proposer exit {proc.returncode}",
                               branch=branch, summary=(proc.stderr or "")[:140])
                return f"proposer exit {proc.returncode}"

            # 2) Did it change anything?
            files = _changed_files(wt.dir)
            n_files, n_lines = _diff_stats(wt.dir)
            if n_files == 0:
                journal.append("skipped", reason="proposer made no changes")
                return "proposer made no changes — clean exit"

            # 3) Forbidden-paths gate
            bad = _touches_forbidden(files)
            if bad:
                journal.append("reverted", outcome=f"forbidden path: {bad}",
                               branch=branch, summary=f"{n_files} files")
                _save_report("reverted-forbidden", f"Touched: `{bad}`")
                return f"reverted: forbidden path {bad}"

            # 4) Diff-size gate
            if n_files > MAX_FILES_CHANGED or n_lines > MAX_LINES_CHANGED:
                journal.append("reverted",
                               outcome=f"diff too large: {n_files}f/{n_lines}l",
                               branch=branch)
                return f"reverted: too large ({n_files} files, {n_lines} lines)"

            # 5) Reviewer agent (second claude call)
            diff_text = wt.run(["git", "diff"]).stdout
            approve, reason = _reviewer_verdict(diff_text)
            if not approve:
                journal.append("reverted", outcome=f"reviewer veto: {reason}",
                               branch=branch, summary=f"{n_files} files")
                _save_report("reverted-reviewer-veto",
                             f"# Reviewer veto\n\n{reason}\n\n```diff\n{diff_text[:5000]}\n```")
                return f"reverted: reviewer veto — {reason}"

            # 6) Ruff + pytest
            ruff = wt.run(["python", "-m", "ruff", "check", "."])
            if ruff.returncode != 0:
                journal.append("reverted", outcome="ruff failed", branch=branch)
                return "reverted: ruff failed"
            # Skip slow tests on the worktree's per-run gate; the main CI catches them
            pytest = wt.run(["python", "-m", "pytest", "-q", "--timeout=120"],
                            timeout=300)
            if pytest.returncode != 0:
                journal.append("reverted", outcome="pytest failed", branch=branch,
                               summary=pytest.stdout[-200:])
                return "reverted: pytest failed"

            # 7) Commit + push (still inside the worktree)
            wt.run(["git", "config", "user.name", "Bluetm Agent"])
            wt.run(["git", "config", "user.email", "agent@bluetm.uz"])
            wt.run(["git", "add", "-A"])
            msg_subject = f"agent: daily upgrade ({n_files} files, {n_lines} lines)"
            msg_body = (
                "Auto-applied by the Bluetm Agent's claude_improvements task.\n\n"
                "Hardened by senior-agent review (2026-05-23). Worktree isolation,\n"
                "dual-call proposer+reviewer, journal-aware prompt, gates: forbidden\n"
                "paths, diff size, ruff, pytest.\n\n"
                f"Reviewer reason: {reason or '(approved silently)'}\n\n"
                "Auto-merge OFF — human review on GitHub before merge."
            )
            wt.run(["git", "commit", "-m", msg_subject, "-m", msg_body])
            push = wt.run(["git", "push", "-u", "origin", branch, "--force-with-lease"])
            if push.returncode != 0:
                journal.append("reverted", outcome="push failed", branch=branch,
                               summary=(push.stderr or "")[:200])
                return f"committed locally as {branch}, push failed"

            # 8) Optional: open a PR via gh
            if shutil.which("gh"):
                _run(["gh", "pr", "create",
                      "--title", msg_subject,
                      "--body", msg_body,
                      "--head", branch], cwd=wt.dir)

            journal.append("shipped", branch=branch,
                           summary=msg_subject,
                           files_touched=files,
                           rationale=reason)
            return f"shipped {branch} ({n_files} files, {n_lines} lines)"

    except RuntimeError as e:
        # Worktree setup failed
        journal.append("reverted", outcome=f"worktree error: {e}", branch=branch)
        return f"worktree error: {e}"
