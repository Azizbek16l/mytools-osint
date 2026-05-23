"""Autonomous code-improvement loop powered by the user's Claude Code subscription.

Runs locally on rootpc (NEVER in CI — OAuth token must not leave the host).
The flow:

  1. Snapshot HEAD                                 (so we can revert if needed).
  2. Ask the `claude` CLI to make ONE small improvement, with permission to
     edit files: `claude -p <prompt> --permission-mode acceptEdits ...`.
  3. Sanity-gate the result:
        - `git diff --stat` ≥ 1 file changed AND ≤ 8 files
        - `git diff --shortstat` insertions+deletions ≤ 200
        - `python -m ruff check .` exits clean
        - `python -m pytest -q` exits clean
  4. If green: create a daily branch `agent/upgrade-YYYY-MM-DD`, commit with a
     descriptive message that says "auto-improved by Claude Code · reviewed by
     the daily Bluetm Agent", push it, and (if `gh` is available) open a PR.
     **Auto-merge is OFF** — the user reviews on GitHub.
  5. If red: `git restore .` to revert and write a failure report to
     `agent/data/proposals/`. The next day's run tries again from a clean tree.

Safeguards:
  - HEAD snapshot lets us revert atomically.
  - Files we never let the LLM touch: pyproject.toml, requirements.txt, .env,
    .github/workflows/, agent/, tests/conftest.py.
  - The push is to a NEW branch — main never sees an unreviewed agent commit.
  - Subscription quota: one run per day. The prompt asks for at most 1 turn.

The user's Claude Code subscription is the LLM provider; no separate API key,
no metering, no costs visible in the GitHub repo. The OAuth token never leaves
the local host.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "agent" / "data" / "proposals"

PROMPT = """\
You are running as the autonomous Bluetm Agent for the mytools-osint repo.
Make ONE small, low-risk improvement that I can ship today. You have edit
permission — apply the change directly.

Choose from:
  - a regex that's too loose and false-positives,
  - a missing edge case in a parser (IPv6, IDN, multi-byte UTF-8),
  - a docstring that misrepresents what the code does,
  - a redundancy across modules that can be lifted into app/core/,
  - a flaky test that needs a tighter assertion or a fixture.

Hard constraints — do NOT violate any of these:
  - Do NOT add new dependencies.
  - Do NOT edit: pyproject.toml, requirements.txt, .env*, .github/workflows/*,
    agent/* (don't edit yourself), or tests/conftest.py.
  - Do NOT change the public CLI flags, the Hit / QueryResult schema, or the
    Runner.register signature.
  - Diff size: at most 8 files changed, at most 200 lines insertions+deletions.
  - All tests (`python -m pytest -q`) and ruff (`python -m ruff check .`) must
    still pass after your change. If you can't be confident, do nothing.
  - If you don't see a confident improvement, exit silently — leave the tree
    untouched.

When you're done, do NOT commit or push. The agent will do that after running
tests + lint. Just make the file edits.
"""

# Files Claude is forbidden from touching (defence in depth — the prompt asks
# but we also enforce post-hoc by reverting unwanted hunks).
FORBIDDEN_PATHS = (
    "pyproject.toml",
    "requirements.txt",
    ".env",
    ".env.example",
    ".github/workflows/",
    "agent/",
    "tests/conftest.py",
)

# How big a diff are we willing to ship today?
MAX_FILES_CHANGED = 8
MAX_LINES_CHANGED = 200


def _claude_available() -> bool:
    return shutil.which("claude") is not None


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kw)


def _diff_stats() -> tuple[int, int]:
    """Return (files_changed, lines_changed) from the current working tree."""
    r = _run(["git", "diff", "--shortstat"])
    txt = (r.stdout or "").strip()
    if not txt:
        return 0, 0
    # e.g. " 3 files changed, 17 insertions(+), 5 deletions(-)"
    parts = txt.split(",")
    files = lines = 0
    for p in parts:
        p = p.strip()
        if "file" in p:
            files = int(p.split()[0])
        if "insertion" in p or "deletion" in p:
            lines += int(p.split()[0])
    return files, lines


def _changed_files() -> list[str]:
    r = _run(["git", "diff", "--name-only"])
    return [f for f in (r.stdout or "").splitlines() if f]


def _touches_forbidden(files: list[str]) -> str | None:
    for f in files:
        for forbidden in FORBIDDEN_PATHS:
            if f == forbidden or f.startswith(forbidden):
                return f
    return None


def _revert_all() -> None:
    _run(["git", "restore", "."])
    _run(["git", "clean", "-fd"])


def _save_report(name: str, body: str) -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    p = OUT_DIR / f"{ts}-{name}.md"
    p.write_text(body, encoding="utf-8")
    return p


async def run() -> str:
    if os.environ.get("BLUETM_AGENT_SKIP_CLAUDE") == "1":
        return "skipped (BLUETM_AGENT_SKIP_CLAUDE=1)"
    if not _claude_available():
        return "claude CLI not found on PATH — skipped"

    # 1) Snapshot HEAD — only proceed if the tree is clean.
    head = _run(["git", "rev-parse", "HEAD"]).stdout.strip()
    if not head:
        return "not a git repo — skipped"
    dirty = _run(["git", "status", "--porcelain"]).stdout.strip()
    if dirty:
        return "tree dirty before run — skipped to avoid clobbering work"

    # 2) Invoke Claude Code with edit permission. acceptEdits lets it modify
    #    files without re-prompting.
    try:
        proc = _run(
            ["claude", "-p", PROMPT,
             "--permission-mode", "acceptEdits",
             "--output-format", "text"],
            timeout=900,
        )
    except subprocess.TimeoutExpired:
        _revert_all()
        return "claude timed out (15 min) — reverted"
    if proc.returncode != 0:
        _revert_all()
        return f"claude exit {proc.returncode} — reverted; stderr: {(proc.stderr or '')[:200]}"

    # 3) Did it actually change anything?
    files = _changed_files()
    n_files, n_lines = _diff_stats()
    if n_files == 0:
        return "claude made no changes — clean exit"

    # Forbidden-path check
    bad = _touches_forbidden(files)
    if bad:
        body = (
            f"# Reverted — forbidden file touched\n\n"
            f"Claude modified `{bad}` which is on the deny-list.\n"
            f"All changes reverted. Full diff (would have been):\n\n"
            f"```\n{_run(['git', 'diff']).stdout[:6000]}\n```"
        )
        _save_report("reverted-forbidden-file", body)
        _revert_all()
        return f"reverted: forbidden path {bad}"

    # Size budget
    if n_files > MAX_FILES_CHANGED or n_lines > MAX_LINES_CHANGED:
        body = (
            f"# Reverted — diff too large\n\n"
            f"{n_files} file(s), {n_lines} line(s) changed (limit "
            f"{MAX_FILES_CHANGED} files / {MAX_LINES_CHANGED} lines).\n\n"
            f"```\n{_run(['git', 'diff', '--stat']).stdout}\n```"
        )
        _save_report("reverted-too-large", body)
        _revert_all()
        return f"reverted: diff too large ({n_files} files, {n_lines} lines)"

    # 4) Ruff + pytest gates
    ruff = _run(["python", "-m", "ruff", "check", "."])
    if ruff.returncode != 0:
        _save_report("reverted-ruff-failed",
                     f"# Reverted — ruff failed\n\n```\n{ruff.stdout[:3000]}\n```")
        _revert_all()
        return "reverted: ruff failed"
    pytest = _run(["python", "-m", "pytest", "-q"], timeout=240)
    if pytest.returncode != 0:
        _save_report("reverted-pytest-failed",
                     f"# Reverted — pytest failed\n\n```\n{pytest.stdout[-3000:]}\n```")
        _revert_all()
        return "reverted: pytest failed"

    # 5) All gates green — branch, commit, push.
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    branch = f"agent/upgrade-{today}"
    _run(["git", "config", "user.name", "Bluetm Agent"])
    _run(["git", "config", "user.email", "agent@bluetm.uz"])
    _run(["git", "checkout", "-B", branch])
    msg_subject = (
        f"agent: daily upgrade ({n_files} file(s), {n_lines} lines)"
    )
    msg_body = (
        "Auto-applied by the Bluetm Agent's claude_improvements task.\n"
        "The LLM that proposed this is the user's Claude Code subscription, "
        "running locally — no API key, no extra cost.\n\n"
        "Gates that passed before this commit was created:\n"
        "  * no forbidden file touched\n"
        f"  * diff size within budget ({n_files}/{MAX_FILES_CHANGED} files, "
        f"{n_lines}/{MAX_LINES_CHANGED} lines)\n"
        "  * ruff clean\n"
        "  * pytest green\n\n"
        "Auto-merge is NOT enabled. Human review on GitHub before merge."
    )
    _run(["git", "add", "-A"])
    _run(["git", "commit", "-m", msg_subject, "-m", msg_body])
    push = _run(["git", "push", "-u", "origin", branch])
    if push.returncode != 0:
        _save_report("push-failed",
                     f"# Push failed\n\n```\n{push.stderr[:2000]}\n```\n"
                     f"Branch `{branch}` committed locally but not pushed.")
        return f"committed locally as {branch}, push failed"

    # 6) Optional: open a PR via gh
    if shutil.which("gh"):
        _run(["gh", "pr", "create", "--title", msg_subject,
              "--body", msg_body, "--head", branch])

    # Keep a record next to the proposals
    diff_text = _run(["git", "diff", f"{head}..HEAD"]).stdout
    _save_report(
        f"applied-{branch.replace('/', '-')}",
        f"# Applied — {branch}\n\n{msg_body}\n\n## Diff\n\n```\n{diff_text[:8000]}\n```",
    )
    return f"shipped {branch} ({n_files} files, {n_lines} lines)"
