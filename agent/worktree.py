"""Worktree isolation — the agent never touches the main checkout.

The single biggest operational risk in a daily code-modification agent is
clobbering uncommitted work the user left on the main checkout. Replit's 2025
incident is the canonical case: agent had write access to a real database
during a code freeze, made destructive changes, then fabricated cover-up
records.

For us the equivalent is: user goes to bed mid-refactor with dirty files,
03:00 cron fires, agent edits + commits over them. Solution: spawn a sibling
git worktree, do all work there, push the branch, never go near the main
checkout's working tree.

This module gives `claude_improvements.py` a context-manager-like helper:

    with isolated_worktree() as wt:
        wt.run_agent_in(...)
        wt.push_branch_if_ok(...)

On exit, the worktree is removed regardless of outcome. The branch lives in
the remote (or local refs) but the on-disk worktree is ephemeral.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

MAIN_REPO = Path(__file__).resolve().parents[1]


class Worktree:
    """Manages a sibling git worktree for the agent's run."""

    def __init__(self, branch: str) -> None:
        self.branch = branch
        self.dir: Path | None = None

    def __enter__(self) -> Worktree:
        self.dir = Path(tempfile.mkdtemp(prefix="bluetm-agent-wt-"))
        # `git worktree add` creates the directory; clean it first.
        self.dir.rmdir()
        try:
            subprocess.run(
                ["git", "worktree", "add", "-B", self.branch, str(self.dir), "HEAD"],
                check=True, cwd=MAIN_REPO, capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"git worktree add failed: {e.stderr}") from e
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.dir and self.dir.exists():
            # Detach the worktree and remove the directory.
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(self.dir)],
                cwd=MAIN_REPO, capture_output=True, text=True, check=False,
            )
            shutil.rmtree(self.dir, ignore_errors=True)

    def run(self, cmd: list[str], **kw) -> subprocess.CompletedProcess:
        assert self.dir is not None, "Worktree not entered"
        return subprocess.run(cmd, cwd=self.dir, capture_output=True, text=True, **kw)


def default_branch() -> str:
    return f"agent/upgrade-{datetime.now(UTC).strftime('%Y-%m-%d')}"
