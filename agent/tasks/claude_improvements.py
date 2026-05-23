"""LLM-driven improvement proposer via the Claude Code Agent SDK.

This task uses the user's already-logged-in **Claude Code subscription** (OAuth
token persisted by `claude login` on the local machine). No API key, no per-call
billing — usage counts against the user's Claude Code Pro/Max plan quota.

Required environment for this task to engage:
  - `claude` CLI installed locally (`npm install -g @anthropic-ai/claude-code`
    or via the official installer)
  - OAuth completed (`claude login` succeeded; token under
    ~/.claude / %USERPROFILE%/.claude)
  - `claude-agent-sdk` Python package installed (`pip install claude-agent-sdk`)

If any of the above is missing, the task **skips silently** (returns "skipped").
It will never crash the daily run.

Designed to run on the user's own machine (rootpc, Mac, …) — NOT on shared GH
Actions runners, because the OAuth credentials live on disk and shouldn't leave
the host.

Output:
  Proposals are written to `agent/data/proposals/YYYYMMDD-HHMMSS-<topic>.md`.
  The agent never edits source files directly. A human reviews and applies.
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
You are reviewing the mytools-osint codebase for ONE small, low-risk improvement \
that could be merged today. Focus on:

  • a regex that's loose enough to false-positive on a known site signature,
  • an HTTP/network module that could benefit from a smarter retry on a
    specific transient HTTP code,
  • a missing edge case in a parser (IPv6 host, IDN, multi-byte UTF-8),
  • a docstring that misrepresents what the code actually does,
  • a redundancy across modules that could be lifted into app/core/.

Constraints:

  • Output ONE proposal at most. If you don't see a confident one, write
    exactly "NO IMPROVEMENT" and stop.
  • Include the file path, the change rationale, and a unified diff or a
    replacement function. Keep diff under 30 lines.
  • Do NOT propose anything that adds a new dependency.
  • Do NOT propose anything that breaks the public CLI flags or the Hit/
    QueryResult schema.

Format your answer as markdown with sections:
  ## Target file
  ## Rationale (under 80 words)
  ## Diff
"""


def _claude_cli_available() -> bool:
    return shutil.which("claude") is not None


async def run() -> str:
    if os.environ.get("BLUETM_AGENT_SKIP_CLAUDE") == "1":
        return "skipped (BLUETM_AGENT_SKIP_CLAUDE=1)"
    # Path 1: Use the official Claude Code Agent SDK if installed.
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query  # type: ignore
        return await _via_sdk(query, ClaudeAgentOptions)
    except ImportError:
        pass

    # Path 2: Fall back to the `claude` CLI in non-interactive mode if installed
    # and OAuth is already done.
    if _claude_cli_available():
        return await _via_cli()

    return "claude SDK + CLI both unavailable — skipped"


async def _via_sdk(query, ClaudeAgentOptions) -> str:                # noqa: N803
    """claude-agent-sdk (https://github.com/anthropics/claude-agent-sdk-python)."""
    options = ClaudeAgentOptions(
        cwd=str(ROOT),
        permission_mode="bypassPermissions",   # read-only review — no tool use
        max_turns=1,
    )
    out_parts: list[str] = []
    async for msg in query(prompt=PROMPT, options=options):
        # Each message carries .content list. Concat any text blocks.
        for block in getattr(msg, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                out_parts.append(text)
    body = "".join(out_parts).strip()
    return _persist(body, source="claude-agent-sdk")


async def _via_cli() -> str:
    """Run via `claude -p '<prompt>'` (one-shot, OAuth-backed)."""
    try:
        r = subprocess.run(
            ["claude", "-p", PROMPT, "--output-format", "text"],
            capture_output=True, text=True, timeout=180, cwd=ROOT,
        )
    except subprocess.TimeoutExpired:
        return "claude CLI timed out"
    except Exception as e:
        return f"claude CLI crash: {type(e).__name__}: {e}"
    if r.returncode != 0:
        return f"claude CLI failed (code {r.returncode}): {(r.stderr or '')[:150]}"
    return _persist(r.stdout.strip(), source="claude-cli")


def _persist(body: str, source: str) -> str:
    if not body or "NO IMPROVEMENT" in body.upper():
        return f"{source}: no confident proposal"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    # Pull topic from first heading or filename mention if present
    topic = "review"
    for line in body.splitlines()[:6]:
        if "Target file" in line or "## " in line:
            topic = (line.replace("#", "").replace("Target file", "")
                     .strip(":, *_")
                     .split("/")[-1]
                     .split(".")[0]
                     or "review")
            break
    out_file = OUT_DIR / f"{ts}-{topic}.md"
    out_file.write_text(
        f"# Bluetm Agent · LLM proposal\n\n"
        f"_Generated by {source} at {ts}_\n\n"
        f"---\n\n{body}\n",
        encoding="utf-8",
    )
    return f"{source}: proposal saved -> {out_file.relative_to(ROOT)}"
