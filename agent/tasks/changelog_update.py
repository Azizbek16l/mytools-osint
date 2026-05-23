"""Sync CHANGELOG.md `[Unreleased]` section with commits since the last tag.

Deterministic — no LLM needed. Groups commits by conventional-prefix
(feat:/fix:/ui:/docs:/chore: …) and writes them as bullet lines. Idempotent:
if every commit since the last tag is already in [Unreleased], nothing
changes and the task exits clean.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHANGELOG = ROOT / "CHANGELOG.md"

PREFIX_TO_HEADING = {
    "feat":  "### Added",
    "add":   "### Added",
    "fix":   "### Fixed",
    "ui":    "### Changed",
    "data":  "### Changed",
    "perf":  "### Changed",
    "refactor": "### Changed",
    "docs":  "### Docs",
    "chore": "### Chores",
    "ci":    "### Chores",
    "test":  "### Chores",
    "release": None,  # skip release-bump commits
}


def _last_tag() -> str | None:
    try:
        r = subprocess.run(["git", "describe", "--tags", "--abbrev=0"],
                           cwd=ROOT, capture_output=True, text=True, check=True)
        return r.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def _commits_since(ref: str | None) -> list[tuple[str, str]]:
    cmd = ["git", "log", "--pretty=format:%H %s"]
    if ref:
        cmd.append(f"{ref}..HEAD")
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True)
    out: list[tuple[str, str]] = []
    for line in (r.stdout or "").splitlines():
        sha, _, msg = line.partition(" ")
        if not sha:
            continue
        out.append((sha[:7], msg.strip()))
    return out


def _group(commits: list[tuple[str, str]]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for sha, msg in commits:
        m = re.match(r"^([a-z]+)(?:\([^)]+\))?:\s*(.+)$", msg)
        if m:
            heading = PREFIX_TO_HEADING.get(m.group(1).lower(), "### Changed")
        else:
            heading = "### Changed"
        if heading is None:
            continue
        grouped.setdefault(heading, []).append(f"- {msg} (`{sha}`)")
    return grouped


async def run() -> str:
    if not CHANGELOG.exists():
        return "CHANGELOG.md missing — nothing to do"
    tag = _last_tag()
    commits = _commits_since(tag)
    if not commits:
        return f"no commits since {tag or 'genesis'}"
    grouped = _group(commits)
    if not grouped:
        return f"{len(commits)} commits since {tag} but none worth recording"

    body = ["## [Unreleased]\n"]
    for heading in ("### Added", "### Changed", "### Fixed", "### Docs", "### Chores"):
        items = grouped.get(heading) or []
        if not items:
            continue
        body.append(heading)
        body.extend(items)
        body.append("")

    existing = CHANGELOG.read_text(encoding="utf-8")
    # Replace the existing [Unreleased] block with the regenerated one
    pattern = re.compile(r"## \[Unreleased\][\s\S]*?(?=\n## \[)", re.MULTILINE)
    new_block = "\n".join(body) + "\n"
    if pattern.search(existing):
        new_content = pattern.sub(new_block, existing)
    else:
        new_content = re.sub(r"^# Changelog.*?\n", lambda m: m.group(0) + "\n" + new_block,
                             existing, count=1, flags=re.MULTILINE)
    if new_content == existing:
        return "CHANGELOG already in sync"
    CHANGELOG.write_text(new_content, encoding="utf-8")
    return f"updated CHANGELOG with {len(commits)} commit(s) since {tag or 'genesis'}"
