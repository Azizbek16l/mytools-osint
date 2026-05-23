"""Pull Sherlock + WhatsMyName and open a PR if data/sites.json grew.

Idempotent — if nothing changed, exits with 'no new sites' and never touches
git. When changes exist, commits to a fresh branch and opens a PR via `gh`.
"""
from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITES = ROOT / "data" / "sites.json"


def _count_sites() -> int:
    if not SITES.exists():
        return 0
    return len(json.loads(SITES.read_text(encoding="utf-8")).get("sites", []))


def _run_script(name: str) -> str:
    """Run a script and return its last line of output (or error message)."""
    try:
        r = subprocess.run(
            ["python", str(ROOT / "scripts" / name)],
            cwd=ROOT, capture_output=True, text=True, timeout=180,
        )
        last = (r.stdout or "").strip().splitlines()[-1:] or [""]
        return last[0] if r.returncode == 0 else f"failed: {r.stderr.strip()[:120]}"
    except subprocess.TimeoutExpired:
        return "timeout"
    except FileNotFoundError:
        return "script missing"


async def run() -> str:
    before = _count_sites()
    out_a = _run_script("sync_sherlock.py")
    out_b = _run_script("sync_whatsmyname.py")
    after = _count_sites()
    delta = after - before
    if delta <= 0:
        return f"no new sites  (sherlock: {out_a}; whatsmyname: {out_b})"

    # Open a PR via gh if we're in CI
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return f"+{delta} sites locally  (sherlock: {out_a}; whatsmyname: {out_b})"
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    branch = f"agent/sites-sync-{today}"
    try:
        subprocess.run(["git", "config", "user.name",
                        "Bluetm Agent"], check=True, cwd=ROOT)
        subprocess.run(["git", "config", "user.email",
                        "agent@bluetm.uz"], check=True, cwd=ROOT)
        subprocess.run(["git", "checkout", "-B", branch], check=True, cwd=ROOT)
        subprocess.run(["git", "add", "data/sites.json"], check=True, cwd=ROOT)
        subprocess.run(["git", "commit", "-m",
                        f"data: sync sites.json (+{delta} entries)"],
                       check=True, cwd=ROOT)
        subprocess.run(["git", "push", "-u", "origin", branch], check=True, cwd=ROOT)
        subprocess.run([
            "gh", "pr", "create", "--title",
            f"data: sync sites.json (+{delta} entries)",
            "--body",
            f"Automated daily sync from upstream Sherlock + WhatsMyName.\n"
            f"\n* before: {before}\n* after: {after}\n* delta: +{delta}\n",
        ], check=True, cwd=ROOT)
        return f"opened PR with +{delta} sites"
    except subprocess.CalledProcessError as e:
        return f"PR creation failed: {e}"
