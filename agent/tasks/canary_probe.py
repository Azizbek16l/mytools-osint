"""Daily canary — probe ~10 well-known public profiles. If a site that used
to return FOUND now returns NOT_FOUND, we file a GitHub issue: a site signature
likely needs an update.

Uses the same Runner the real tool uses, so a passing canary actually proves
the tool works end-to-end against real network.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from app.core.config import load_settings
from app.core.http import close_client
from app.core.runner import runner
from app.core.types import HitStatus, Query, QueryKind

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_FILE = ROOT / "agent" / "data" / "canary_expectations.json"

# Known-good public profiles. If any of these stop reporting FOUND on the
# expected sites, the site signature likely broke and we file an issue.
CANARIES: list[tuple[QueryKind, str, set[str]]] = [
    (QueryKind.USERNAME, "torvalds",    {"GitHub", "GitLab", "Keybase"}),
    (QueryKind.USERNAME, "durov",       {"GitHub", "Telegram (web)"}),
    (QueryKind.USERNAME, "octocat",     {"GitHub"}),
    (QueryKind.DOMAIN,   "github.com",  {"DNS:A", "DNS:NS"}),
    (QueryKind.DOMAIN,   "cloudflare.com", {"DNS:A", "DNS:NS"}),
    (QueryKind.IP,       "1.1.1.1",     {"rDNS"}),
    (QueryKind.IP,       "8.8.8.8",     {"rDNS"}),
]


async def run() -> str:
    load_settings()
    r = runner()
    regressions: list[str] = []
    summary_lines: list[str] = []
    for kind, value, expected in CANARIES:
        q = Query(kind=kind, value=value)
        try:
            res = await r.run(q)
        except Exception as e:
            regressions.append(f"{kind.value}:{value} crashed: {e}")
            continue
        seen_sources = {h.source for h in res.hits if h.status == HitStatus.FOUND}
        missing = expected - seen_sources
        if missing:
            regressions.append(
                f"{kind.value}:{value} missing {sorted(missing)} "
                f"(got {len(seen_sources)} positives)"
            )
        summary_lines.append(
            f"{kind.value:10} {value:20} {len(seen_sources):>3}/{len(res.hits):>3} "
            f"positives  missing={sorted(missing) if missing else '-'}"
        )
    await close_client()

    # Persist the run for trend analysis
    EXPECTED_FILE.parent.mkdir(parents=True, exist_ok=True)
    EXPECTED_FILE.write_text(
        json.dumps({"summary": summary_lines, "regressions": regressions},
                   indent=2),
        encoding="utf-8",
    )

    if not regressions:
        return f"all {len(CANARIES)} canaries green"

    # File a GitHub issue if running under CI
    if os.environ.get("GITHUB_ACTIONS") == "true":
        try:
            body = ("Automated canary probe detected regressions:\n\n"
                    + "\n".join(f"- {r}" for r in regressions)
                    + "\n\nFull canary log:\n```\n"
                    + "\n".join(summary_lines)
                    + "\n```\n")
            subprocess.run([
                "gh", "issue", "create",
                "--title", f"canary: {len(regressions)} site(s) regressed",
                "--body", body,
                "--label", "canary,automated",
            ], cwd=ROOT, check=False)
        except Exception:
            pass
    return f"{len(regressions)} regression(s) detected"
