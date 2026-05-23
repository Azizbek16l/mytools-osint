"""Apply deterministic labels to open GitHub issues. Best-effort, never fails
the run if `gh` isn't available or the repo has zero issues.

Rules:
  - title contains "bug" / "crash" / "error"             → bug
  - title contains "feature" / "add" / "support"         → enhancement
  - title contains "doc" / "readme" / "typo"             → docs
  - title contains "canary"                              → canary, automated
  - mentions a module name (username/email/phone/…)      → module:<name>
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

KEYWORD_LABELS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("bug", "crash", "error", "broken", "regress"),  "bug"),
    (("feature", "add", "support", "request"),         "enhancement"),
    (("doc", "readme", "typo"),                        "docs"),
    (("canary",),                                       "canary"),
    (("telegram", "mtproto"),                          "module:telegram"),
    (("email", "breach", "hibp", "holehe"),            "module:email"),
    (("phone", "whatsapp", "wa.me"),                   "module:phone"),
    (("domain", "subdomain", "crt.sh", "tls", "ssl"),  "module:domain"),
    (("ip", "asn", "bgp"),                             "module:ip"),
    (("username", "sherlock", "whatsmyname"),          "module:username"),
)


async def run() -> str:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return "not in CI — skipped"
    try:
        r = subprocess.run(
            ["gh", "issue", "list", "--state", "open",
             "--json", "number,title,labels", "--limit", "100"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
    except Exception as e:
        return f"gh list failed: {e}"
    issues = json.loads(r.stdout or "[]")
    if not issues:
        return "no open issues"
    n_labeled = 0
    for issue in issues:
        title = (issue.get("title") or "").lower()
        existing = {label["name"] for label in (issue.get("labels") or [])}
        wanted: set[str] = set()
        for keywords, label in KEYWORD_LABELS:
            if any(k in title for k in keywords):
                wanted.add(label)
        new_labels = wanted - existing
        if not new_labels:
            continue
        try:
            subprocess.run(
                ["gh", "issue", "edit", str(issue["number"]),
                 "--add-label", ",".join(sorted(new_labels))],
                cwd=ROOT, check=False,
            )
            n_labeled += 1
        except Exception:
            continue
    return f"labeled {n_labeled} issue(s)"
