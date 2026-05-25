"""AI-assisted analysis — `osint ai explain` (v4.0).

Two sub-commands:
  osint ai explain <kind> <value>
      Pulls the most recent saved scan from the DB, generates a 5-bullet
      executive summary + risk ranking using Anthropic's Claude API.

  osint ai query "find phishing infra targeting acme.com"
      Translates natural language → (profile, kind, target) and runs it.

Requirements:
  ANTHROPIC_API_KEY env var (or `osint config set ANTHROPIC_API_KEY …`).
  Optional `anthropic` package — falls back to direct HTTP if missing.

Cost-aware: uses claude-haiku-4-5 by default (cheap + fast). Bumps to
sonnet only for explain on > 50 findings.

Privacy: the analyst's hits go to Anthropic — domain names, IPs, emails
in the prompt. Document this in SECURITY.md. Skip if user is on OPSEC mode.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

from app.core.config import load_settings, settings
from app.core.db import Database
from app.core.http import _opsec_on, get_client
from app.core.types import HitStatus

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-haiku-4-5"


def _api_key() -> str:
    return os.getenv("ANTHROPIC_API_KEY", "").strip()


async def _claude(prompt: str, system: str = "", *, model: str | None = None,
                  max_tokens: int = 800) -> str:
    """One-shot call to Anthropic's /v1/messages endpoint."""
    key = _api_key()
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY unset")
    if _opsec_on():
        raise RuntimeError("AI calls are disabled while --opsec is on "
                           "(your queries go to Anthropic's servers)")
    body = {
        "model": model or DEFAULT_MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system
    client = await get_client()
    r = await client.post(
        ANTHROPIC_URL,
        json=body,
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"},
        timeout=60.0,
    )
    if r.status_code != 200:
        raise RuntimeError(f"Anthropic HTTP {r.status_code}: {r.text[:200]}")
    data = r.json()
    parts = data.get("content") or []
    return "".join(p.get("text", "") for p in parts if isinstance(p, dict))


SUMMARISE_SYSTEM = """You are a senior threat-intel analyst. The user pastes
the raw findings from a single OSINT scan. Produce a short executive summary:
  1. ONE-LINE verdict (critical/high/medium/low risk + why)
  2. Top 5 findings, ranked by impact, each ONE concise line
  3. Three concrete next-step actions for the analyst
Output as Markdown. Be direct, not vague. NO disclaimers. NO restating obvious facts."""


QUERY_SYSTEM = """You translate a natural-language threat-intel question into
a single mytools-osint CLI invocation. Output ONLY a JSON object:
  {"kind": "domain|ip|email|username|phone|telegram|hash",
   "target": "<the entity>",
   "profile": "quick|deep|person|domain-recon|red-team|blue-team|ioc|creds|leak-hunt",
   "pivot": 0|1|2}

If you cannot extract a clear target, return {"error": "..."}."""


# ---------------------------------------------------------------- CLI

async def _explain(kind: str, value: str) -> int:
    load_settings()
    db = Database(settings().db_path)
    await db.connect()
    try:
        assert db._conn is not None
        async with db._conn.execute(
            "SELECT id FROM queries WHERE kind = ? AND value = ? "
            "ORDER BY id DESC LIMIT 1",
            (kind, value),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            print(f"  no saved scan found for {kind}={value} — run it first.",
                  file=sys.stderr)
            return 1
        qid = row["id"]
        async with db._conn.execute(
            "SELECT module, source, status, severity, title, detail, url "
            "FROM hits WHERE query_id = ? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
            (qid,),
        ) as cur:
            hrows = await cur.fetchall()
        # Filter to FOUND only — most informative + cheaper
        positives = [dict(r) for r in hrows if r["status"] == "found"]
        if not positives:
            print(f"  scan has no positive findings to explain.")
            return 0
        # Compact JSON payload
        payload = json.dumps([
            {"module": h["module"], "src": h["source"],
             "sev": h["severity"], "title": h["title"],
             "detail": (h["detail"] or "")[:200],
             "url": h["url"][:160] if h["url"] else ""}
            for h in positives[:80]   # cap for cost
        ], indent=2, default=str)
        prompt = (
            f"Target: {kind}={value}\n"
            f"Findings (top {len(positives[:80])} of {len(positives)} positives):\n"
            f"```json\n{payload}\n```\n\n"
            "Summarise as instructed."
        )
        print(f"  ↻ explaining {len(positives)} findings via Claude…",
              file=sys.stderr)
        try:
            model = "claude-sonnet-4-6" if len(positives) > 50 else DEFAULT_MODEL
            text = await _claude(prompt, system=SUMMARISE_SYSTEM, model=model,
                                  max_tokens=1200)
        except Exception as e:
            print(f"  ai explain failed: {e}", file=sys.stderr)
            return 1
        print("\n" + text + "\n")
        return 0
    finally:
        await db.close()


async def _nl_query(text: str) -> int:
    try:
        raw = await _claude(text, system=QUERY_SYSTEM, max_tokens=200)
    except Exception as e:
        print(f"  ai query failed: {e}", file=sys.stderr)
        return 1
    # Extract JSON object from response
    try:
        start = raw.index("{")
        end = raw.rindex("}") + 1
        parsed = json.loads(raw[start:end])
    except Exception:
        print(f"  could not parse AI response:\n{raw}", file=sys.stderr)
        return 1
    if "error" in parsed:
        print(f"  AI declined: {parsed['error']}")
        return 1
    target = parsed.get("target", "")
    if not target:
        print("  AI returned no target", file=sys.stderr)
        return 1
    new_argv = [target]
    if parsed.get("kind"):
        new_argv += ["--kind", parsed["kind"]]
    if parsed.get("profile"):
        new_argv += ["--profile", parsed["profile"]]
    if parsed.get("pivot"):
        new_argv += ["--pivot", str(parsed["pivot"])]
    print(f"  ↻ AI translated → osint {' '.join(new_argv)}", file=sys.stderr)
    from cli import main as _main
    return _main(new_argv)


def cmd_ai(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage: osint ai <explain|query> ...\n\n"
            "  ai explain <kind> <value>      — summarise most recent saved scan\n"
            "  ai query \"natural-language\"  — translate to osint args + run\n\n"
            "  Requires ANTHROPIC_API_KEY. Free $5 credit covers ~1000 explains.\n"
            "  Disabled when --opsec is active (queries go off-host).",
            file=sys.stderr,
        )
        return 0 if argv else 2
    sub = argv[0]
    if sub == "explain" and len(argv) >= 3:
        return asyncio.run(_explain(argv[1], argv[2]))
    if sub == "query" and len(argv) >= 2:
        return asyncio.run(_nl_query(" ".join(argv[1:])))
    print("usage: osint ai <explain|query> ...", file=sys.stderr)
    return 2
