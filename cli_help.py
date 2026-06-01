"""CLI help / argument-parser scaffolding for the ``osint`` command.

Pure-leaf module: static help data + the argparse builder + the
position-independent toggle router. Extracted verbatim from ``cli.py`` so
that file stays focused on dispatch + the streaming run path. ``cli.py``
re-imports every public name here, so ``cli._build_parser`` /
``cli._route_leading_toggles`` / ``cli._GLOBAL_TOGGLE_FLAGS`` /
``cli._SUBCOMMAND_NAMES`` continue to resolve unchanged.

This module imports only leaves (``app.ui.banner``, ``app.core.types``) — it
must never import ``cli`` (which imports it), or any ``app.features.*`` that
would pull ``cli`` back in, to keep the import graph acyclic.
"""
from __future__ import annotations

import argparse
from typing import Any

from app.core.types import QueryKind
from app.ui.banner import BRAND

# ``cli.py`` populates this with its own module docstring at import time, so
# the ``Examples:`` epilog rendered by --help is byte-identical to the old
# in-cli behaviour (which read ``cli.__doc__`` directly). Leaving it ``None``
# yields an empty examples block — harmless for callers that don't set it.
_CLI_MODULE_DOC: str | None = None


class _Formatter(argparse.RawDescriptionHelpFormatter):
    """Slightly wider help with raw description."""

    def __init__(self, *a: object, **kw: object) -> None:
        kw.setdefault("max_help_position", 32)
        kw.setdefault("width", 100)
        super().__init__(*a, **kw)  # type: ignore[arg-type]


_SUBCOMMANDS_BLURB = """
subcommands (run any of these in place of <value>):
  config            settings wizard (Telegram + API keys + paths)
  serve [--port N]  local web dashboard (http://127.0.0.1:8765)
  self-update [--check]   pull latest binary, SHA-256 verify, in-place swap
  opsec-check [--opsec]   verify OPSEC mode is leak-free
  cert-watch <pat>  live tail Certificate Transparency for matches of <pat>
  cache stats|clear|clear-expired       SQLite HTTP cache control
  completion bash|zsh                   emit shell completion script
  mcp               start MCP server over stdio (Claude / Cursor)
  watch add|list|remove|enable|disable|run        watchlist daemon
  diff <kind> <value> [--from ID --to ID]         diff two stored scans
  graph show|export|rebuild|stats|forget  v4.0 entity graph
  export <kind> <value> --to splunk|elastic|syslog|misp   push to SIEM
  preset list|show|run <name>           YAML-defined saved scans
  plugin list|install|search|remove     third-party plugin loader
  ai explain|query                       Claude-powered analysis (needs ANTHROPIC_API_KEY)
  agent <target> [--no-approve]         local ReAct agent loop (opt-in; prompts to approve)
  doctor            local diagnostic — system · AI providers · network
  case new|list|show|note|close|reopen|resume|rm        named investigations (Wave D)
  rules list|run [--case SLUG]          correlation rules engine (Wave D)
  playbook list|run <id> <target> [--case SLUG]         conditional DAG playbooks (Wave D)
  schedule install|list|remove          opt-in OS scheduler (launchd/systemd/Task Sched.)
"""

# No-arg global toggle flags that may legitimately precede a subcommand.
_GLOBAL_TOGGLE_FLAGS = frozenset({
    "--no-color", "--no-banner", "--no-splash", "--debug", "--opsec",
    "--banner", "--classic", "--per-source", "--no-save",
})
# Every recognised subcommand verb (must match the dispatch chain in main()).
_SUBCOMMAND_NAMES = frozenset({
    "config", "mcp", "watch", "diff", "self-update", "selfupdate", "update",
    "opsec-check", "opseccheck", "cert-watch", "certwatch", "cache", "graph",
    "export", "preset", "plugin", "ai", "agent", "case", "rules", "playbook",
    "schedule", "doctor", "serve",
})

# Universal sub-command --help / -h table: command-name → (one-line summary,
# multi-line help body). Surfaced by main() when `osint <sub> --help` is run.
_SUB_HELP: dict[str, tuple[str, str]] = {
    "self-update": ("pull latest release binary in place (SHA-256 verified)",
        "usage: osint self-update [--check]\n"
        "  --check   compare versions without downloading\n"
        "  detects pipx / brew / scoop installs and routes you to the\n"
        "  right package-manager command instead of replacing the binary."),
    "opsec-check": ("verify --opsec is leak-free (Tor exit + UA + jitter)",
        "usage: osint opsec-check [--opsec]\n"
        "  --opsec   enable OPSEC mode for the duration of the check\n"
        "  probes: egress IP, Tor-exit-status, UA rotation across 5 calls,\n"
        "  jitter stdev across 5 calls. Non-zero exit if any check fails\n"
        "  while OPSEC is on."),
    "cache": ("SQLite HTTP cache control",
        "usage: osint cache [stats|clear|clear-expired]\n"
        "  enable with `OSINT_CACHE=1`. per-source TTL (see app/core/cache.py)."),
    "serve": ("local web dashboard with live SSE results",
        "usage: osint serve [--port N]\n"
        "  starts an http://127.0.0.1:N dashboard (default port 8765).\n"
        "  zero extra deps — stdlib asyncio + Server-Sent Events."),
    "completion": ("emit shell completion script",
        "usage: osint completion <bash|zsh|fish>\n"
        "  install:\n"
        "    bash:  osint completion bash > /etc/bash_completion.d/osint\n"
        "    zsh:   osint completion zsh > ~/.zsh/completions/_osint && compinit"),
    "cert-watch": ("live tail Certificate Transparency for a pattern",
        "usage: osint cert-watch <pattern> [--max N]\n"
        "  <pattern>: case-insensitive substring (e.g. 'acme')\n"
        "  --max N:   exit after N matching certs (default: keep going)"),
    "config": ("settings wizard (Telegram + API keys + paths)",
        "usage: osint config [wizard|show|edit|telegram|set KEY VAL|unset KEY]"),
    "watch": ("watchlist daemon — re-scan + Telegram-notify on diff",
        "usage: osint watch [add|list|remove|enable|disable|run] ..."),
    "diff": ("diff two stored scans of the same target",
        "usage: osint diff <kind> <value> [--from ID --to ID]"),
    "mcp": ("start MCP server over stdio (Claude / Cursor)",
        "usage: osint mcp\n"
        "  wire into your AI agent's mcp.json — see agent/mcp.json for an example."),
    "graph": ("entity graph — show/export/rebuild/stats/forget (v4.0)",
        "usage: osint graph <show|export|rebuild|stats|forget> ...\n"
        "  show    <kind> <value> [--depth N]\n"
        "  export  <kind> <value> [--format gexf|graphml|cytoscape] [--out FILE]\n"
        "  rebuild         re-derive entities from every stored hit\n"
        "  stats           totals per type\n"
        "  forget  <kind> <value>"),
    "export": ("push findings into a SIEM (Splunk/Elastic/syslog/MISP)",
        "usage: osint export <kind> <value> --to <target>\n"
        "  see `osint export --help` for env vars per target"),
    "doctor": ("local diagnostic: system + AI providers + network",
        "usage: osint doctor\n"
        "  prints OS / RAM / Python, Ollama reachability + installed models,\n"
        "  Claude key state, active provider, config dir perms, and a quick\n"
        "  network probe. Exit codes: 0 ok, 1 warnings, 2 errors."),
    "agent": ("local ReAct agent loop (opt-in, default OFF)",
        "usage: osint agent <target> [--no-approve]\n"
        "  Bounded ReAct loop (max 8 steps, 4000 tokens) using the active\n"
        "  LLM provider. Prompts for plan approval unless --no-approve."),
    "case": ("named investigations (Wave D)",
        "usage: osint case <new|list|show|note|close|reopen|resume|rm> ...\n"
        "  new <slug> [--name N] [--kind K] [--target V]\n"
        "  list [--all|--open|--closed]\n"
        "  show <slug>            timeline of runs + notes\n"
        "  note <slug> \"...\"    add a note (or --from-stdin)\n"
        "  close <slug> / reopen <slug>\n"
        "  resume <slug>          re-run the last action of the case\n"
        "  rm <slug> [--force]"),
    "rules": ("correlation rules engine (Wave D)",
        "usage: osint rules <list|run> [--case SLUG] [--id RULE]"),
    "playbook": ("conditional DAG playbooks (Wave D)",
        "usage: osint playbook <list|run> <id> <target> [--case SLUG]"),
    "schedule": ("opt-in OS scheduler (launchd / systemd / Task Scheduler)",
        "usage: osint schedule <install|list|remove> ...\n"
        "  install <slug-or-target> --every <Nh|cron> [--profile NAME] [--apply]\n"
        "    previews by default (writes nothing); pass --apply to write +\n"
        "    enable a real persistent OS job.\n"
        "  list / remove <name>"),
}


def _route_leading_toggles(raw: list[str]) -> list[str]:
    """Re-point argv past leading global toggles when a subcommand follows.

    `osint --no-color playbook list` → `playbook list` (dispatchable). A bare
    value (`osint --no-color octocat`) is left intact — octocat isn't a verb —
    so the main scan path is unaffected. Pure function (unit-tested).
    """
    lead = 0
    while lead < len(raw) and raw[lead] in _GLOBAL_TOGGLE_FLAGS:
        lead += 1
    if lead and lead < len(raw) and raw[lead] in _SUBCOMMAND_NAMES:
        return raw[lead:]
    return raw


def _build_parser(*, color: bool = True) -> argparse.ArgumentParser:
    _doc = _CLI_MODULE_DOC
    examples = _doc.split("Examples:", 1)[1] if _doc and "Examples:" in _doc else ""
    kw: dict[str, Any] = {
        "prog": "osint",
        "description": f"mytools-osint — personal OSINT lookups by {BRAND} (free APIs, no paid keys)",
        "formatter_class": _Formatter,
        "epilog": _SUBCOMMANDS_BLURB + (examples or ""),
    }
    # argparse 3.14+ colourises help/usage; honour --no-color / NO_COLOR / pipe.
    try:
        ap = argparse.ArgumentParser(color=color, **kw)  # type: ignore[call-arg]
    except TypeError:
        # Pre-3.14 argparse has no `color` kwarg — NO_COLOR env (set by the
        # caller) is the only lever, which older argparse simply ignores.
        ap = argparse.ArgumentParser(**kw)
    ap.add_argument("value", nargs="?", help="username, email, +phone, @tg, domain or IP")
    ap.add_argument("--kind", choices=[k.value for k in QueryKind], default=None,
                    help="force the query kind (auto-detect otherwise)")
    ap.add_argument("--all", action="store_true",
                    help="show every probe (default: only positives + rate-limited + breach)")
    ap.add_argument("--format", choices=["plain", "json", "jsonl", "csv"], default="plain",
                    help="output format (jsonl = one Hit per line, ideal for piping)")
    ap.add_argument("--out", default=None, help="write output to FILE instead of stdout")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ap.add_argument("--no-banner", action="store_true", help="suppress the startup banner")
    ap.add_argument("--no-splash", action="store_true",
                    help="suppress the cold-start splash (v4.2). Also implied by --no-banner.")
    ap.add_argument("--classic", action="store_true",
                    help="use the v4.2 menu-based interactive shell instead of the v4.3 chat-style prompt.")
    ap.add_argument("--list-modules", action="store_true",
                    help="list all registered OSINT modules and exit")
    ap.add_argument("--list-stats", action="store_true",
                    help="show site dataset breakdown by category and exit")
    ap.add_argument("--list-profiles", action="store_true",
                    help="list available --profile presets and exit")
    ap.add_argument("--version", action="store_true",
                    help="print banner + version and exit")
    ap.add_argument("--interactive", "-i", action="store_true",
                    help="launch the interactive menu shell (default when no value + TTY)")
    ap.add_argument("--debug", action="store_true",
                    help="show per-source diagnostics, summaries, and upstream outages")
    ap.add_argument("--per-source", action="store_true",
                    help="emit one Hit per (subdomain, source) instead of deduplicated rows")
    ap.add_argument("--banner", action="store_true",
                    help="show the full BLUETM.UZ figlet banner (default: compact one-liner)")
    # --- red-team additions ---------------------------------------------
    ap.add_argument("--profile",
                    help="module preset: quick | deep | person | domain-recon | "
                         "red-team | blue-team | ioc (default: all enabled)")
    ap.add_argument("--enable", action="append", default=[], metavar="MOD",
                    help="force-enable a specific module (repeatable)")
    ap.add_argument("--disable", action="append", default=[], metavar="MOD",
                    help="force-disable a specific module (repeatable)")
    ap.add_argument("--min-severity", default=None,
                    choices=["info", "low", "medium", "high", "critical"],
                    help="only surface hits at or above this severity")
    ap.add_argument("--bulk", default=None, metavar="FILE",
                    help="read targets from FILE (one per line, '#' = comment); "
                         "run them sequentially")
    ap.add_argument("--bulk-format", choices=["plain", "jsonl"], default="jsonl",
                    help="output format when --bulk is set (default: jsonl)")
    ap.add_argument("--opsec", action="store_true",
                    help="route HTTP via SOCKS5 (TOR_SOCKS env or 127.0.0.1:9050), "
                         "add jitter, force-randomize UA")
    ap.add_argument("--tui", action="store_true",
                    help="launch the live Textual dashboard for this query")
    ap.add_argument("--html", default=None, metavar="FILE",
                    help="write a self-contained HTML report to FILE")
    ap.add_argument("--md", default=None, metavar="FILE",
                    help="write a Markdown report (great for GitHub issues / Notion)")
    # v4.0 entity graph
    ap.add_argument("--no-save", action="store_true",
                    help="don't persist this scan's hits + graph entities to DB")
    ap.add_argument("--pivot", type=int, default=0, metavar="DEPTH",
                    help="auto-pivot — after main scan, re-run profile-appropriate "
                         "scans against every discovered entity (bounded BFS, default depth 0 = off)")
    ap.add_argument("--parallel", type=int, default=4, metavar="N",
                    help="bulk mode: number of targets to scan concurrently (default: 4)")
    ap.add_argument("--explain", action="store_true",
                    help="after the scan, ask Claude for an executive summary "
                         "(needs ANTHROPIC_API_KEY; disabled in --opsec)")
    ap.add_argument("--case", default=None, metavar="SLUG",
                    help="attach this scan's result to a named case (Wave D). "
                         "The case must already exist (use `osint case new`).")
    return ap
