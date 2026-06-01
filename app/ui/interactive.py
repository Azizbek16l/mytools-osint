"""Interactive CLI shell — arrow-key menus, live streaming, drill-down.

Modelled after Claude Code / lazygit / Vite scaffolders. Launches when:
  - `osint` is invoked with no value AND stdin is a TTY, OR
  - `osint --interactive` / `osint -i` is explicitly requested.

Design (per senior UX + designer review, 2026-05):
  - Big BLUETM.UZ figlet on cold start; single-line compact brandmark thereafter
  - Single-prompt input with live kind inference; only ambiguous → disambiguator
  - Sticky footer during streaming: hits-count, sites-probed, elapsed, shortcuts
  - Rounded boxes only; no double-line BBS chrome
  - Single accent (azure) — palette in app/ui/tokens
"""
from __future__ import annotations

import asyncio
import difflib
import json
import re
import webbrowser
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from pathlib import Path as _Path
from typing import TYPE_CHECKING, Any, cast

import questionary
from prompt_toolkit.styles import Style as PStyle
from questionary import Choice
from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.text import Text

from app.core.config import settings
from app.core.db import Database
from app.core.runner import Runner, runner
from app.core.types import Hit, HitStatus, Query, QueryKind
from app.ui import tokens
from app.ui.banner import BRAND
from app.ui.health import record_module_run

# Pure rendering layer (see app/ui/interactive_render.py). Re-imported so the
# orchestration here (run_query, _render_modules_table, after_results_menu) and
# external references (tests + scripts/diag_*.py on `interactive._render_*`)
# keep resolving against `app.ui.interactive`. This module imports the render
# module; the render module imports only leaves — strictly one-way, no cycle.
from app.ui.interactive_render import (  # noqa: F401  (re-export for back-compat)
    ModProgress,
    _classify,
    _render_body,
    _render_domain_report,
    _render_footer,
    _render_header,
    _render_hits_feed,
    _render_modules_rail,
    _render_streaming_layout,
    _render_summary_card,
    _sparkline,
    _spin_char,
    _status_marker,
    _update_module_progress,
)

if TYPE_CHECKING:
    from app.ui.lookup_input import SlashName

console = Console(highlight=False, force_terminal=tokens.colour_enabled() or None)

# questionary style — single accent
QSTYLE = PStyle([
    ("qmark", f"fg:{tokens.ACCENT} bold"),
    ("question", "bold"),
    ("answer", f"fg:{tokens.OK} bold"),
    ("pointer", f"fg:{tokens.ACCENT} bold"),
    ("highlighted", f"fg:{tokens.ACCENT} bold"),
    ("selected", f"fg:{tokens.OK}"),
    ("separator", f"fg:{tokens.DIM}"),
    ("instruction", f"fg:{tokens.DIM}"),
    ("text", ""),
    ("disabled", f"fg:{tokens.DIM} italic"),
])

KIND_LABELS = {
    QueryKind.USERNAME: f"{tokens.ICON_SEARCH}  username  — social profile enum across 1,000+ sites",
    QueryKind.EMAIL:    f"{tokens.ICON_EMAIL}  email     — breach + Holehe + Gravatar + derived",
    QueryKind.PHONE:    f"{tokens.ICON_PHONE}  phone     — libphonenumber + Telegram MTProto + WhatsApp",
    QueryKind.TELEGRAM: f"{tokens.ICON_TELEGRAM}  telegram  — @username via MTProto + t.me HTML",
    QueryKind.DOMAIN:   f"{tokens.ICON_WEB}  domain    — crt.sh + HackerTarget + urlscan.io + DNS",
    QueryKind.IP:       f"{tokens.ICON_IP}  ip / host — IPinfo + reverse DNS",
}

def _auto_kind(value: str) -> QueryKind | None:
    """Infer query kind from value for the chat shell. None if ambiguous.

    Delegates the routing decision to the SINGLE canonical inferer
    (:func:`app.core.infer.infer_kind`) so wallet/hash/image/IP ordering can
    never drift from cli.py. Two chat-shell-specific behaviours are layered
    explicitly on top:

      1. A leading ``@`` means TELEGRAM here (the canonical maps it to the
         generic USERNAME). This is an *intentional* fork for the interactive
         shell — kept as an explicit, commented branch, not a silent copy.
      2. ``None`` (ambiguous → show the kind picker) is returned when the
         canonical fell through to its USERNAME *catch-all* for something that
         isn't a plausible bare handle (e.g. ``a`` or ``foo bar``). The CLI
         always commits to USERNAME; the interactive shell prefers to ask.
    """
    from app.core.infer import infer_kind as _canonical_infer_kind

    v = value.strip()
    if not v:
        return None
    # (1) Explicit chat-shell override: '@handle' → TELEGRAM (canonical = USERNAME).
    if v.startswith("@"):
        return QueryKind.TELEGRAM
    kind = _canonical_infer_kind(v)
    # (2) Distinguish a *real* bare-username match from the canonical catch-all.
    # The canonical returns USERNAME both for valid handles and as a final
    # fallback; the chat shell only auto-commits to USERNAME for a plausible
    # handle and otherwise asks (returns None → picker).
    if kind == QueryKind.USERNAME and not re.match(r"^[A-Za-z0-9_\-]{2,}$", v):
        return None
    return kind


def _print_compact() -> None:
    """Print the one-line brandmark at the top of every menu screen."""
    brand = f"[bold {tokens.ACCENT}]bluetm·uz[/]"
    rest = f"[{tokens.DIM}]  osint · v{__import__('app').__version__}[/]"
    console.print(f"\n{brand}{rest}")


def _print_keybindings(*pairs: tuple[str, str]) -> None:
    """Sticky keybinding hint — used at the bottom of every screen.

    Mirrors lazygit / k9s — a 1-line dim cheatsheet so the user never has to
    leave the screen to remember what `o`, `?`, `/`, `q` mean.
    """
    t = Text("   ")
    for i, (key, label) in enumerate(pairs):
        if i:
            t.append("  ·  ", style=tokens.DIM)
        t.append(key, style=f"bold {tokens.ACCENT}")
        t.append(" " + label, style=tokens.DIM)
    console.print(t)


# ---- Global ? help overlay ------------------------------------------------

_HELP_SCREENS: dict[str, list[tuple[str, str]]] = {
    "main": [
        ("L", "new lookup — single-prompt with auto-detect"),
        ("H", "recent history (last 50)"),
        ("M", "modules — k9s-style table + toggle"),
        ("S", "sites — Sherlock + WhatsMyName breakdown"),
        ("P", "command palette — fuzzy launcher for any action"),
        ("T", "settings — API keys · Telegram · paths"),
        ("I", "this info / help overlay"),
        ("Q", "exit"),
    ],
    "results": [
        ("1-9", "open positive #N directly"),
        ("O", "open positive in browser (picker)"),
        ("E", "export — csv · json · markdown"),
        ("R", "re-run (same query, fresh probes)"),
        ("N", "new lookup"),
        ("M", "main menu"),
        ("Q", "quit"),
    ],
    "modules": [
        ("↵", "toggle enable/disable of highlighted module"),
        ("↑↓", "navigate"),
        ("←", "back to main menu"),
    ],
    "streaming": [
        ("Ctrl+C", "cancel the in-flight run"),
    ],
}


async def show_help(screen: str = "main") -> None:
    """Show a `?`-style cheatsheet overlay for the current screen.

    Used by binding `?` on every menu where it's offered. Renders a rich
    Group with a section per topic.
    """
    bindings = _HELP_SCREENS.get(screen) or _HELP_SCREENS["main"]
    rows = Text("\n")
    rows.append(f"   {tokens.ICON_QUESTION}  help — {screen}\n",
                style=f"bold {tokens.ACCENT}")
    rows.append("   " + ("─" * 60) + "\n", style=tokens.DIM)
    for key, label in bindings:
        rows.append(f"   {key:<8}", style=f"bold {tokens.ACCENT}")
        rows.append(f"  {label}\n", style=tokens.FG)
    rows.append("   " + ("─" * 60) + "\n", style=tokens.DIM)
    rows.append("   Esc / ← always returns one level up\n", style=tokens.DIM)
    console.print(rows)


# Chat-shell /help groups — canonical slash names by theme. Built from
# lookup_input.SLASH_ALIASES + SLASH_DESCRIPTIONS so the help can never drift
# from the dispatcher / completer.
_CHAT_HELP_GROUPS: list[tuple[str, tuple[SlashName, ...]]] = [
    ("lookup",        ("kind", "history", "export")),
    ("shell",         ("help", "clear", "version", "quit")),
    ("config",        ("settings", "profile", "theme", "modules", "sites")),
    ("investigate",   ("graph", "case", "rules", "playbook", "diff", "watch")),
    ("AI / OPSEC",    ("agent", "explain", "pattern", "opsec")),
    ("ops",           ("schedule", "doctor")),
]


async def _show_chat_help() -> None:
    """v4.3 chat-shell help — teach the real slash-command + chat workflow.

    Replaces the legacy single-letter menu cheatsheet (L/H/M/S/…), which was
    the wrong vocabulary for the chat prompt. Rendered from the canonical
    SLASH_ALIASES catalogue so the primary spelling + one-line description per
    command always matches the dispatcher and tab-completion.
    """
    from app.ui.lookup_input import SLASH_ALIASES, SLASH_DESCRIPTIONS

    rows = Text("\n")
    rows.append("   mytools-osint — chat shell\n", style=f"bold {tokens.ACCENT}")
    rows.append(
        "   type a target (auto-detect) to scan · use /commands for everything else\n",
        style=tokens.DIM,
    )
    rows.append("   " + ("─" * 64) + "\n", style=tokens.DIM)
    seen: set[str] = set()
    for group, names in _CHAT_HELP_GROUPS:
        rows.append(f"   {group}\n", style=f"bold {tokens.FG}")
        for name in names:
            aliases = SLASH_ALIASES.get(name)
            if not aliases:
                continue
            seen.add(name)
            primary = aliases[0]
            extra = (
                "  (" + ", ".join(aliases[1:]) + ")" if len(aliases) > 1 else ""
            )
            desc = SLASH_DESCRIPTIONS.get(name, "")
            rows.append(f"     {primary:<11}", style=f"bold {tokens.ACCENT}")
            rows.append(f" {desc}", style=tokens.FG)
            rows.append(f"{extra}\n", style=tokens.DIM)
        rows.append("\n")
    # Any catalogue entry not placed in a group above (forward-compat safety).
    leftover = [n for n in SLASH_ALIASES if n not in seen]
    if leftover:
        rows.append("   more\n", style=f"bold {tokens.FG}")
        for name in leftover:
            primary = SLASH_ALIASES[name][0]
            rows.append(f"     {primary:<11}", style=f"bold {tokens.ACCENT}")
            rows.append(f" {SLASH_DESCRIPTIONS.get(name, '')}\n",
                        style=tokens.FG)
        rows.append("\n")
    rows.append("   " + ("─" * 64) + "\n", style=tokens.DIM)
    rows.append("   keys", style=f"bold {tokens.FG}")
    rows.append("   Tab", style=f"bold {tokens.ACCENT}")
    rows.append(" complete  ", style=tokens.DIM)
    rows.append("→", style=f"bold {tokens.ACCENT}")
    rows.append(" ghost text  ", style=tokens.DIM)
    rows.append("Ctrl-R", style=f"bold {tokens.ACCENT}")
    rows.append(" history  ", style=tokens.DIM)
    rows.append("Alt+Enter / ,", style=f"bold {tokens.ACCENT}")
    rows.append(" burst multiple targets\n", style=tokens.DIM)
    rows.append(
        "   The Wave D verbs (/case /rules /playbook /diff /watch /schedule "
        "/doctor) run the same\n"
        "   handlers as `osint <verb> …` on the command line — pass args "
        "exactly as you would there,\n"
        "   e.g. /case new acme --target acme.com --kind domain.\n",
        style=tokens.DIM,
    )
    rows.append(
        "   Prefer the classic single-key menu?  Restart with `osint --classic`.\n",
        style=tokens.DIM,
    )
    console.print(rows)


# ---- live streaming layout --------------------------------------------------
# The pure rendering layer (status markers, sparkline, per-module progress,
# streaming dashboard, domain report, summary card) lives in
# ``app.ui.interactive_render``; the names are re-imported below so existing
# call sites (run_query, action_modules, after_results_menu) and external
# references (tests + diag scripts on ``interactive._render_summary_card`` etc.)
# resolve unchanged.


async def run_query(db: Database, query: Query) -> tuple[list[Hit], int]:
    """Run a single query with a live split-pane (modules rail | hits feed).

    Runs in the terminal's **alternate screen buffer** (`screen=True`) — exactly
    like htop / k9s / lazygit. This eliminates the per-frame flicker we get on
    Windows Terminal when Rich redraws panel borders 12 times per second.
    Refresh is throttled to 6 Hz; on exit we transition back to the main screen
    and print a static snapshot so the result remains visible in scrollback.

    Sprint 3 polish: after the run completes, each registered module emits a
    health record (``ok | degraded | failed``) to ``app.ui.health`` so the
    modules screen sparkline reflects real activity, not a placeholder.
    """
    r = runner()
    hits: list[Hit] = []
    progress: dict[str, ModProgress] = {}
    routed = r.modules_for(query.kind)
    for m in routed:
        progress[m.name] = ModProgress(name=m.name, state="idle")
    started = asyncio.get_event_loop().time()

    async def on_hit(h: Hit) -> None:
        hits.append(h)
        _update_module_progress(progress, h, asyncio.get_event_loop().time())

    result = None
    try:
        with Live(
            _render_streaming_layout(query, hits, progress, 0, False),
            console=console,
            refresh_per_second=6,
            screen=True,          # alternate buffer — no flicker
            transient=False,
            vertical_overflow="visible",
            auto_refresh=True,
        ) as live:
            task = asyncio.create_task(r.run(query, on_hit=on_hit))
            try:
                while not task.done():
                    elapsed_ms = int(
                        (asyncio.get_event_loop().time() - started) * 1000,
                    )
                    live.update(_render_streaming_layout(
                        query, hits, progress, elapsed_ms, False,
                    ))
                    try:
                        await asyncio.wait_for(asyncio.shield(task), timeout=0.15)
                    except TimeoutError:
                        continue
            except (KeyboardInterrupt, asyncio.CancelledError):
                task.cancel()
                try:
                    await task
                except Exception:
                    pass
            result = await task
            elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
            for p in progress.values():
                p.finished = True
            live.update(_render_streaming_layout(
                query, hits, progress, elapsed_ms, True,
            ))
            # one final paint inside the alt buffer so the user sees done state
            await asyncio.sleep(0.4)
    except KeyboardInterrupt:
        pass

    elapsed_ms = int((asyncio.get_event_loop().time() - started) * 1000)
    # After the alt-screen Live closes, the main screen is restored — print a
    # static snapshot of the dashboard so the result lives on in scrollback.
    for p in progress.values():
        p.finished = True
    console.print(_render_streaming_layout(query, hits, progress, elapsed_ms, True))

    # Record per-module health entries — best-effort, never fatal.
    for m in routed:
        p = progress.get(m.name) or ModProgress(name=m.name)
        if p.errors and not p.positives:
            status = "failed"
        elif p.ratelimited and not p.positives:
            status = "degraded"
        else:
            status = "ok"
        try:
            record_module_run(m.name, status, p.positives)
        except Exception:
            pass

    if result is not None:
        try:
            await db.save_result(result)
        except Exception:
            pass
    return hits, elapsed_ms


# ---- menu actions -----------------------------------------------------------

async def action_lookup(db: Database, *, kind_override: QueryKind | None = None) -> bool:
    """Single-prompt input with **live kind inference** in the bottom toolbar.

    Beyond the live toolbar (kept verbatim from the original), the prompt now
    offers Claude Code-class ergonomics:

    * fish-shell ghost-text auto-suggestions from a persistent ``FileHistory``
    * Tab completion across slash commands, the seven kinds, and recent history
    * Ctrl-R reverse history search (native prompt_toolkit)
    * inline ``/help`` ``/clear`` ``/history`` … slash command dispatcher
    * comma- or Alt+Enter-separated multi-target burst input

    ``kind_override`` short-circuits auto-detection for a single submission and
    is set by the ``/kind <k>`` slash command.
    """
    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.formatted_text import FormattedText

    from app.ui.lookup_input import (
        build_completer,
        build_history,
        build_key_bindings,
        dispatch_slash,
        split_multi_target,
        suggest_slash_for_typo,
    )

    # v4.3: the pre-prompt block (examples + Tab/ghost/Ctrl-R/help/quit tips)
    # is shown ONCE on the FIRST prompt of each session — for new AND returning
    # users (history is non-empty forever after the first ever query, so gating
    # on history alone meant rusty returners never saw the affordances again).
    # New users also get the worked examples; returning users get a shorter
    # "welcome back" affordance line above the tips. The always-visible bottom
    # toolbar carries the per-prompt cue on every subsequent prompt.
    history = build_history()
    _has_any_history = any(True for _ in history.load_history_strings())
    if not _CHAT_STATE.get("_pre_prompt_shown"):
        _CHAT_STATE["_pre_prompt_shown"] = True
        console.print()
        if _has_any_history:
            wb = Text("   ")
            wb.append("welcome back", style=f"bold {tokens.ACCENT}")
            wb.append(" — type a target to scan, or ", style=tokens.DIM)
            wb.append("/help", style=f"bold {tokens.ACCENT}")
            wb.append(" for the command list", style=tokens.DIM)
            console.print(wb)
        else:
            examples = Text("   ")
            examples.append("examples:  ", style=tokens.DIM)
            for e in ("temur", "satya@microsoft.com", "+998 90 123 45 67",
                      "@durov", "github.com"):
                examples.append(e, style=tokens.ACCENT)
                examples.append("   ", style=tokens.DIM)
            console.print(examples)
        tips = Text("   ")
        for label, key in (("Tab", "complete"), ("→", "ghost text"),
                           ("Ctrl-R", "history"), ("/help", "commands"),
                           ("/quit", "exit")):
            tips.append(label, style=f"bold {tokens.ACCENT}")
            tips.append(f" {key}  ·  ", style=tokens.DIM)
        console.print(tips)
        console.print()

    r = runner()
    # `history` was built above when deciding whether to render the
    # session-intro block. Reuse the same FileHistory instance.

    # PromptSession bottom_toolbar — v4.3 carries session state too: shows
    # current theme accent, active profile, opsec/explain toggles, plus the
    # live kind inference. Empty input → slash command discovery cue.
    def _toolbar_for(buf_text: str) -> FormattedText:
        v = (buf_text or "").strip()
        # Right-side: session state pill. Built once per refresh.
        state_bits: list[tuple[str, str]] = []
        # Wave B — surface live agent progress when the loop is running.
        try:
            from app.features.agent import AGENT_STATE  # local import: opt-in
            if AGENT_STATE.get("running"):
                tok = int(AGENT_STATE.get("tokens", 0) or 0)
                tok_str = f"{tok / 1000:.1f}k" if tok >= 1000 else str(tok)
                state_bits.append((
                    "fg:#a371f7 bold",
                    f"  [agent {AGENT_STATE.get('step', 0)}/"
                    f"{AGENT_STATE.get('max_steps', 0)} steps · {tok_str} tok]",
                ))
        except Exception:
            pass
        if _CHAT_STATE.get("profile"):
            state_bits.append(("fg:#58a6ff bold", f"  profile:{_CHAT_STATE['profile']}"))
        if _CHAT_STATE.get("opsec"):
            state_bits.append(("fg:#d29922 bold", "  ⚑opsec"))
        if _CHAT_STATE.get("explain"):
            state_bits.append(("fg:#3fb950 bold", "  🤖explain"))
        # Left-side: input-state hint.
        if not v:
            left = [
                ("fg:#6e7681", "  type a "),
                ("fg:#c9d1d9 bold", "target"),
                ("fg:#6e7681", " (auto-detect) or "),
                ("fg:#58a6ff bold", "/help · /theme · /profile · /opsec · /quit"),
            ]
        elif v.startswith("/"):
            left = [
                ("fg:#58a6ff bold", "  /command"),
                ("fg:#6e7681", " — Tab to complete, Enter to run"),
            ]
        else:
            kind = kind_override or _auto_kind(v)
            if kind is None:
                left = [
                    ("fg:#d29922", "  AMBIGUOUS"),
                    ("fg:#6e7681", " — picker appears after Enter"),
                ]
            else:
                n_modules = len(r.modules_for(kind))
                left = [
                    ("fg:#3fb950 bold", f"  [{kind.value.upper()}]"),
                    ("fg:#6e7681", "  → "),
                    ("fg:#c9d1d9 bold", str(n_modules)),
                    ("fg:#6e7681", " modules · "),
                    ("fg:#58a6ff bold", "Enter"),
                    ("fg:#6e7681", " to scan, "),
                    ("fg:#58a6ff bold", "Ctrl-C"),
                    ("fg:#6e7681", " to cancel"),
                ]
        return FormattedText(left + state_bits)

    session: PromptSession[str] = PromptSession(
        message=FormattedText([("fg:#58a6ff bold", "❯ ")]),
        bottom_toolbar=lambda: _toolbar_for(session.default_buffer.text),
        refresh_interval=0.15,
        history=history,
        auto_suggest=AutoSuggestFromHistory(),
        completer=build_completer(history),
        # v4.3: live popup completions for slash commands + history.
        # The AutoSuggestFromHistory ghost text is rendered to the *right*
        # of the cursor; the popup shows below — they don't collide.
        complete_while_typing=True,
        enable_history_search=True,    # binds Ctrl-R natively
        key_bindings=build_key_bindings(),
        multiline=False,
    )
    try:
        value = await session.prompt_async()
    except (KeyboardInterrupt, EOFError):
        return True
    if value is None:
        return True
    value = value.strip()
    if not value:
        return True

    # ---- Slash command branch -------------------------------------------- #
    if value.startswith("/"):
        action = dispatch_slash(value)
        if action.action == "quit":
            return False
        if action.action == "help":
            await _show_chat_help()
            return await action_lookup(db)
        if action.action == "clear":
            console.clear()
            return await action_lookup(db)
        if action.action == "history":
            await action_history(db)
            return await action_lookup(db)
        if action.action == "modules":
            await action_modules()
            return await action_lookup(db)
        if action.action == "sites":
            await action_stats()
            return await action_lookup(db)
        if action.action == "settings":
            # See above — cmd_wizard internally calls asyncio.run, so we
            # off-load it to a worker thread to avoid loop nesting.
            import asyncio as _asyncio

            from app.ui.config_cli import cmd_wizard
            try:
                await _asyncio.to_thread(cmd_wizard)
            except Exception as e:
                console.print(f"[{tokens.BAD}]settings wizard error:[/] {e}")
            return await action_lookup(db)
        if action.action == "version":
            from app import __version__ as _ver
            console.print(
                f"   [bold {tokens.ACCENT}]mytools-osint[/] "
                f"[{tokens.FG}]v{_ver}[/] [{tokens.DIM}]· by Bluetm.uz[/]",
            )
            return await action_lookup(db)
        if action.action == "kind":
            try:
                kind = QueryKind(action.arg.lower()) if action.arg else None
            except ValueError:
                kind = None
            if kind is None:
                console.print(
                    f"[{tokens.WARN}]usage:[/] /kind <"
                    + "|".join(k.value for k in QueryKind)
                    + ">",
                )
                return await action_lookup(db)
            return await action_lookup(db, kind_override=kind)
        # ---- v4.3 chat-shell slash commands -----------------------------
        if action.action == "theme":
            await _action_theme_picker()
            return await action_lookup(db)
        if action.action == "profile":
            await _slash_profile(action.arg)
            return await action_lookup(db)
        if action.action == "graph":
            await _slash_graph(action.arg)
            return await action_lookup(db)
        if action.action == "opsec":
            _slash_opsec_toggle(action.arg)
            return await action_lookup(db)
        if action.action == "explain":
            _slash_explain_toggle()
            return await action_lookup(db)
        if action.action == "pattern":
            _slash_pattern(action.arg)
            return await action_lookup(db)
        if action.action == "export":
            await _slash_export(db, action.arg)
            return await action_lookup(db)
        if action.action == "agent":
            await _slash_agent(action.arg)
            return await action_lookup(db)
        # ---- Wave D verbs — thin wrappers over the existing CLI handlers --
        if action.action in ("case", "rules", "playbook", "schedule",
                             "diff", "watch", "doctor"):
            await _slash_cli_verb(action.action, action.arg)
            return await action_lookup(db)
        # unknown — print the dispatcher's did-you-mean hint and loop
        if action.message:
            console.print(f"[{tokens.WARN}]{action.message}[/]")
        return await action_lookup(db)

    # ---- Multi-target burst input ---------------------------------------- #
    targets = split_multi_target(value)
    if len(targets) > 1:
        return await _run_multi_target(db, targets, kind_override=kind_override)

    # ---- Single-target path ---------------------------------------------- #
    kind = kind_override or _auto_kind(value)
    if kind is None:
        # Non-slash typo that looks like a slash command? Offer a hint first.
        hinted = suggest_slash_for_typo(value)
        if hinted:
            console.print(
                f"[{tokens.WARN}]no kind inferred[/] — did you mean "
                f"[{tokens.ACCENT}]{hinted}[/]?",
            )
        kind = await questionary.select(
            "could not infer kind — pick one:",
            choices=[Choice(label, value=k) for k, label in KIND_LABELS.items()] +
                    [Choice("← back", value="__BACK__")],
            style=QSTYLE,
        ).ask_async()
        # Treat None, sentinel, or literal label as "back" — questionary
        # version differences make value=None unreliable.
        if kind is None or kind == "__BACK__" or kind == "← back":
            return True
    query = Query(kind=kind, value=value)
    hits, elapsed_ms = await run_query(db, query)
    # v4.3: stash for /export, then loop directly back to the prompt instead
    # of detouring through after_results_menu. Claude-Code style: the output
    # IS the report; further actions go through slash commands.
    _CHAT_STATE["last_query"] = query
    _CHAT_STATE["last_hits"] = list(hits)
    _CHAT_STATE["last_elapsed_ms"] = elapsed_ms
    # Wave B — remember the raw input so `/agent` (no arg) can target it.
    _CHAT_STATE["last_target"] = value
    # Quick footer cue so users discover the slash commands.
    console.print(
        f"   [{tokens.DIM}]/export html · md · json  ·  /graph show {kind.value} {value}  ·  type a new target to continue[/]"
    )
    return await action_lookup(db)


async def _run_multi_target(
    db: Database, targets: list[str], *, kind_override: QueryKind | None = None,
) -> bool:
    """Run one query per target sequentially, then print one combined summary.

    Each target gets its own full streaming dashboard via :func:`run_query`;
    after all of them complete we render a small recap table so the user can
    see at a glance which targets yielded the most positives.
    """
    console.print()
    header = Text("   ")
    header.append("burst input", style=f"bold {tokens.ACCENT}")
    header.append(f"   {len(targets)} targets — running sequentially", style=tokens.DIM)
    console.print(header)
    console.print()

    recap: list[tuple[str, str, int, int, int]] = []  # value, kind, found, total, ms
    for idx, target in enumerate(targets, start=1):
        kind = kind_override or _auto_kind(target)
        if kind is None:
            console.print(
                f"[{tokens.WARN}]skipping[/] [{tokens.FG}]{target}[/] "
                f"[{tokens.DIM}](no kind inferred — pass /kind first)[/]",
            )
            recap.append((target, "—", 0, 0, 0))
            continue
        line = Text("   ")
        line.append(f"[{idx}/{len(targets)}] ", style=tokens.DIM)
        line.append(target, style=f"bold {tokens.FG}")
        line.append(f"   ({kind.value})", style=tokens.DIM)
        console.print(line)
        query = Query(kind=kind, value=target)
        hits, elapsed_ms = await run_query(db, query)
        found = sum(1 for h in hits if h.status == HitStatus.FOUND)
        recap.append((target, kind.value, found, len(hits), elapsed_ms))

    # Combined summary table.
    t = Table.grid(padding=(0, 2))
    t.add_column(width=4, justify="right")
    t.add_column(width=30, overflow="ellipsis", no_wrap=True)
    t.add_column(width=10)
    t.add_column(width=10, justify="right")
    t.add_column(width=10, justify="right")
    t.add_column(width=10, justify="right")
    t.add_row(
        Text("#",     style=f"bold {tokens.ACCENT}"),
        Text("TARGET", style=f"bold {tokens.ACCENT}"),
        Text("KIND",   style=f"bold {tokens.ACCENT}"),
        Text("FOUND",  style=f"bold {tokens.ACCENT}"),
        Text("TOTAL",  style=f"bold {tokens.ACCENT}"),
        Text("MS",     style=f"bold {tokens.ACCENT}"),
    )
    for i, (val, knd, found, total, ms) in enumerate(recap, start=1):
        t.add_row(
            Text(str(i), style=tokens.DIM),
            Text(val, style=tokens.FG),
            Text(knd, style=tokens.DIM),
            Text(str(found), style=f"bold {tokens.OK}" if found else tokens.DIM),
            Text(str(total), style=tokens.FG),
            Text(str(ms), style=tokens.DIM),
        )
    console.print()
    console.print(t)
    console.print()
    return True


async def after_results_menu(db: Database, query: Query, hits: list[Hit],
                              elapsed_ms: int) -> bool:
    """Post-run menu with the design summary card, did-you-mean for zero hits,
    and the k9s-style ``[N]/[c]/[a]`` per-hit action sub-menu (Sprint 3)."""
    positives = [h for h in hits if h.status == HitStatus.FOUND]

    # Zero-positive empty-state — render did-you-mean BEFORE the summary card
    # so the suggestion is the first thing the eye lands on.
    suggestions = build_did_you_mean(query, hits) if not positives else []
    if suggestions:
        console.print(_render_did_you_mean(query, len(hits), suggestions))

    # Render the design summary card (categorised findings + sparkline)
    console.print(_render_summary_card(query, hits, elapsed_ms))
    # For domain queries, also render the 3-column condensed report
    if query.kind == QueryKind.DOMAIN and positives:
        console.print(_render_domain_report(query, hits))

    while True:
        # Suggestion shortcut keys ``1/2/3`` are only attached when we have a
        # did-you-mean block — otherwise the same digits are used to open a
        # numbered positive via the per-hit branch.
        sug_choices: list[Choice] = []
        for i, (label, _sug_kind, _sug_val) in enumerate(suggestions, start=1):
            sug_choices.append(Choice(
                f"  try [{i}] — {label}", value=f"sug:{i - 1}",
                shortcut_key=str(i),
            ))

        choice = await questionary.select(
            "what next?",
            choices=[
                *sug_choices,
                Choice(f"  open positive in browser  ·  pick from {len(positives)} URLs",
                       value="open", shortcut_key="o",
                       disabled=None if positives else "no positives"),
                Choice("  per-hit actions  ·  open · copy · adjacent",
                       value="per-hit", shortcut_key="p",
                       disabled=None if positives else "no positives"),
                Choice("  export  ·  csv · json · md",
                       value="export", shortcut_key="e",
                       disabled=None if hits else "nothing to export"),
                Choice("  re-run (refresh)  ·  same query, fresh probes",
                       value="rerun", shortcut_key="r"),
                Choice("  new lookup  ·  back to prompt",
                       value="new",  shortcut_key="n"),
                Choice("  main menu", value="main", shortcut_key="m"),
                Choice("  quit",      value="quit", shortcut_key="q"),
            ],
            style=QSTYLE,
            use_shortcuts=True,
            instruction="(↑↓ or single key)",
        ).ask_async()
        if isinstance(choice, str) and choice.startswith("sug:"):
            idx = int(choice.split(":", 1)[1])
            _label, sug_kind, sug_value = suggestions[idx]
            new_query = Query(kind=sug_kind, value=sug_value)
            hits, elapsed_ms = await run_query(db, new_query)
            return await after_results_menu(db, new_query, hits, elapsed_ms)
        if choice == "open":
            await drill_open(positives)
        elif choice == "per-hit":
            await per_hit_actions(db, positives)
        elif choice == "export":
            await action_export(query, hits)
        elif choice == "rerun":
            hits, elapsed_ms = await run_query(db, query)
            positives = [h for h in hits if h.status == HitStatus.FOUND]
            suggestions = build_did_you_mean(query, hits) if not positives else []
            if suggestions:
                console.print(_render_did_you_mean(query, len(hits), suggestions))
            console.print(_render_summary_card(query, hits, elapsed_ms))
        elif choice == "new":
            return await action_lookup(db)
        elif choice in (None, "main"):
            return True
        elif choice == "quit":
            return False


async def drill_open(positives: list[Hit]) -> None:
    """Numbered picker — [1] [2] [3] etc. Mirrors the indices the summary card shows."""
    if not positives:
        return
    with_url = [h for h in positives if h.url]
    if not with_url:
        console.print(f"[{tokens.WARN}]no positives have URLs to open[/]")
        return
    choices = [
        Choice(f"  [{i}]  {h.source[:22]:22}  {h.detail[:70]}", value=h.url)
        for i, h in enumerate(with_url, start=1)
    ]
    choices.append(Choice("  ← cancel", value=""))
    url = await questionary.select(
        "open which?",
        choices=choices,
        style=QSTYLE,
        instruction="(↑↓ or 1-9)",
    ).ask_async()
    if url:
        try:
            webbrowser.open(url)
            console.print(f"[{tokens.OK}]opened[/] {url}")
        except Exception as e:
            console.print(f"[{tokens.BAD}]failed:[/] {e}")


# --------------------------------------------------------------------------- #
# Per-hit actions — k9s-style single-key sub-menu (Sprint 3, item 2)
# --------------------------------------------------------------------------- #

def _copy_to_clipboard(text: str) -> tuple[bool, str]:
    """Try to copy ``text`` to the OS clipboard via :mod:`pyperclip`.

    Returns ``(True, msg)`` on success. On any failure (module missing, no
    clipboard service on a headless box, OS mechanism refused) returns
    ``(False, "<reason>")`` and the caller falls back to printing the value
    so the user can select+copy manually. ``pyperclip`` is intentionally a
    soft dependency — never added to ``requirements.txt``.
    """
    try:
        import pyperclip
    except ImportError:
        return False, "pyperclip not installed"
    try:
        pyperclip.copy(text)
        return True, "copied"
    except Exception as e:  # pyperclip.PyperclipException, etc.
        return False, f"{type(e).__name__}: {e}"


async def per_hit_actions(db: Database, positives: list[Hit]) -> None:
    """Drill into a numbered positive and offer ``o/c/a/b`` single-key actions.

    Steps:
      1. Prompt for the hit index (1..N).
      2. Show a 4-row sub-menu — open, copy, adjacent, back.
      3. Each action returns control to the result-list (caller loops).

    Adjacency uses ``Hit.extra["suggested_kind"]`` + ``Hit.extra["suggested_value"]``
    emitted by Agent A's adjacency module. Missing keys produce a friendly
    "no suggestions" line rather than an error.
    """
    if not positives:
        return
    n = len(positives)
    raw = await questionary.text(
        f"pick a hit number to drill into [1-{n}]:",
        style=QSTYLE,
        instruction="(blank to cancel)",
    ).ask_async()
    if not raw:
        return
    try:
        idx = int(raw.strip()) - 1
    except ValueError:
        console.print(f"[{tokens.WARN}]not a number — '{raw}'[/]")
        return
    if not (0 <= idx < n):
        console.print(f"[{tokens.WARN}]out of range — pick 1..{n}[/]")
        return

    hit = positives[idx]
    summary = Text("   ")
    summary.append(f"[{idx + 1}]", style=f"bold {tokens.ACCENT}")
    summary.append(f"  {hit.source[:24]:24}", style=f"bold {tokens.FG}")
    summary.append("   ")
    summary.append((hit.url or hit.detail)[:80], style=tokens.DIM)
    console.print(summary)

    choice = await questionary.select(
        "action:",
        choices=[
            Choice("  o  open URL in browser", value="o", shortcut_key="o",
                   disabled=None if hit.url else "no URL on this hit"),
            Choice("  c  copy URL to clipboard", value="c", shortcut_key="c",
                   disabled=None if hit.url else "no URL on this hit"),
            Choice("  a  adjacent search (use suggested kind+value)",
                   value="a", shortcut_key="a"),
            Choice("  b  back to result list", value="b", shortcut_key="b"),
        ],
        style=QSTYLE,
        use_shortcuts=True,
        instruction="(single key)",
    ).ask_async()

    if choice == "o" and hit.url:
        try:
            webbrowser.open(hit.url)
            console.print(f"[{tokens.OK}]opened[/] {hit.url}")
        except Exception as e:
            console.print(f"[{tokens.BAD}]failed:[/] {e}")
    elif choice == "c" and hit.url:
        ok, msg = _copy_to_clipboard(hit.url)
        if ok:
            console.print(f"[{tokens.OK}]copied[/]  {hit.url}")
        else:
            console.print(
                f"[{tokens.WARN}]clipboard unavailable ({msg}) — select & copy manually:[/]\n"
                f"   {hit.url}",
            )
    elif choice == "a":
        extra = hit.extra or {}
        sug_kind = extra.get("suggested_kind")
        sug_value = extra.get("suggested_value")
        if not sug_kind or not sug_value:
            console.print(
                f"[{tokens.DIM}]no adjacency suggestions for this source[/]",
            )
            return
        try:
            kind = QueryKind(str(sug_kind))
        except ValueError:
            console.print(
                f"[{tokens.WARN}]adjacent kind unknown: {sug_kind!r}[/]",
            )
            return
        new_query = Query(kind=kind, value=str(sug_value))
        new_hits, ms = await run_query(db, new_query)
        await after_results_menu(db, new_query, new_hits, ms)
    # `b` / None — fall through and return


# --------------------------------------------------------------------------- #
# Did-you-mean for zero-hit results — Sprint 3 item 8
# --------------------------------------------------------------------------- #

_EMAIL_LIKE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_PHONE_LIKE = re.compile(r"^[+0-9 ()\-]{6,}$")
_DOMAIN_LIKE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$",
)


def _history_candidates() -> list[str]:
    """Newest-first deduplicated history values from the persistent FileHistory.

    Returns ``[]`` on any IO failure — did-you-mean is a soft hint, not a
    critical path.
    """
    try:
        from prompt_toolkit.history import FileHistory

        from app.ui.lookup_input import history_file_path
        h = FileHistory(str(history_file_path()))
        seen: set[str] = set()
        out: list[str] = []
        for entry in h.load_history_strings():
            if entry and entry not in seen:
                seen.add(entry)
                out.append(entry)
            if len(out) >= 200:
                break
        return out
    except Exception:
        return []


def build_did_you_mean(
    query: Query, hits: list[Hit],
) -> list[tuple[str, QueryKind, str]]:
    """Return up to 3 ``(label, kind, value)`` suggestions for a zero-hit run.

    Two sources:
      1. **closest historical match** — :func:`difflib.get_close_matches`
         against the user's persisted lookup history (cutoff 0.6).
      2. **type-misclassification** — if the value's shape *looks* like a
         different kind than was used (``@`` → telegram, ``+``/digits →
         phone, ``…@…`` → email, ``.`` → domain), suggest the alternative.

    Pure function — easy to unit-test without spinning up the runner.
    """
    if any(h.status == HitStatus.FOUND for h in hits):
        return []

    value = (query.value or "").strip()
    if not value:
        return []

    suggestions: list[tuple[str, QueryKind, str]] = []

    # Source 1: history fuzzy match (must differ from the current value).
    history = _history_candidates()
    hist_pool = [h for h in history if h != value]
    close = difflib.get_close_matches(value, hist_pool, n=1, cutoff=0.6)
    if close:
        label = f"{close[0]}  (closest match in your history)"
        suggestions.append((label, query.kind, close[0]))

    # Source 2: type-misclassification.
    lower = value.lower()
    if query.kind != QueryKind.EMAIL and _EMAIL_LIKE.match(lower):
        suggestions.append(
            (f"{lower} as email", QueryKind.EMAIL, lower),
        )
    if query.kind != QueryKind.TELEGRAM and value.startswith("@"):
        suggestions.append(
            (f"{value} as Telegram", QueryKind.TELEGRAM, value),
        )
    elif (
        query.kind == QueryKind.USERNAME
        and re.match(r"^[A-Za-z0-9_]{5,32}$", value)
    ):
        suggestions.append(
            (f"@{value} as Telegram", QueryKind.TELEGRAM, f"@{value}"),
        )

    digits = re.sub(r"\D", "", value)
    if (
        query.kind != QueryKind.PHONE
        and _PHONE_LIKE.match(value)
        and 6 <= len(digits) <= 16
        and not _EMAIL_LIKE.match(value)
    ):
        suggestions.append(
            (f"{value} as phone", QueryKind.PHONE, value),
        )

    if (
        query.kind != QueryKind.DOMAIN
        and "." in value
        and _DOMAIN_LIKE.match(value)
    ):
        suggestions.append(
            (f"{value} as domain", QueryKind.DOMAIN, value),
        )

    # Dedupe while preserving order (label, kind, value triples).
    seen: set[tuple[str, str]] = set()
    deduped: list[tuple[str, QueryKind, str]] = []
    for label, kind, val in suggestions:
        key = (kind.value, val)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((label, kind, val))
        if len(deduped) >= 3:
            break
    return deduped


def _render_did_you_mean(
    query: Query, probed: int,
    suggestions: list[tuple[str, QueryKind, str]],
) -> Group:
    """Render the zero-hit empty-state block. Sits ABOVE the summary card."""
    rule_top = Text("   ── no positives " + "─" * 56, style=tokens.DIM)
    line = Text("   ")
    line.append("Probed ", style=tokens.DIM)
    line.append(f"{probed} ", style=f"bold {tokens.FG}")
    line.append("sources for ", style=tokens.DIM)
    line.append(query.kind.value, style=tokens.DIM)
    line.append(" ")
    line.append(f"'{query.value}'", style=f"bold {tokens.FG}")
    line.append(" — nothing found.", style=tokens.DIM)

    intro = Text("   ")
    intro.append("Did you mean to search:", style=f"bold {tokens.FG}")

    rows = Table.grid(padding=(0, 1))
    rows.add_column(width=8)
    rows.add_column()
    for i, (label, _kind, _val) in enumerate(suggestions, start=1):
        rows.add_row(
            Text(f"   ◆ [{i}]", style=f"bold {tokens.ACCENT}"),
            Text(label, style=tokens.FG),
        )

    foot = Text("   ")
    foot.append("Press ", style=tokens.DIM)
    for i in range(1, len(suggestions) + 1):
        foot.append(f"[{i}]", style=f"bold {tokens.ACCENT}")
        if i < len(suggestions):
            foot.append("/", style=tokens.DIM)
    foot.append(" to switch & re-scan, or ", style=tokens.DIM)
    foot.append("[n]", style=f"bold {tokens.ACCENT}")
    foot.append(" for a new query.", style=tokens.DIM)

    return Group(
        Text(""),
        rule_top,
        Text(""),
        line,
        Text(""),
        intro,
        Text(""),
        rows,
        Text(""),
        foot,
        Text(""),
    )


EXPORT_FORMATS = ("csv", "json", "jsonl", "md", "html")


def export_hits(
    query: Query,
    hits: list[Hit],
    fmt: str,
    *,
    elapsed_ms: int = 0,
    path: str | _Path | None = None,
) -> _Path:
    """Serialise a scan to ``fmt`` and write it to disk; return the path.

    Single source of truth for BOTH the menu export (``action_export``) and
    the chat-shell ``/export``. Standardises on:

      * ``exports_dir`` for the default location (not cwd) with a sanitised,
        timestamped filename;
      * pydantic ``model_dump(mode="json")`` for json/jsonl (Hit is a pydantic
        model — there is no ``to_dict``; the old ``__dict__`` fallback leaked
        private pydantic state);
      * the canonical ``render_report`` / ``render_markdown`` for html/md,
        which take a ``QueryResult`` (the old ``from … import render`` names
        did not exist — html/md export raised ImportError).

    Raises ``ValueError`` for an unknown format.
    """
    fmt = (fmt or "").lower()
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"unknown format {fmt!r} — use {' | '.join(EXPORT_FORMATS)}")

    if path is not None:
        out = _Path(path)
    else:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = settings().exports_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_value = re.sub(r"[^A-Za-z0-9_.+@-]", "_", query.value)[:60]
        out = out_dir / f"osint-{query.kind.value}-{safe_value}-{ts}.{fmt}"
    if out.parent:
        out.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "csv":
        import csv as _csv
        with out.open("w", encoding="utf-8", newline="") as f:
            w = _csv.writer(f)
            w.writerow(["module", "source", "category", "status", "title",
                        "detail", "url", "severity", "latency_ms"])
            for h in hits:
                w.writerow([h.module, h.source, h.category, h.status.value,
                            h.title, h.detail, h.url, h.severity.value, h.latency_ms])
    elif fmt == "json":
        payload = {
            "query": query.model_dump(mode="json"),
            "hits": [h.model_dump(mode="json") for h in hits],
            "exported_at": datetime.now().isoformat(),
        }
        out.write_text(
            json.dumps(payload, indent=2, default=str, ensure_ascii=False),
            encoding="utf-8",
        )
    elif fmt == "jsonl":
        with out.open("w", encoding="utf-8") as f:
            for h in hits:
                f.write(json.dumps(h.model_dump(mode="json"),
                                   default=str, ensure_ascii=False) + "\n")
    elif fmt == "html":
        from app.core.types import QueryResult
        from app.ui.html_report import render_report
        result = QueryResult(query=query, hits=list(hits))
        out.write_text(render_report(query, result, elapsed_ms), encoding="utf-8")
    else:  # md
        from app.core.types import QueryResult
        from app.ui.md_report import render_markdown
        result = QueryResult(query=query, hits=list(hits))
        out.write_text(render_markdown(query, result, elapsed_ms), encoding="utf-8")
    return out


async def action_export(query: Query, hits: list[Hit]) -> None:
    fmt = await questionary.select(
        "format?",
        choices=[
            Choice("csv  (one row per hit)",     value="csv",  shortcut_key="c"),
            Choice("json (full payload)",        value="json", shortcut_key="n"),  # 'j' is vim-nav
            Choice("md   (positives only)",      value="md",   shortcut_key="m"),
            Choice("html (full report)",         value="html", shortcut_key="h"),
            Choice("← cancel",                   value=""),
        ],
        style=QSTYLE, use_shortcuts=True,
    ).ask_async()
    if not fmt:
        return
    try:
        path = export_hits(query, hits, fmt)
        console.print(f"[{tokens.OK}]saved →[/] [bold]{path}[/]")
    except Exception as e:
        console.print(f"[{tokens.BAD}]export failed:[/] {e}")


async def action_history(db: Database) -> None:
    rows = await db.list_history(50)
    if not rows:
        console.print(f"[{tokens.DIM}]no history yet[/]")
        return

    # Heatmap header — last 28 days
    try:
        heat = await db.history_heatmap(days=28)
    except Exception:
        heat = []
    if heat:
        header = Text("   ")
        header.append("bluetm·uz", style=f"bold {tokens.ACCENT}")
        header.append("   history  ·  ", style=tokens.DIM)
        header.append(str(len(rows)), style=f"bold {tokens.FG}")
        header.append(" recent  ·  28d:  ", style=tokens.DIM)
        # reverse so oldest is left, today is right
        header += _sparkline(list(reversed(heat)))
        console.print()
        console.print(header)
        console.print()
    choices = []
    for row in rows:
        when = (row.get("started_at") or "").replace("T", " ").split(".")[0]
        choices.append(Choice(
            f"{when}  [{row['kind']:8}] {row['value']:30}  "
            f"found={row['found']:>3}/{row['total']:>3}",
            value=row["id"],
        ))
    choices.append(Choice("← back", value="__BACK__"))
    qid = await questionary.select(
        "recent (pick to view):", choices=choices, style=QSTYLE,
    ).ask_async()
    # Robust back-detection: questionary may return None, the sentinel string,
    # or the literal label depending on the version installed.
    if qid is None or qid == "__BACK__" or qid == "← back" or not isinstance(qid, int):
        return
    q = await db.get_query(qid)
    hits = await db.hits_for(qid)
    if q is None:
        console.print(f"[{tokens.BAD}]query not found[/]")
        return
    t = Table(title=f"[bold]history #{qid}[/] · {q.kind.value} · {q.value}",
              expand=True, header_style=f"bold {tokens.ACCENT}",
              border_style=tokens.DIM, box=None)
    t.add_column("", width=2)
    t.add_column("module", style=tokens.DIM, width=12)
    t.add_column("source", width=24)
    t.add_column("evidence", overflow="fold")
    t.add_column("url", overflow="ellipsis", max_width=40, style=tokens.ACCENT)
    for h in hits:
        if h.status in (HitStatus.FOUND, HitStatus.RATELIMITED):
            t.add_row(_status_marker(h.status), h.module, h.source,
                      h.detail[:120], h.url or "")
    console.print(t)


async def action_modules() -> None:
    """k9s-style modules table — interactive: arrow-select to toggle enable/disable."""
    r = runner()
    await _render_modules_table(r)
    # Interactive toggle loop
    _BACK_LABEL = "  ← back to main menu"
    while True:
        mods = r.all_modules()
        # Use a sentinel string ("__BACK__") instead of None so questionary
        # versions that echo the label still let us detect "back".
        choices = []
        for m in mods:
            mark = "●" if m.enabled else "○"
            label = f"  {mark}  {m.name:<18}  {'on' if m.enabled else 'off'}"
            choices.append(Choice(label, value=m.name))
        # Reload + refresh sub-action so users can hot-refresh the table.
        choices.append(Choice("  ↻ refresh health view", value="__REFRESH__"))
        choices.append(Choice("  ⊕ enable all",  value="__ENABLE_ALL__"))
        choices.append(Choice("  ⊖ disable all", value="__DISABLE_ALL__"))
        choices.append(Choice(_BACK_LABEL,       value="__BACK__"))
        pick = await questionary.select(
            "toggle a module:",
            choices=choices,
            style=QSTYLE,
            qmark="",
            instruction="(↵ flip enabled/disabled  ·  ← back)",
        ).ask_async()
        # Robust back-detection: None (ctrl-C), the label string, or our sentinel.
        if pick is None or pick == "__BACK__" or pick == _BACK_LABEL or "back to main" in (pick or ""):
            break
        if pick == "__REFRESH__":
            await _render_modules_table(r)
            continue
        if pick == "__ENABLE_ALL__":
            for m in mods:
                r.set_enabled(m.name, True)
            console.print(f"[{tokens.OK}]✓ enabled all {len(mods)} modules[/]")
            continue
        if pick == "__DISABLE_ALL__":
            for m in mods:
                r.set_enabled(m.name, False)
            console.print(f"[{tokens.WARN}]✓ disabled all {len(mods)} modules[/]")
            continue
        # Toggle and refresh
        target = next((m for m in mods if m.name == pick), None)
        if target:
            r.set_enabled(pick, not target.enabled)
            console.print(
                f"[{tokens.OK if not target.enabled else tokens.WARN}]"
                f"{'enabled' if not target.enabled else 'disabled'}[/]  {pick}"
            )


async def _render_modules_table(r: Runner) -> None:
    """Render the k9s-style table (no questionary)."""

    # Header line
    mods = r.all_modules()
    n_active = sum(1 for m in mods if m.enabled)
    header = Text("   ")
    header.append("bluetm·uz", style=f"bold {tokens.ACCENT}")
    header.append("   modules  ·  ", style=tokens.DIM)
    header.append(str(n_active), style=f"bold {tokens.OK}")
    header.append(" active", style=tokens.DIM)
    try:
        from app.modules.username import load_sites
        n_sites = len(load_sites())
        header.append("  ·  ", style=tokens.DIM)
        header.append(f"{n_sites:,}", style=tokens.FG)
        header.append(" probe targets", style=tokens.DIM)
    except Exception:
        pass

    col_widths = (14, 38, 12, 8, 8, 30)
    t = Table.grid(padding=(0, 2))
    for w in col_widths:
        t.add_column(width=w, overflow="ellipsis", no_wrap=True)
    headers = ("NAME", "KINDS", "HEALTH", "STATE", "GLYPH", "7d")
    t.add_row(*[Text(h, style=f"bold {tokens.ACCENT}") for h in headers])
    t.add_row(*[Text("─" * max(2, w - 2), style=tokens.DIM) for w in col_widths])

    from app.ui.health import get_module_history, render_module_sparkline

    for i, m in enumerate(mods):
        kinds = ", ".join(k.value for k in sorted(m.kinds, key=lambda k: k.value))
        history = get_module_history(m.name, limit=7)
        if m.enabled:
            if history and history[-1][1] == "failed":
                health_text, dot, colour = "failed", "●", tokens.BAD
            elif history and history[-1][1] == "degraded":
                health_text, dot, colour = "degraded", "●", tokens.WARN
            elif history:
                health_text, dot, colour = "healthy", "●", tokens.OK
            else:
                health_text, dot, colour = "untested", "○", tokens.DIM
        else:
            health_text, dot, colour = "disabled", "○", tokens.DIM
        state = "ready" if m.enabled else "off"
        glyph = tokens.MODULE_GLYPHS.get(m.name, "") or "—"
        # Real 7-day sparkline from the persisted health store. Falls back to
        # dim dots when the module hasn't been exercised yet.
        spark = render_module_sparkline(m.name, limit=7)
        sel = i == 0
        pfx = "❯ " if sel else "  "
        name_cell = Text(pfx + m.name,
                         style=f"bold {tokens.ACCENT}" if sel else f"bold {tokens.FG}")
        t.add_row(
            name_cell,
            Text(kinds, style=tokens.DIM),
            Text(f"{dot} {health_text}", style=colour),
            Text(state, style=tokens.FG if m.enabled else tokens.DIM),
            Text(glyph, style=tokens.FG),
            spark,
        )

    console.print()
    console.print(header)
    console.print()
    console.print(t)
    console.print()


# ============================================================================
# v4.3 chat-shell slash handlers — keep them small + chained-friendly
# ============================================================================

# Session-level state carried across consecutive prompts. Survives /clear but
# resets on process exit. Read by action_lookup → _stream_run via env vars.
_CHAT_STATE: dict[str, object] = {
    "profile": None,          # str | None — applied to next scan if set
    "explain": False,         # bool — adds --explain on next scan
    "opsec":   False,         # bool — sets OSINT_OPSEC=1 for next scan
    "last_query": None,       # Query | None — used by /export
    "last_hits":  None,       # list[Hit] | None
    "last_elapsed_ms": 0,
    # Wave A — the externalised pattern the next /explain should use.
    "pattern": "exec-summary",
    # Wave B — remember last typed target so `/agent` (no arg) can default to it
    "last_target": "",
    # Wave B — agent approval posture for this session. False = confirm each
    # plan (the CLI default); True = auto-approve (set via `/agent auto`).
    "agent_auto_approve": False,
}


async def _slash_profile(arg: str) -> None:
    """`/profile` — list / set / clear the per-session default profile."""
    from app.core.profiles import PROFILES
    a = (arg or "").strip().lower()
    if not a or a == "list":
        cur = _CHAT_STATE.get("profile") or "(none)"
        console.print(f"   [{tokens.DIM}]current profile:[/] [{tokens.ACCENT}]{cur}[/]")
        console.print(f"   [{tokens.DIM}]available:[/]")
        for name in PROFILES:
            console.print(f"     [{tokens.FG}]{name}[/]  [{tokens.DIM}]· {len(PROFILES[name])} modules[/]")
        return
    if a in ("off", "none", "clear", "-"):
        _CHAT_STATE["profile"] = None
        console.print(f"   [{tokens.OK}]✓ profile cleared[/]")
        return
    if a not in PROFILES:
        from difflib import get_close_matches
        sug = get_close_matches(a, list(PROFILES.keys()), n=2, cutoff=0.4)
        hint = f" — did you mean: {', '.join(sug)}?" if sug else ""
        console.print(f"   [{tokens.BAD}]unknown profile {a!r}[/]{hint}")
        return
    _CHAT_STATE["profile"] = a
    console.print(f"   [{tokens.OK}]✓ profile set →[/] [{tokens.ACCENT}]{a}[/] [{tokens.DIM}]· applies to next scan[/]")


async def _slash_graph(arg: str) -> None:
    """`/graph [show|stats|export|forget] [args]` — inline entity-graph ops."""
    from app.features.graph import cmd_graph
    parts = (arg or "stats").strip().split() or ["stats"]
    try:
        # cmd_graph is a SYNC handler that runs its OWN event loop internally
        # (asyncio.run). `await`-ing its int result raised TypeError and broke
        # /graph entirely; calling it directly here would also fail ("event loop
        # already running"). Off-load to a worker thread — same pattern as
        # _slash_cli_verb uses for the other sync CLI handlers.
        await asyncio.to_thread(cmd_graph, parts)
    except SystemExit:
        pass  # cmd_graph may sys.exit on error — keep the prompt alive
    except Exception as e:
        console.print(f"   [{tokens.BAD}]graph error:[/] {type(e).__name__}: {e}")


def _slash_opsec_toggle(arg: str) -> None:
    """`/opsec [on|off]` — set the per-session OPSEC flag."""
    a = (arg or "").strip().lower()
    if a in ("on", "1", "true", "yes"):
        _CHAT_STATE["opsec"] = True
    elif a in ("off", "0", "false", "no"):
        _CHAT_STATE["opsec"] = False
    else:
        _CHAT_STATE["opsec"] = not _CHAT_STATE["opsec"]
    state = "ON" if _CHAT_STATE["opsec"] else "OFF"
    style = tokens.WARN if _CHAT_STATE["opsec"] else tokens.DIM
    console.print(f"   [{style}]⚑ OPSEC mode → {state}[/]  [{tokens.DIM}]· applies to next scan[/]")
    if _CHAT_STATE["opsec"]:
        console.print(f"   [{tokens.DIM}]SOCKS5 127.0.0.1:9050 · jitter · UA rotation · active modules refuse unless overridden[/]")


def _slash_explain_toggle() -> None:
    """`/explain` — toggle AI explain on the next scan."""
    _CHAT_STATE["explain"] = not _CHAT_STATE["explain"]
    state = "ON" if _CHAT_STATE["explain"] else "OFF"
    console.print(f"   [{tokens.ACCENT}]🤖 AI explain → {state}[/]")
    if _CHAT_STATE["explain"]:
        # We don't hard-fail here — `osint ai` resolves the provider, which
        # might be local Ollama instead of Claude. Just nudge if neither is
        # configured.
        from app.features.ai import NoneProvider, select_provider
        if isinstance(select_provider(), NoneProvider):
            console.print(
                f"   [{tokens.WARN}]no LLM available — "
                f"run `osint doctor` for setup hints[/]",
            )


def _slash_pattern(arg: str) -> None:
    """`/pattern [name|list]` — choose the explain pattern (Fabric-style)."""
    from app.features.patterns import list_patterns, load_pattern
    a = (arg or "").strip().lower()
    if not a or a == "list":
        names = list_patterns()
        cur = _CHAT_STATE.get("pattern") or "(default)"
        console.print(f"   [{tokens.DIM}]current pattern:[/] [{tokens.ACCENT}]{cur}[/]")
        if names:
            console.print(f"   [{tokens.DIM}]available:[/]")
            for n in names:
                console.print(f"     [{tokens.FG}]{n}[/]")
        return
    try:
        load_pattern(a)
    except FileNotFoundError as e:
        console.print(f"   [{tokens.BAD}]{e}[/]")
        return
    _CHAT_STATE["pattern"] = a
    console.print(
        f"   [{tokens.OK}]✓ pattern set →[/] [{tokens.ACCENT}]{a}[/] "
        f"[{tokens.DIM}]· used by /explain[/]",
    )


async def _slash_agent(arg: str) -> None:
    """`/agent [target] [--yes|--no-approve]` — run the Wave B ReAct loop.

    With no target, falls back to the last typed value (usually the most recent
    scan target).

    Approval posture matches the CLI (`osint agent`): the model emits a one-line
    PLAN and we require an inline y/N approval BEFORE any tool runs (and before
    we spend LLM tokens on tool execution). Opt out per-call with `--yes` /
    `--no-approve`, or for the whole session with `/agent auto` (toggle back
    with `/agent confirm`). This closes the old gap where the chat shell
    auto-approved silently while the CLI prompted.
    """
    parts = (arg or "").split()
    no_approve = any(p in ("--yes", "-y", "--no-approve") for p in parts)
    rest = [p for p in parts if p not in ("--yes", "-y", "--no-approve")]

    # Session-level toggle: `/agent auto` / `/agent confirm`.
    if rest and rest[0] in ("auto", "confirm"):
        _CHAT_STATE["agent_auto_approve"] = (rest[0] == "auto")
        state = "AUTO-APPROVE" if _CHAT_STATE["agent_auto_approve"] else "CONFIRM (y/N)"
        console.print(f"   [{tokens.ACCENT}]agent approval → {state}[/]")
        return

    target = " ".join(rest).strip() or str(_CHAT_STATE.get("last_target") or "")
    if not target:
        console.print(
            f"   [{tokens.WARN}]/agent: no target — type one first, or `/agent <target>`[/]",
        )
        return
    from app.features.agent import AgentLoop
    from app.features.ai import NoneProvider, select_provider

    if isinstance(select_provider(), NoneProvider):
        console.print(
            f"   [{tokens.WARN}]no LLM available — run `osint doctor` for setup hints[/]",
        )
        return

    # Reuse the same kind-inference the lookup prompt uses.
    kind = _auto_kind(target)
    if kind is None:
        console.print(
            f"   [{tokens.WARN}]ambiguous target {target!r} — type it through the prompt first[/]",
        )
        return
    query = Query(kind=kind, value=target)

    def _stream(step_kind: str, text: str, n_tok: int) -> None:
        badge = {
            "plan":        "[bold]plan[/]       ",
            "thought":     "thought    ",
            "action":      "action     ",
            "observation": "observation",
            "answer":      "[bold]answer[/]     ",
            "error":       f"[{tokens.BAD}]error[/]      ",
        }.get(step_kind, step_kind)
        snippet = text.strip().splitlines()[0] if text.strip() else ""
        if len(snippet) > 160:
            snippet = snippet[:157] + "…"
        suffix = f"  [{tokens.DIM}]{n_tok}t[/]" if n_tok else ""
        console.print(f"   [{tokens.DIM}]·[/] {badge}  {snippet}{suffix}")

    # Inline approver — surfaces the plan, defaults to reject (same as CLI).
    async def _approve(plan: str) -> bool:
        console.print(f"   [bold {tokens.ACCENT}]agent plan:[/] {plan}")
        try:
            return bool(await questionary.confirm(
                "approve this plan and let the agent run its tools?",
                default=False, style=QSTYLE,
            ).ask_async())
        except Exception:
            return False

    # Skip the prompt only if the caller opted out (--yes) or the session is in
    # auto mode. Default = confirm, identical to the CLI default.
    auto = no_approve or bool(_CHAT_STATE.get("agent_auto_approve"))
    approve = None if auto else _approve
    if auto:
        console.print(
            f"   [{tokens.DIM}]up to 8 steps / 4000 tokens via the active provider · "
            f"auto-approved · Ctrl-C to cancel[/]",
        )

    loop = AgentLoop()
    try:
        result = await loop.run(
            query, max_steps=8, max_tokens=4000, on_step=_stream, approve=approve,
        )
    except asyncio.CancelledError:
        console.print(f"   [{tokens.WARN}]agent cancelled[/]")
        raise
    if result.status == "rejected":
        console.print(f"   [{tokens.WARN}]plan rejected — no tools ran[/]")
        return
    console.print(
        f"   [{tokens.DIM}]status={result.status} · steps={len(result.steps)} · "
        f"tokens={result.tokens['in']}/{result.tokens['out']} · "
        f"{result.elapsed_ms}ms[/]",
    )
    if result.status == "done" and result.answer:
        console.print(f"   [{tokens.OK}]✓ {result.answer}[/]")


async def _slash_cli_verb(verb: str, arg: str) -> None:
    """Run a Wave D CLI verb (`/case`, `/rules`, `/playbook`, `/schedule`,
    `/diff`, `/watch`, `/doctor`) from inside the chat shell.

    These reuse the exact CLI handlers — we do NOT duplicate their logic.
    Each handler synchronously calls ``asyncio.run`` internally, so we off-load
    to a worker thread to avoid nesting event loops (same pattern as /settings).
    Calling with no args prints the handler's own usage (returns 0/2).
    """
    import shlex

    argv = shlex.split(arg) if arg else []

    # `/schedule install` writes + enables a persistent OS job. The CLI already
    # previews by default and requires --apply; mirror that gate here, and add
    # an explicit inline confirmation before we ever pass --apply through.
    if verb == "schedule" and argv and argv[0] == "install":
        wants_apply = ("--apply" in argv) or ("--confirm" in argv)
        if wants_apply:
            try:
                ok = await questionary.confirm(
                    "schedule install will write + ENABLE a persistent OS job. "
                    "Proceed?",
                    default=False, style=QSTYLE,
                ).ask_async()
            except Exception:
                ok = False
            if not ok:
                console.print(
                    f"   [{tokens.WARN}]cancelled[/] — re-running as a preview "
                    f"[{tokens.DIM}](nothing will be written)[/]",
                )
                argv = [a for a in argv if a not in ("--apply", "--confirm")]

    # Lazy import the handler so a missing optional dep degrades to a message.
    def _resolve() -> Callable[..., Any] | None:
        if verb == "case":
            from cli import _handle_case_subcommand as h
            return h
        if verb == "diff":
            from cli import _handle_diff_subcommand as h
            return h
        if verb == "watch":
            from cli import _handle_watch_subcommand as h
            return h
        if verb == "rules":
            from app.features.correlation import cmd_rules as h
            return h
        if verb == "playbook":
            from app.features.playbooks import cmd_playbook as h
            return h
        if verb == "schedule":
            from app.features.scheduler import cmd_schedule as h
            return h
        if verb == "doctor":
            from app.features.doctor import cmd_doctor as h
            return h
        return None

    try:
        handler = await asyncio.to_thread(_resolve)
    except Exception as e:
        console.print(f"   [{tokens.BAD}]/{verb} unavailable:[/] {type(e).__name__}: {e}")
        return
    if handler is None:
        console.print(f"   [{tokens.BAD}]unknown verb {verb!r}[/]")
        return
    try:
        await asyncio.to_thread(handler, argv)
    except SystemExit:
        pass  # some handlers sys.exit on bad args — keep the prompt alive
    except Exception as e:
        console.print(f"   [{tokens.BAD}]/{verb} error:[/] {type(e).__name__}: {e}")


async def _slash_export(db: Database, arg: str) -> None:
    """`/export <csv|json|jsonl|md|html> [PATH]` — re-render the last scan.

    Uses the SAME ``export_hits`` helper as the menu export, so both paths
    serialise identically (model_dump, not pydantic __dict__) and default to
    ``exports_dir`` rather than the cwd. An explicit PATH still wins.
    """
    a = (arg or "html").strip().split()
    fmt = (a[0] if a else "html").lower()
    out = a[1] if len(a) > 1 else None
    q = _CHAT_STATE.get("last_query")
    hits = _CHAT_STATE.get("last_hits")
    if q is None or hits is None:
        console.print(f"   [{tokens.WARN}]no scan to export yet — run one first[/]")
        return
    # _CHAT_STATE is an untyped state bag; last_query/last_hits are set together
    # after a scan, so they are a Query and a list[Hit] here.
    q = cast("Query", q)
    hits = cast("list[Hit]", hits)
    try:
        path = export_hits(
            q, list(hits), fmt,
            elapsed_ms=int(cast("int", _CHAT_STATE.get("last_elapsed_ms", 0)) or 0),
            path=out,
        )
    except ValueError:
        console.print(
            f"   [{tokens.BAD}]unknown format {fmt!r}[/] — use "
            + " | ".join(EXPORT_FORMATS),
        )
        return
    except Exception as e:
        console.print(f"   [{tokens.BAD}]export failed:[/] {type(e).__name__}: {e}")
        return
    console.print(f"   [{tokens.OK}]✓ {fmt} →[/] [{tokens.ACCENT}]{path}[/]")


async def _action_theme_picker() -> None:
    """v4.2 theme switcher — pick from 7 palettes, persist to ~/.config."""
    from app.ui.tokens import ACTIVE, THEMES, persist_theme
    current_name = next(
        (k for k, v in THEMES.items()
         if v.ACCENT == ACTIVE.ACCENT and v.BG_HINT == ACTIVE.BG_HINT),
        "github-dark",
    )
    # Render swatches with rich markup THEN format the Choice label.
    # questionary doesn't parse rich tags, so we pre-render swatches via Text/console.
    # Workaround: emit raw ANSI 24-bit color in the label string itself.
    def _swatch(hex_color: str, ch: str = "██") -> str:
        # hex like "#BD93F9" → ANSI 24-bit "\x1b[38;2;R;G;Bm{ch}\x1b[0m"
        h = hex_color.lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return f"\x1b[38;2;{r};{g};{b}m{ch}\x1b[0m"

    choices = []
    for name, tk in THEMES.items():
        marker = "●" if name == current_name else "○"
        sample = (_swatch(tk.ACCENT) + _swatch(tk.OK)
                  + _swatch(tk.WARN) + _swatch(tk.BAD))
        label = f"  {marker}  {name:<22}  {sample}"
        choices.append(Choice(label, value=name))
    choices.append(Choice("  ← back (keep current)", value="__BACK__"))
    # questionary's `default` is matched against Choice.value, not label.
    # Pass the current theme NAME so cursor lands on the active row.
    pick = await questionary.select(
        "pick a theme (saved to ~/.config/mytools-osint/theme):",
        choices=choices, style=QSTYLE, qmark="",
        default=current_name,  # cursor starts on the active theme
        instruction="(↑↓ navigate · ↵ apply · ← back)",
    ).ask_async()
    if pick is None or pick == "__BACK__":
        return
    persist_theme(pick)
    console.print(
        f"[{tokens.OK}]✓ theme saved → [b]{pick}[/]; "
        f"restart osint to apply everywhere (most colors update on next screen).[/]"
    )


async def _press_enter() -> None:
    """Pause until the user acknowledges — used after read-only screens."""
    try:
        await questionary.text(
            "press Enter to return", style=QSTYLE, qmark="", instruction="",
            default="",
        ).ask_async()
    except Exception:
        pass


async def action_stats() -> None:
    """Sites stats — categorised bar chart per design handoff."""
    from app.modules.username import load_sites
    sites = load_sites()
    cats = Counter((s.get("category") or "uncategorised") for s in sites)
    total = sum(cats.values())

    header = Text("   ")
    header.append("bluetm·uz", style=f"bold {tokens.ACCENT}")
    header.append("   sites  ·  ", style=tokens.DIM)
    header.append(f"{total:,}", style=f"bold {tokens.FG}")
    header.append(" probe targets across ", style=tokens.DIM)
    header.append(str(len(cats)), style=f"bold {tokens.FG}")
    header.append(" categories", style=tokens.DIM)

    t = Table.grid(padding=(0, 2))
    t.add_column(width=22)
    t.add_column(width=6, justify="right")
    t.add_column(width=32)
    t.add_column(ratio=1)
    t.add_row(
        Text("CATEGORY", style=f"bold {tokens.ACCENT}"),
        Text("COUNT", style=f"bold {tokens.ACCENT}"),
        Text("SHARE", style=f"bold {tokens.ACCENT}"),
        Text("", style=tokens.DIM),
    )
    t.add_row(
        Text("─" * 20, style=tokens.DIM),
        Text("──", style=tokens.DIM),
        Text("─" * 30, style=tokens.DIM),
        Text("", style=tokens.DIM),
    )
    mx = max(cats.values()) if cats else 1
    for cat, n in cats.most_common(25):
        pct = n / total * 100 if total else 0
        bar = "█" * max(1, int(n / mx * 28))
        t.add_row(
            Text(cat, style=tokens.FG),
            Text(f"{n}", style=f"bold {tokens.FG}"),
            Text(bar, style=tokens.ACCENT),
            Text(f"{pct:>4.1f}%", style=tokens.DIM),
        )
    console.print()
    console.print(header)
    console.print()
    console.print(t)
    console.print()
    footer = Text("   extend via: ", style=tokens.DIM)
    footer.append("scripts/sync_sherlock.py", style=tokens.ACCENT)
    footer.append("  ·  ", style=tokens.DIM)
    footer.append("scripts/sync_whatsmyname.py", style=tokens.ACCENT)
    console.print(footer)
    console.print()
    await _press_enter()


async def action_settings_overview() -> None:
    s = settings()
    t = Table(title=f"[bold]settings — by {BRAND}[/]", expand=False,
              border_style=tokens.DIM, header_style=f"bold {tokens.ACCENT}")
    t.add_column("key")
    t.add_column("status")
    rows = [
        ("HIBP",            "set" if s.has_hibp else "not set (free: XposedOrNot, HudsonRock, ProxyNova)"),
        ("Numverify",       "set" if s.has_numverify else "not set (libphonenumber works offline)"),
        ("IPinfo",          "set" if s.has_ipinfo else "not set (rDNS still works)"),
        ("Telegram MTProto","configured" if s.has_telegram else "not set"),
        ("LeakCheck",       "set" if s.has_leakcheck else "not set"),
        ("Concurrency",     str(s.http_concurrency)),
        ("Timeout (sec)",   str(s.http_timeout_sec)),
        ("Data dir",        str(s.data_dir)),
    ]
    for k, v in rows:
        t.add_row(k, v)
    console.print(t)


# ---- main loop --------------------------------------------------------------

async def run_interactive(show_figlet: bool = False, classic: bool = False) -> int:
    """Top-level interactive shell. Returns process exit code.

    Default (v4.3): chat-style — `osint` opens straight into a persistent
    prompt. Type a target → scan runs inline → prompt returns. Slash
    commands replace menu navigation entirely.

    Pass ``classic=True`` (CLI: ``--classic``) to use the menu-based shell
    from v4.2.x — the one with `pick_action()` on launch.
    """
    from app import __version__ as _ver
    if show_figlet:
        from app.ui.banner import ASCII_ART
        console.print(Text(ASCII_ART, style=tokens.ACCENT))

    try:
        from app.modules.username import load_sites
        n_sites = len(load_sites())
    except Exception:
        n_sites = 0
    r = runner()
    n_modules = len(r.all_modules())

    title_line = Text("   ")
    title_line.append("mytools-osint ", style=tokens.FG)
    title_line.append(f"v{_ver} ", style=tokens.DIM)
    title_line.append("— by ", style=tokens.FG)
    title_line.append("Bluetm.uz", style=f"bold {tokens.ACCENT}")
    console.print(title_line)

    status_line = Text("   ")
    status_line.append("●", style=tokens.OK)
    status_line.append(" online ", style=tokens.DIM)
    status_line.append("·", style=tokens.DIM)
    status_line.append(f" {n_sites:,} ", style=tokens.FG)
    status_line.append("sites", style=tokens.DIM)
    status_line.append(" · ", style=tokens.DIM)
    status_line.append(f"{n_modules} ", style=tokens.FG)
    status_line.append("modules", style=tokens.DIM)
    status_line.append(" · ", style=tokens.DIM)
    status_line.append("free APIs", style=tokens.FG)
    status_line.append(" · ", style=tokens.DIM)
    status_line.append("authorised use only", style=tokens.DIM)
    console.print(status_line)
    console.print()

    s = settings()
    db = Database(s.db_path)
    await db.connect()
    try:
        if classic:
            # ---- Legacy menu-based shell (v4.2.x behaviour) ---------------
            from app.ui.main_menu import pick_action
            while True:
                choice = await pick_action()
                if choice in (None, "exit"):
                    console.print(f"\n[{tokens.DIM}]bye — {BRAND}[/]\n")
                    return 0
                if choice == "lookup":
                    if not await action_lookup(db):
                        return 0
                elif choice == "history":
                    await action_history(db)
                elif choice == "modules":
                    await action_modules()
                elif choice == "stats":
                    await action_stats()
                elif choice == "settings":
                    import asyncio as _asyncio

                    from app.ui.config_cli import cmd_wizard
                    try:
                        await _asyncio.to_thread(cmd_wizard)
                    except Exception as e:
                        console.print(f"[{tokens.BAD}]settings wizard error:[/] {e}")
                elif choice == "palette":
                    from app.ui.command_palette import build_palette, open_palette
                    async def _db_factory() -> Database:
                        return db
                    try:
                        await open_palette(build_palette(_db_factory))
                    except Exception as e:
                        console.print(f"[{tokens.BAD}]palette error:[/] {e}")
                elif choice == "help":
                    await show_help("main")
                    await _press_enter()
                elif choice == "theme":
                    await _action_theme_picker()
            return 0

        # ---- Default v4.3: chat-style persistent prompt -------------------
        # Print a Claude-Code-style help hint once at start.
        hint = Text("   ")
        hint.append("type a target ", style=tokens.DIM)
        hint.append("·", style=tokens.DIM)
        hint.append(" /help", style=tokens.ACCENT)
        hint.append(" for commands ", style=tokens.DIM)
        hint.append("·", style=tokens.DIM)
        hint.append(" /quit", style=tokens.ACCENT)
        hint.append(" to exit ", style=tokens.DIM)
        hint.append("·", style=tokens.DIM)
        hint.append(" --classic", style=tokens.DIM)
        hint.append(" for the legacy menu", style=tokens.DIM)
        console.print(hint)

        # The prompt loop lives entirely inside action_lookup; it recurses
        # to itself after every command + every scan. /quit returns False.
        while True:
            should_continue = await action_lookup(db)
            if not should_continue:
                console.print(f"\n[{tokens.DIM}]bye — {BRAND}[/]\n")
                return 0
    except (KeyboardInterrupt, EOFError):
        console.print(f"\n[{tokens.DIM}]bye — {BRAND}[/]\n")
        return 130
    finally:
        await db.close()
