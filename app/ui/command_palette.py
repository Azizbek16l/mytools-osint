"""Command palette — vscode/sublime-style fuzzy launcher for any action.

Triggered with `/` from the interactive shell or via `osint palette` CLI.

Aggregates every navigable action in the app (top-level menus + sub-actions +
profile presets + module toggles + saved targets) into a single flat list
with fuzzy filter. Pick → execute immediately.

Why this matters: 11 profiles × 32 modules × 9 sub-commands × 6 menus is a
lot of surface. A palette gives the user one keypress (`/`) to jump
straight to whatever they need without remembering menu paths.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.db import Database
from dataclasses import dataclass, field

from app.core.profiles import PROFILES
from app.core.runner import runner


@dataclass(slots=True)
class PaletteAction:
    """A single palette entry."""

    label: str                                 # what the user sees in the picker
    group: str                                 # tag for grouping (e.g. "profile", "module")
    handler: Callable[[], Awaitable[int]]      # async callable that performs the action
    keywords: list[str] = field(default_factory=list)


def build_palette(db_factory: Callable[[], Awaitable[Database]]) -> list[PaletteAction]:
    """Build the standard palette. db_factory is a callable that returns a Database."""
    from app.ui import interactive as ix

    actions: list[PaletteAction] = []

    # Top-level navigations
    async def _nav_lookup() -> int:
        db = await db_factory()
        await ix.action_lookup(db)
        return 0

    async def _nav_history() -> int:
        db = await db_factory()
        await ix.action_history(db)
        return 0

    async def _nav_modules() -> int:
        await ix.action_modules()
        return 0

    async def _nav_stats() -> int:
        await ix.action_stats()
        return 0

    actions.extend([
        PaletteAction("⌕  new lookup", "nav", _nav_lookup,
                      ["lookup", "search", "query", "scan"]),
        PaletteAction("⊜  recent history", "nav", _nav_history,
                      ["history", "log", "past", "previous"]),
        PaletteAction("◫  modules table", "nav", _nav_modules,
                      ["modules", "enable", "disable", "toggle"]),
        PaletteAction("◐  sites breakdown", "nav", _nav_stats,
                      ["sites", "stats", "sources"]),
    ])

    # Profile presets — clicking applies the profile + opens lookup
    for prof_name, prof_set in PROFILES.items():
        if prof_name in ("default", "all"):
            continue

        async def _apply_profile(p: str = prof_name) -> int:
            from app.core.profiles import apply_profile
            r = runner()
            apply_profile(r, p)
            db = await db_factory()
            await ix.action_lookup(db)
            return 0

        actions.append(PaletteAction(
            f"⚙  profile · {prof_name}",
            "profile",
            _apply_profile,
            ["profile", prof_name, *prof_set],
        ))

    # Per-module toggle entries (so user can hit `/email_security` and toggle)
    r = runner()
    for m in r.all_modules():
        async def _toggle(name: str = m.name) -> int:
            r2 = runner()
            for mod in r2.all_modules():
                if mod.name == name:
                    r2.set_enabled(name, not mod.enabled)
                    return 0
            return 1

        actions.append(PaletteAction(
            f"◉  toggle · {m.name}", "module", _toggle,
            ["toggle", "module", m.name, *(k.value for k in m.kinds)],
        ))

    # Shortcuts to sub-commands
    async def _opsec() -> int:
        from app.features.opsec_check import cmd_opsec_check
        return cmd_opsec_check()

    async def _cache_stats() -> int:
        from app.core.cache import cmd_cache
        return cmd_cache(["stats"])

    async def _serve() -> int:
        from app.ui.web import serve
        return serve()

    actions.extend([
        PaletteAction("⚇  opsec-check (verify Tor + UA + jitter)", "cmd", _opsec,
                      ["opsec", "tor", "ua", "jitter", "leak"]),
        PaletteAction("◰  cache stats", "cmd", _cache_stats,
                      ["cache", "stats", "size"]),
        PaletteAction("◧  serve (local web dashboard)", "cmd", _serve,
                      ["serve", "web", "dashboard", "ui"]),
    ])
    return actions


async def open_palette(actions: list[PaletteAction]) -> int:
    """Show fuzzy picker; run the selected action."""
    import questionary
    from questionary import Choice

    from app.ui.interactive import QSTYLE

    choices = [Choice(a.label, value=i) for i, a in enumerate(actions)]
    choices.append(Choice("← cancel", value="__BACK__"))
    pick = await questionary.select(
        "/  command palette  (type to filter):",
        choices=choices,
        style=QSTYLE,
        qmark="/",
        use_search_filter=True,
        use_jk_keys=False,  # questionary 2.1.1 rejects search-filter + jk together
        instruction="(type to fuzzy-filter · ↵ run · esc cancel)",
    ).ask_async()
    if pick is None or pick == "__BACK__" or not isinstance(pick, int):
        return 0
    if 0 <= pick < len(actions):
        return await actions[pick].handler()
    return 0
