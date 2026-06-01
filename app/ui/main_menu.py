"""Single-fire main menu (v4.2) — prompt_toolkit Application.

Replaces the `questionary.select` main menu so shortcut keys fire INSTANTLY
on a single keypress (no Enter needed). Matches the convention set by
lazygit, k9s, btop, helix, claude code.

Public surface:
    >>> from app.ui.main_menu import pick_action
    >>> action = await pick_action()  # → "lookup" | "history" | … | "exit"

Behaviour:
    l   lookup       h   history     m   modules       s   sites
    p   palette      t   settings    i   info/help     T   theme picker
    q   quit         Esc / Ctrl-D / Ctrl-C  → "exit"
    ↑↓ + Enter still navigate (familiar fallback for keyboard purists).
"""
from __future__ import annotations

from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.key_binding.key_processor import KeyPressEvent
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.styles import Style

from app.ui import tokens

# (key, action_id, label, description)
# Label matches key case so users can tell lowercase `t` (settings) apart from
# Shift+T (theme picker). All lowercase except the explicit Shift modifier.
_ENTRIES: list[tuple[str, str, str, str]] = [
    ("l", "lookup",   "l", "new lookup           single prompt with auto-detect"),
    ("h", "history",  "h", "recent history       last 50 queries · resume any"),
    ("m", "modules",  "m", "modules              k9s-style table · health · 7d"),
    ("s", "stats",    "s", "sites                Sherlock + WhatsMyName breakdown"),
    ("p", "palette",  "p", "command palette      fuzzy launcher for any action"),
    ("t", "settings", "t", "settings             API keys · Telegram · paths"),
    ("i", "help",     "i", "info / help          keybindings, profiles, sub-commands"),
    ("T", "theme",    "⇧T", "theme picker        pick palette: dracula, nord, …"),
    ("q", "exit",     "q", "exit"),
]


def _style() -> Style:
    return Style.from_dict({
        "cursor":     f"fg:{tokens.ACCENT} bold",
        "row":        f"fg:{tokens.FG}",
        "row.dim":    f"fg:{tokens.DIM}",
        "shortcut":   f"fg:{tokens.ACCENT} bold",
        "header":     f"fg:{tokens.FG} bold",
        "footer":     f"fg:{tokens.DIM}",
        "footer.key": f"fg:{tokens.ACCENT}",
    })


def _render(cursor: int) -> list[tuple[str, str]]:
    """Build the styled fragment list for the current frame."""
    lines: list[tuple[str, str]] = []
    # Header
    lines.append(("class:header", "── main menu "))
    lines.append(("class:row.dim", "─" * 60 + "\n\n"))
    for i, (_key, _action, label, desc) in enumerate(_ENTRIES):
        is_cursor = (i == cursor)
        bullet = "▌ " if is_cursor else "  "
        cls = "class:cursor" if is_cursor else "class:row"
        lines.append((cls, f" {bullet}"))
        lines.append(("class:shortcut", f"[{label}] "))
        lines.append((cls, f" {desc}\n"))
    lines.append(("", "\n"))
    lines.append(("class:footer", "  "))
    for k, label in [("↑↓", "navigate"), ("↵", "select"),
                     ("l/h/m/s/p/t/i/T", "fire"), ("q/Esc", "quit")]:
        lines.append(("class:footer.key", k))
        lines.append(("class:footer", f" {label}   "))
    return lines


async def pick_action() -> str:
    """Show the menu and return one of the action ids in _ENTRIES, or 'exit'."""
    state: dict[str, int] = {"cursor": 0}

    def get_text() -> list[tuple[str, str]]:
        return _render(state["cursor"])

    kb = KeyBindings()

    # Single-fire shortcuts — the headline UX win.
    for key, action, _label, _desc in _ENTRIES:
        @kb.add(key, eager=True)
        def _(event: KeyPressEvent, _act: str = action) -> None:
            event.app.exit(result=_act)

    # Standard navigation.
    @kb.add("up")
    @kb.add("c-p")
    def _up(event: KeyPressEvent) -> None:
        state["cursor"] = (state["cursor"] - 1) % len(_ENTRIES)
        event.app.invalidate()

    @kb.add("down")
    @kb.add("c-n")
    @kb.add("tab")
    def _down(event: KeyPressEvent) -> None:
        state["cursor"] = (state["cursor"] + 1) % len(_ENTRIES)
        event.app.invalidate()

    @kb.add("enter")
    def _enter(event: KeyPressEvent) -> None:
        event.app.exit(result=_ENTRIES[state["cursor"]][1])

    @kb.add("escape")
    @kb.add("c-c")
    @kb.add("c-d")
    def _quit(event: KeyPressEvent) -> None:
        event.app.exit(result="exit")

    # Layout — single window, ~12 lines high (header + 9 rows + footer).
    body = Window(
        content=FormattedTextControl(get_text, focusable=True, show_cursor=False),
        always_hide_cursor=True,
        wrap_lines=False,
    )

    app: Application[str] = Application(
        layout=Layout(HSplit([body])),
        key_bindings=kb,
        style=_style(),
        full_screen=False,
        mouse_support=True,
    )
    result = await app.run_async()
    return result or "exit"
