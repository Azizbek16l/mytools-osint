"""Input layer for the interactive lookup prompt.

Carved out of `interactive.action_lookup` to keep that function readable. Bundles
the ergonomics expected by users coming from Claude Code, Gemini CLI, Aider and
Warp:

* persistent ``FileHistory`` under ``%LOCALAPPDATA%/MarsIT/mytools-osint/``
* fish-shell-style ghost-text auto-suggestions from history
* Tab completion across slash commands, the seven query kinds, and recent
  history entries (all wrapped in a ``FuzzyCompleter``)
* Ctrl-R reverse history search (native ``enable_history_search=True``)
* a small slash-command dispatcher with ``difflib`` "did you mean?" hints
* comma / Alt+Enter multi-target burst splitting

The PromptSession lives here too so ``interactive.py`` only orchestrates.
"""
from __future__ import annotations

import difflib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from platformdirs import user_data_path
from prompt_toolkit.completion import (
    Completer,
    Completion,
    FuzzyCompleter,
    merge_completers,
)
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory

from app.core.types import QueryKind

# --------------------------------------------------------------------------- #
# Slash command catalogue
# --------------------------------------------------------------------------- #

SlashName = Literal[
    "help", "clear", "history", "modules", "sites",
    "settings", "version", "kind", "quit",
    # v4.3 chat-shell additions
    "theme", "profile", "graph", "opsec", "explain", "export",
    # Wave A — pattern picker for AI explain
    "pattern",
]

# Canonical name → aliases (the canonical is always first). Used by the
# completer, the dispatcher, and the "did you mean?" suggester.
SLASH_ALIASES: dict[SlashName, tuple[str, ...]] = {
    "help":     ("/help", "/h", "/?"),
    "clear":    ("/clear", "/cls"),
    "history":  ("/history",),
    "modules":  ("/modules",),
    "sites":    ("/sites",),
    "settings": ("/settings", "/config"),
    "version":  ("/version", "/v"),
    "kind":     ("/kind",),
    "quit":     ("/quit", "/q", "/exit"),
    # v4.3 — chat-shell first-class actions
    "theme":    ("/theme", "/themes"),
    "profile":  ("/profile",),
    "graph":    ("/graph", "/g"),
    "opsec":    ("/opsec",),
    "explain":  ("/explain",),
    "export":   ("/export",),
    "pattern":  ("/pattern", "/patterns"),
}

# Flat list of every recognised slash spelling (sorted for stable completion).
ALL_SLASH_TOKENS: tuple[str, ...] = tuple(sorted({
    tok for aliases in SLASH_ALIASES.values() for tok in aliases
}))

# Short, one-line description per canonical action — surfaces as completion
# metadata so the user sees what each command does.
SLASH_DESCRIPTIONS: dict[SlashName, str] = {
    "help":     "show keybinding cheatsheet",
    "clear":    "clear the screen and restart the prompt",
    "history":  "browse the last 50 queries",
    "modules":  "k9s-style modules table · toggle on/off",
    "sites":    "Sherlock + WhatsMyName breakdown",
    "settings": "API keys · Telegram · paths",
    "version":  "print mytools-osint version + brand",
    "kind":     "force a query kind: /kind <username|email|…>",
    "quit":     "exit interactive mode",
    # v4.3
    "theme":    "pick a palette (dracula, nord, tokyo-night, …)",
    "profile":  "set or list profiles: /profile [name|list]",
    "graph":    "entity graph: /graph [show|stats|export] [args]",
    "opsec":    "toggle OPSEC mode for this session",
    "explain":  "toggle AI explain for the next scan",
    "export":   "export the last scan: /export <html|md|json|jsonl>",
    "pattern":  "pick or list AI explain patterns: /pattern [name|list]",
}

KIND_VALUES: tuple[str, ...] = tuple(k.value for k in QueryKind)


# --------------------------------------------------------------------------- #
# Slash dispatcher result
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class SlashAction:
    """Outcome of routing a `/`-prefixed input.

    ``action`` is one of:
        * a canonical name from ``SlashName`` — caller branches on it
        * ``"unknown"`` — ``message`` carries a "did you mean?" hint to print
        * ``"noop"`` — fall through to a fresh prompt (used by /clear etc.)
    """

    action: str
    arg: str = ""
    message: str = ""


def dispatch_slash(line: str) -> SlashAction:
    """Map a raw `/cmd ...` line to a :class:`SlashAction`.

    Splits on whitespace **or** ``=`` so both ``/kind email`` and
    ``/kind=email`` work. Unknown commands return ``action='unknown'`` with a
    ``difflib``-powered hint.
    """
    raw = line.strip()
    if not raw.startswith("/"):
        return SlashAction(action="noop")
    # split on first whitespace OR '='
    head = raw
    arg = ""
    for sep in (" ", "\t", "="):
        if sep in raw:
            head, arg = raw.split(sep, 1)
            break
    head = head.strip().lower()
    arg = arg.strip()

    for canonical, aliases in SLASH_ALIASES.items():
        if head in aliases:
            return SlashAction(action=canonical, arg=arg)

    # Unknown — propose close matches against every recognised spelling.
    suggestions = difflib.get_close_matches(head, ALL_SLASH_TOKENS, n=3, cutoff=0.5)
    if suggestions:
        hint = ", ".join(suggestions)
        msg = f"unknown command {head!r} — did you mean: {hint}?"
    else:
        msg = f"unknown command {head!r} — type /help for the list"
    return SlashAction(action="unknown", message=msg)


def suggest_slash_for_typo(value: str) -> str | None:
    """Spot non-slash typos that look like a slash command.

    User types bare ``help`` (no leading ``/``) — we suggest ``/help``. Returns
    the canonical slash (with leading ``/``) or ``None`` if nothing close.
    """
    candidate = "/" + value.strip().lower()
    matches = difflib.get_close_matches(candidate, ALL_SLASH_TOKENS, n=1, cutoff=0.7)
    return matches[0] if matches else None


# --------------------------------------------------------------------------- #
# History file
# --------------------------------------------------------------------------- #

def history_file_path() -> Path:
    """Return the on-disk path used by :class:`FileHistory`.

    Lives under ``%LOCALAPPDATA%\\MarsIT\\mytools-osint\\lookup_history.txt``
    on Windows (and the XDG equivalent on Linux/macOS). The parent directory
    is created on demand — safe to call from a cold install.
    """
    base = user_data_path("mytools-osint", "MarsIT")
    base.mkdir(parents=True, exist_ok=True)
    return base / "lookup_history.txt"


def build_history() -> FileHistory:
    """Construct the :class:`FileHistory` used by both the PromptSession and
    the history-completer below. Shared singleton-by-path semantics."""
    return FileHistory(str(history_file_path()))


# --------------------------------------------------------------------------- #
# Completers
# --------------------------------------------------------------------------- #

class _SlashCompleter(Completer):
    """Emits `/help`, `/clear`, ... when the buffer starts with `/`."""

    def get_completions(self, document: Document, complete_event):  # noqa: D401
        text = document.text_before_cursor
        if not text.startswith("/"):
            return
        # If user already typed "/kind " or "/kind=", switch to kind-value mode.
        stripped = text.lstrip()
        if stripped.startswith("/kind") and stripped.startswith(("/kind ", "/kind=")):
            sep_idx = max(stripped.find(" "), stripped.find("="))
            partial = stripped[sep_idx + 1:].lower()
            for k in KIND_VALUES:
                if k.startswith(partial):
                    yield Completion(
                        k, start_position=-len(partial),
                        display=k, display_meta="query kind",
                    )
            return
        # Plain slash-command completion.
        prefix = text.lower()
        for token in ALL_SLASH_TOKENS:
            if token.startswith(prefix):
                canonical = _canonical_for(token)
                meta = SLASH_DESCRIPTIONS.get(canonical, "")
                yield Completion(
                    token, start_position=-len(text),
                    display=token, display_meta=meta,
                )


class _KindFlagCompleter(Completer):
    """Emits the 7 kinds after `--kind=` or `--kind ` (non-slash form)."""

    def get_completions(self, document: Document, complete_event):
        text = document.text_before_cursor
        lower = text.lower()
        # Walk back to a "--kind=" or "--kind " token even if it's mid-line.
        for marker in ("--kind=", "--kind "):
            idx = lower.rfind(marker)
            if idx == -1:
                continue
            partial = text[idx + len(marker):]
            if " " in partial:  # already past the flag value
                continue
            for k in KIND_VALUES:
                if k.startswith(partial.lower()):
                    yield Completion(
                        k, start_position=-len(partial),
                        display=k, display_meta="query kind",
                    )
            return


class _HistoryCompleter(Completer):
    """Emits the last ~50 distinct history entries once 2+ chars are typed."""

    def __init__(self, history: FileHistory, *, limit: int = 50) -> None:
        self._history = history
        self._limit = limit

    def get_completions(self, document: Document, complete_event):
        text = document.text_before_cursor
        if text.startswith("/") or len(text.strip()) < 2:
            return
        seen: set[str] = set()
        # FileHistory.load_history_strings() yields newest-first.
        for entry in self._history.load_history_strings():
            if entry in seen:
                continue
            seen.add(entry)
            if entry.lower().startswith(text.lower()) and entry != text:
                yield Completion(
                    entry, start_position=-len(text),
                    display=entry, display_meta="history",
                )
            if len(seen) >= self._limit:
                break


def _canonical_for(token: str) -> SlashName:
    for canonical, aliases in SLASH_ALIASES.items():
        if token in aliases:
            return canonical
    return "help"  # unreachable but keeps the type-checker happy


def build_completer(history: FileHistory) -> Completer:
    """Merged + fuzzy-wrapped completer used by the PromptSession."""
    return FuzzyCompleter(merge_completers([
        _SlashCompleter(),
        _KindFlagCompleter(),
        _HistoryCompleter(history),
    ]))


# --------------------------------------------------------------------------- #
# Multi-target burst input
# --------------------------------------------------------------------------- #

def split_multi_target(value: str) -> list[str]:
    """Split a burst input into one target per element.

    The user may separate targets with commas or newlines (Alt+Enter inserts a
    real ``\\n``). Empty fragments are dropped. Single-target inputs are
    returned as a 1-element list so callers can treat both shapes uniformly.
    """
    if not value:
        return []
    raw = value.replace("\n", ",")
    parts = [p.strip() for p in raw.split(",")]
    return [p for p in parts if p]


# --------------------------------------------------------------------------- #
# Key bindings
# --------------------------------------------------------------------------- #

def build_key_bindings():
    """Return KeyBindings that bind Alt+Enter to insert ``\\n``.

    Plain Enter still submits — we deliberately keep ``multiline=False`` so the
    default behaviour is untouched.
    """
    # Lazy import — prompt_toolkit's KeyBindings is light, but the input layer
    # is exercised by tests that don't need the binding at all.
    from prompt_toolkit.key_binding import KeyBindings

    kb = KeyBindings()

    @kb.add("escape", "enter")  # Alt+Enter (a.k.a. Meta-Enter)
    def _(event):  # noqa: ANN001
        event.current_buffer.insert_text("\n")

    return kb


# --------------------------------------------------------------------------- #
# Tiny helpers shared with interactive.py
# --------------------------------------------------------------------------- #

def known_slash_tokens() -> Iterable[str]:
    """Public view of every slash token — handy for tests + introspection."""
    return ALL_SLASH_TOKENS
