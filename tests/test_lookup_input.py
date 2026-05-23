"""Unit tests for the interactive lookup input layer.

Targets the pure helpers exposed by ``app.ui.lookup_input`` — the
PromptSession itself is interactive and exercised via the manual smoke flow
in ``scripts/smoke_test.py``.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory

from app.ui.lookup_input import (
    KIND_VALUES,
    build_completer,
    dispatch_slash,
    history_file_path,
    split_multi_target,
    suggest_slash_for_typo,
)

# --------------------------------------------------------------------------- #
# 1. FileHistory round-trip — entries persist across reopens, newest-first.
# --------------------------------------------------------------------------- #

def test_history_file_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Redirect platformdirs' resolution to a clean tmp dir.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    # First writer
    h1 = FileHistory(str(tmp_path / "h.txt"))
    h1.append_string("torvalds")
    h1.append_string("me@example.com")
    h1.append_string("+998948241222")
    # Reopen — load_history_strings yields newest-first.
    h2 = FileHistory(str(tmp_path / "h.txt"))
    entries = list(h2.load_history_strings())
    assert entries[0] == "+998948241222"
    assert entries[1] == "me@example.com"
    assert entries[2] == "torvalds"
    assert len(entries) == 3
    # history_file_path returns a writable, existing parent dir.
    p = history_file_path()
    assert p.parent.exists()
    assert p.name == "lookup_history.txt"


# --------------------------------------------------------------------------- #
# 2. Slash dispatcher — happy path
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("/help", "help"),
        ("/h", "help"),
        ("/?", "help"),
        ("/clear", "clear"),
        ("/cls", "clear"),
        ("/history", "history"),
        ("/modules", "modules"),
        ("/sites", "sites"),
        ("/settings", "settings"),
        ("/config", "settings"),
        ("/version", "version"),
        ("/v", "version"),
        ("/quit", "quit"),
        ("/q", "quit"),
        ("/exit", "quit"),
    ],
)
def test_slash_command_router_known(line: str, expected: str) -> None:
    result = dispatch_slash(line)
    assert result.action == expected
    assert result.message == ""


def test_slash_command_router_kind_arg() -> None:
    # Both `/kind email` and `/kind=email` carry the arg through.
    assert dispatch_slash("/kind email").action == "kind"
    assert dispatch_slash("/kind email").arg == "email"
    assert dispatch_slash("/kind=phone").arg == "phone"
    assert dispatch_slash("/kind").arg == ""


# --------------------------------------------------------------------------- #
# 3. Slash dispatcher — unknown produces did-you-mean
# --------------------------------------------------------------------------- #

def test_slash_command_router_unknown_suggests() -> None:
    result = dispatch_slash("/halp")
    assert result.action == "unknown"
    assert "did you mean" in result.message
    assert "/help" in result.message


def test_slash_command_router_noop_for_non_slash() -> None:
    assert dispatch_slash("torvalds").action == "noop"
    assert dispatch_slash("").action == "noop"


def test_suggest_slash_for_typo() -> None:
    # Bare `help` (no slash) — we should propose `/help`.
    assert suggest_slash_for_typo("help") == "/help"
    # Nonsense gets nothing.
    assert suggest_slash_for_typo("xyzzy") is None


# --------------------------------------------------------------------------- #
# 4. Completer — `--kind=` yields all 7 query kinds
# --------------------------------------------------------------------------- #

def _completions_for(completer, text: str) -> list[str]:
    doc = Document(text=text, cursor_position=len(text))
    return [c.text for c in completer.get_completions(doc, CompleteEvent())]


def test_kind_completer_yields_kinds(tmp_path: Path) -> None:
    history = FileHistory(str(tmp_path / "h.txt"))
    completer = build_completer(history)
    # FuzzyCompleter ranks/filters but the seven kinds must all be reachable.
    completions = _completions_for(completer, "--kind=")
    # Order is up to FuzzyCompleter — assert set equality.
    assert set(completions) == set(KIND_VALUES)
    assert len(completions) == 7
    # Narrowing — `--kind=u` should still produce `username`.
    completions_u = _completions_for(completer, "--kind=u")
    assert "username" in completions_u


def test_slash_completer_includes_help_and_quit(tmp_path: Path) -> None:
    history = FileHistory(str(tmp_path / "h.txt"))
    completer = build_completer(history)
    completions = _completions_for(completer, "/")
    # Both leading-slash spellings and the canonical /quit are surfaced.
    assert "/help" in completions
    assert "/quit" in completions
    assert "/kind" in completions


def test_kind_completer_after_slash_kind(tmp_path: Path) -> None:
    history = FileHistory(str(tmp_path / "h.txt"))
    completer = build_completer(history)
    completions = _completions_for(completer, "/kind ")
    assert set(completions) == set(KIND_VALUES)


# --------------------------------------------------------------------------- #
# 5. Multi-target split
# --------------------------------------------------------------------------- #

def test_multi_target_split() -> None:
    assert split_multi_target("a@b.com, c@d.com") == ["a@b.com", "c@d.com"]
    assert split_multi_target("a@b.com,c@d.com,e@f.com") == [
        "a@b.com", "c@d.com", "e@f.com",
    ]
    # Newline-separated (Alt+Enter inserts a literal \n).
    assert split_multi_target("torvalds\nlinus") == ["torvalds", "linus"]
    # Single target → 1-element list.
    assert split_multi_target("torvalds") == ["torvalds"]
    # Empty + whitespace fragments are dropped.
    assert split_multi_target("a,,  ,b") == ["a", "b"]
    assert split_multi_target("") == []
    assert split_multi_target("   ") == []


# --------------------------------------------------------------------------- #
# 6. Sanity — history-file path is creatable
# --------------------------------------------------------------------------- #

def test_history_file_path_creates_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # platformdirs reads LOCALAPPDATA on Windows; XDG_DATA_HOME elsewhere.
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    # Force a re-resolution by reimporting the helper through its module.
    from importlib import reload

    import app.ui.lookup_input as li
    reload(li)
    p = li.history_file_path()
    assert p.parent.exists()
    assert p.name == "lookup_history.txt"
    # Round-trip a write so we know it's actually writable.
    h = FileHistory(str(p))
    h.append_string("smoke")
    assert "smoke" in list(FileHistory(str(p)).load_history_strings())
    # Restore module state so later tests see the canonical user_data_path.
    reload(li)
    _ = os.environ  # silence unused-import warning if any
