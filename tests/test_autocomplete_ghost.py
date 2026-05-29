"""QA regression tests for the interactive shell's autocomplete + ghost text.

Locks the behaviour verified during the v4.3 chat-shell QA:
  * completions REPLACE the whole token — accepting one never produces a
    garbled buffer like ``//help`` (the classic FuzzyCompleter + leading-``/``
    pitfall).
  * fuzzy/typo slash completion works (``/hlp`` -> ``/help``).
  * history completion + fish-style ghost text resolve from FileHistory.
"""
from __future__ import annotations

import pytest
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document
from prompt_toolkit.history import InMemoryHistory

from app.ui.lookup_input import _HistoryCompleter, build_completer

_EV = CompleteEvent(text_inserted=True)


def _apply(text: str, completion) -> str:
    """The buffer-before-cursor after accepting `completion` at end of `text`."""
    return text[: len(text) + completion.start_position] + completion.text


def _completions(text: str):
    comp = build_completer(InMemoryHistory())
    return list(comp.get_completions(Document(text, len(text)), _EV))


@pytest.mark.parametrize(
    "text",
    ["/he", "/the", "/hlp", "/tme", "/clr", "/sett", "/kind ", "/kind=user", "--kind=", "--kind "],
)
def test_accepting_a_completion_never_garbles_the_buffer(text: str) -> None:
    """Every completion must apply to a clean buffer — no doubled '/' or stray
    fragments (regression for the FuzzyCompleter + leading-slash double-insert)."""
    for c in _completions(text):
        applied = _apply(text, c)
        assert "//" not in applied, f"garbled buffer {applied!r} from {text!r}"
        # a slash command applies to a single '/'-prefixed token
        if text.startswith("/") and not text.startswith(("/kind ", "/kind=")):
            assert applied.startswith("/") and applied.count("/") == 1


@pytest.mark.parametrize(
    "text,expected",
    [("/hlp", "/help"), ("/tme", "/theme"), ("/clr", "/clear"), ("/sett", "/settings")],
)
def test_fuzzy_typo_slash_completion(text: str, expected: str) -> None:
    """Subsequence-fuzzy matching surfaces the intended command from a typo."""
    texts = [c.text for c in _completions(text)]
    assert expected in texts, f"{expected!r} not in {texts!r} for {text!r}"


def test_kind_value_completion_after_slash_kind() -> None:
    texts = [c.text for c in _completions("/kind ")]
    assert {"username", "email", "phone", "domain", "ip"} <= set(texts)


def test_history_completion_prefix() -> None:
    h = InMemoryHistory()
    for s in ["github.com", "satya@microsoft.com", "github.io"]:
        h.append_string(s)
    hc = _HistoryCompleter(h)
    got = {c.text for c in hc.get_completions(Document("git", 3), _EV)}
    assert got == {"github.com", "github.io"}


def test_history_completer_needs_two_chars_and_skips_slash() -> None:
    h = InMemoryHistory()
    h.append_string("github.com")
    hc = _HistoryCompleter(h)
    assert list(hc.get_completions(Document("g", 1), _EV)) == []      # <2 chars
    assert list(hc.get_completions(Document("/g", 2), _EV)) == []     # slash → handled elsewhere


def test_ghost_text_from_history() -> None:
    h = InMemoryHistory()
    for s in ["github.com", "satya@microsoft.com"]:
        h.append_string(s)
    asg = AutoSuggestFromHistory()
    buf = Buffer(history=h)
    assert asg.get_suggestion(buf, Document("git", 3)).text == "hub.com"
    assert asg.get_suggestion(buf, Document("saty", 4)).text == "a@microsoft.com"
    assert asg.get_suggestion(buf, Document("zzz", 3)) is None
