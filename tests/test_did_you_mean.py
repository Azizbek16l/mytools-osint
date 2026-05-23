"""Tests for the zero-hit ``did you mean?`` suggester (Sprint 3, item 8)."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.core.types import Hit, HitStatus, Query, QueryKind
from app.ui.interactive import _render_did_you_mean, build_did_you_mean


def _empty_hits(n: int = 5) -> list[Hit]:
    return [
        Hit(module="username", source=f"site{i}", status=HitStatus.NOT_FOUND)
        for i in range(n)
    ]


def _isolate_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entries: list[str] | None = None,
) -> None:
    """Redirect ``history_file_path`` to a tmp file unique to this test.

    ``platformdirs`` ignores ``LOCALAPPDATA`` on Windows so we monkeypatch
    the path resolver directly. Seeds ``entries`` (oldest first) if given.
    """
    import app.ui.lookup_input as li
    target = tmp_path / "lookup_history.txt"
    monkeypatch.setattr(li, "history_file_path", lambda: target)
    if entries:
        h = li.build_history()
        for e in entries:
            h.append_string(e)


def test_no_suggestions_when_there_are_positives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(tmp_path, monkeypatch)
    q = Query(kind=QueryKind.USERNAME, value="torvalds")
    hits = [
        Hit(module="username", source="github.com",
            status=HitStatus.FOUND, url="https://github.com/torvalds"),
    ]
    assert build_did_you_mean(q, hits) == []


def test_no_suggestions_for_empty_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(tmp_path, monkeypatch)
    q = Query(kind=QueryKind.USERNAME, value="")
    assert build_did_you_mean(q, []) == []


def test_history_closest_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(
        tmp_path, monkeypatch,
        entries=["torvalds", "linus", "kernel.org"],
    )
    q = Query(kind=QueryKind.USERNAME, value="torvallds")  # typo
    out = build_did_you_mean(q, _empty_hits())
    assert any("torvalds" in label for label, _, _ in out)
    # The matched suggestion preserves the original kind.
    matched = next(s for s in out if "torvalds" in s[0])
    label, kind, val = matched
    assert kind == QueryKind.USERNAME
    assert val == "torvalds"


def test_username_looks_like_telegram_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(tmp_path, monkeypatch)
    q = Query(kind=QueryKind.USERNAME, value="durov")
    out = build_did_you_mean(q, _empty_hits())
    # Username path proposes @durov as Telegram.
    assert any(kind == QueryKind.TELEGRAM and val == "@durov" for _, kind, val in out)


def test_leading_at_suggests_telegram(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(tmp_path, monkeypatch)
    q = Query(kind=QueryKind.USERNAME, value="@durov")
    out = build_did_you_mean(q, _empty_hits())
    assert any(kind == QueryKind.TELEGRAM and val == "@durov" for _, kind, val in out)


def test_email_misclassified_as_username(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(tmp_path, monkeypatch)
    q = Query(kind=QueryKind.USERNAME, value="alice@example.com")
    out = build_did_you_mean(q, _empty_hits())
    assert any(kind == QueryKind.EMAIL for _, kind, _ in out)


def test_phone_misclassified_as_username(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(tmp_path, monkeypatch)
    q = Query(kind=QueryKind.USERNAME, value="+998948241222")
    out = build_did_you_mean(q, _empty_hits())
    assert any(kind == QueryKind.PHONE for _, kind, _ in out)


def test_domain_misclassified_as_username(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(tmp_path, monkeypatch)
    q = Query(kind=QueryKind.USERNAME, value="marsits.uz")
    out = build_did_you_mean(q, _empty_hits())
    assert any(kind == QueryKind.DOMAIN and val == "marsits.uz" for _, kind, val in out)


def test_capped_at_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(tmp_path, monkeypatch, entries=["@durov", "durov"])
    # Multiple shapes match — but we never return more than 3.
    q = Query(kind=QueryKind.USERNAME, value="durov")
    out = build_did_you_mean(q, _empty_hits())
    assert len(out) <= 3


def test_same_kind_value_not_repeated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(tmp_path, monkeypatch, entries=["@durov"])
    q = Query(kind=QueryKind.TELEGRAM, value="durov")
    out = build_did_you_mean(q, _empty_hits())
    # No duplicate (TELEGRAM, "@durov") triples.
    seen = set()
    for _, kind, val in out:
        key = (kind, val)
        assert key not in seen
        seen.add(key)


def test_render_block_emits_keypress_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _isolate_history(tmp_path, monkeypatch)
    q = Query(kind=QueryKind.USERNAME, value="alice@example.com")
    sug = build_did_you_mean(q, _empty_hits())
    out = _render_did_you_mean(q, probed=1008, suggestions=sug)
    # The block carries the keypress hint and probed count.
    from rich.console import Console
    console = Console(width=120, record=True)
    console.print(out)
    rendered = console.export_text()
    assert "1008" in rendered
    assert "[1]" in rendered
    assert "[n]" in rendered  # "press [N] for a new query"
