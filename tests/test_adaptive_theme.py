"""Tests for the adaptive light/dark theme resolver (Sprint 3, item 9).

These tests stay pure-Python — they don't touch a real Console, and they
prove the resolver's three-branch contract:

    explicit "light"  → LIGHT_TOKENS
    explicit "dark"   → DARK_TOKENS
    "auto" / unknown / None → COLORFGBG-driven, fall back to DARK_TOKENS
"""
from __future__ import annotations

import pytest

from app.ui import tokens as t


def test_explicit_dark_returns_dark_tokens() -> None:
    out = t.resolve_theme("dark")
    assert out is t.DARK_TOKENS
    assert out.name == "dark"
    assert out.ACCENT == "#58A6FF"


def test_explicit_light_returns_light_tokens() -> None:
    out = t.resolve_theme("light")
    assert out is t.LIGHT_TOKENS
    assert out.name == "light"
    # Light palette uses Primer brand blue.
    assert out.ACCENT == "#0969DA"
    # AA-safe contrast against #FFFFFF — light variants are darker.
    assert out.FG != t.DARK_TOKENS.FG
    assert out.DIM != t.DARK_TOKENS.DIM


def test_unknown_value_falls_back_to_dark(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("COLORFGBG", raising=False)
    assert t.resolve_theme("xyzzy") is t.DARK_TOKENS
    assert t.resolve_theme("") is t.DARK_TOKENS
    assert t.resolve_theme(None) is t.DARK_TOKENS
    assert t.resolve_theme("auto") is t.DARK_TOKENS


def test_colorfgbg_light_bg_triggers_light(monkeypatch: pytest.MonkeyPatch) -> None:
    # xterm convention: "<fg>;<bg>" — bg=15 (white) → light.
    monkeypatch.setenv("COLORFGBG", "0;15")
    assert t.resolve_theme("auto") is t.LIGHT_TOKENS
    # Three-segment form (used by rxvt) — final value still the bg.
    monkeypatch.setenv("COLORFGBG", "0;default;15")
    assert t.resolve_theme(None) is t.LIGHT_TOKENS


def test_colorfgbg_dark_bg_stays_dark(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLORFGBG", "15;0")  # bg=0 (black) → dark
    assert t.resolve_theme("auto") is t.DARK_TOKENS


def test_colorfgbg_garbage_falls_back_to_dark(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLORFGBG", "not;a;number")
    assert t.resolve_theme(None) is t.DARK_TOKENS
    monkeypatch.setenv("COLORFGBG", "")
    assert t.resolve_theme(None) is t.DARK_TOKENS


def test_module_constants_mirror_active_palette() -> None:
    # The module-level ACCENT/OK/… must mirror the resolved ACTIVE struct
    # so existing call sites (tokens.ACCENT) keep working.
    assert t.ACCENT == t.ACTIVE.ACCENT
    assert t.OK == t.ACTIVE.OK
    assert t.WARN == t.ACTIVE.WARN
    assert t.BAD == t.ACTIVE.BAD
    assert t.FG == t.ACTIVE.FG
    assert t.DIM == t.ACTIVE.DIM


def test_tokens_re_exported_from_theme_module() -> None:
    # Contract: `from app.ui.theme import tokens` returns the same module.
    from app.ui.theme import tokens as via_theme
    assert via_theme is t


def test_explicit_case_insensitive() -> None:
    assert t.resolve_theme("DARK") is t.DARK_TOKENS
    assert t.resolve_theme(" Light ") is t.LIGHT_TOKENS


def test_light_palette_distinct_from_dark() -> None:
    # All five status colours differ — otherwise the "adaptive" doesn't show.
    for key in ("ACCENT", "OK", "WARN", "BAD", "FG", "DIM", "BG_HINT"):
        assert getattr(t.LIGHT_TOKENS, key) != getattr(t.DARK_TOKENS, key), (
            f"LIGHT_TOKENS.{key} must differ from DARK_TOKENS.{key}"
        )
