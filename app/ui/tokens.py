"""Design tokens — single source of truth for palette + iconography.

Used by cli.py (plain ANSI Style class) and interactive.py (rich/questionary).
Mirrors the Qt theme constants in app/ui/theme.py so GUI + CLI feel cohesive.

Adaptive theme (Sprint 3): the palette is selected at import time from
``BLUETM_THEME`` ∈ {``light``, ``dark``, ``auto``} (default ``auto``). The
classic dark GitHub palette is the fallback. Detection heuristics are
documented on :func:`resolve_theme`. All module-level constants (``ACCENT``
etc.) remain importable; in addition the resolved :class:`ThemeTokens`
instance is exposed as ``ACTIVE`` and re-exported from ``app/ui/theme.py``
as the module-level ``tokens`` proxy so call sites can write either
``tokens.ACCENT`` (current) or ``from app.ui.theme import tokens``.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Literal

# ---- Palette dataclass -----------------------------------------------------

ThemeName = Literal["light", "dark"]


@dataclass(frozen=True, slots=True)
class ThemeTokens:
    """Resolved palette. All hex strings — Rich + prompt_toolkit accept them."""

    name: ThemeName
    ACCENT: str
    OK: str
    WARN: str
    BAD: str
    FG: str
    DIM: str
    BG_HINT: str
    MUTED_BG: str


# Dark — the original GitHub-Dark style palette (Sprint 1).
DARK_TOKENS = ThemeTokens(
    name="dark",
    ACCENT="#58A6FF",
    OK="#3FB950",
    WARN="#D29922",
    BAD="#F85149",
    FG="#C9D1D9",
    DIM="#6E7681",
    BG_HINT="#0D1117",
    MUTED_BG="#161B22",
)

# Light — GitHub Primer light palette. Contrast-ratio AA verified on white.
LIGHT_TOKENS = ThemeTokens(
    name="light",
    ACCENT="#0969DA",
    OK="#1F883D",
    WARN="#9A6700",
    BAD="#D1242F",
    FG="#1F2328",
    DIM="#656D76",
    BG_HINT="#FFFFFF",
    MUTED_BG="#F6F8FA",
)

# ---- Theme registry (v4.2) -------------------------------------------------
# Named palettes the user can pick in-app via T → theme picker, or with
# ``BLUETM_THEME=<name>`` env var. Adding a theme = adding one dict entry.

DRACULA_TOKENS = ThemeTokens(
    name="dark",
    ACCENT="#BD93F9", OK="#50FA7B", WARN="#F1FA8C", BAD="#FF5555",
    FG="#F8F8F2", DIM="#6272A4", BG_HINT="#282A36", MUTED_BG="#44475A",
)

NORD_TOKENS = ThemeTokens(
    name="dark",
    ACCENT="#88C0D0", OK="#A3BE8C", WARN="#EBCB8B", BAD="#BF616A",
    FG="#ECEFF4", DIM="#4C566A", BG_HINT="#2E3440", MUTED_BG="#3B4252",
)

TOKYO_NIGHT_TOKENS = ThemeTokens(
    name="dark",
    ACCENT="#7AA2F7", OK="#9ECE6A", WARN="#E0AF68", BAD="#F7768E",
    FG="#C0CAF5", DIM="#565F89", BG_HINT="#1A1B26", MUTED_BG="#24283B",
)

CATPPUCCIN_TOKENS = ThemeTokens(
    name="dark",
    ACCENT="#89B4FA", OK="#A6E3A1", WARN="#F9E2AF", BAD="#F38BA8",
    FG="#CDD6F4", DIM="#6C7086", BG_HINT="#1E1E2E", MUTED_BG="#313244",
)

HIGH_CONTRAST_TOKENS = ThemeTokens(
    name="dark",
    ACCENT="#5DADE2", OK="#58D68D", WARN="#F5B041", BAD="#EC7063",
    FG="#FFFFFF", DIM="#A6ACAF", BG_HINT="#000000", MUTED_BG="#1B1B1B",
)

THEMES: dict[str, ThemeTokens] = {
    "github-dark":      DARK_TOKENS,
    "github-light":     LIGHT_TOKENS,
    "dracula":          DRACULA_TOKENS,
    "nord":             NORD_TOKENS,
    "tokyo-night":      TOKYO_NIGHT_TOKENS,
    "catppuccin-mocha": CATPPUCCIN_TOKENS,
    "high-contrast":    HIGH_CONTRAST_TOKENS,
}

# Persistence path (read on import, written when user picks a theme).
_THEME_CONFIG_PATH = os.path.expanduser("~/.config/mytools-osint/theme")


def _read_persisted_theme() -> str | None:
    """If the user previously picked a theme via the in-app switcher, honour it."""
    try:
        with open(_THEME_CONFIG_PATH) as f:
            name = f.read().strip()
        return name if name in THEMES else None
    except OSError:
        return None


def persist_theme(name: str) -> None:
    """Write the picked theme name so it survives across launches."""
    if name not in THEMES:
        return
    try:
        os.makedirs(os.path.dirname(_THEME_CONFIG_PATH), exist_ok=True)
        with open(_THEME_CONFIG_PATH, "w") as f:
            f.write(name)
    except OSError:
        pass


# ---- Resolver --------------------------------------------------------------

def _detect_terminal_background() -> ThemeName | None:
    """Best-effort terminal-background detection.

    Returns ``"light"`` or ``"dark"`` if the environment makes it clear,
    otherwise ``None`` (caller falls back to ``dark``).

    Signals consulted, in order:
      * ``COLORFGBG`` (xterm convention, ``"<fg>;<bg>"`` — bg ≥ 8 means light)
      * macOS: ``__CFBundleIdentifier=com.apple.Terminal`` + ``LSColors`` hints
        are not reliable enough; we skip.
      * Windows: no portable terminal-background query; we trust ``BLUETM_THEME``.
    """
    cfgbg = os.environ.get("COLORFGBG", "")
    if cfgbg:
        try:
            parts = cfgbg.split(";")
            bg = int(parts[-1])
            # xterm convention: bg in 0..7 = dark, 8..15 = light, plus 15 = white.
            if bg >= 8:
                return "light"
            return "dark"
        except (ValueError, IndexError):
            pass
    return None


def resolve_theme(env_value: str | None) -> ThemeTokens:
    """Pick a palette from the THEMES registry (v4.2) or fall back to legacy logic.

    Resolution order:
      1. Persisted choice in ``~/.config/mytools-osint/theme`` (user-picked).
      2. ``BLUETM_THEME`` env value — accepts any THEMES key (``dracula``,
         ``nord``…) or legacy ``"light"`` / ``"dark"`` / ``"auto"``.
      3. ``COLORFGBG`` detection.
      4. Dark default.

    Case-insensitive; unknown names are treated as ``auto``.
    """
    persisted = _read_persisted_theme()
    if persisted:
        return THEMES[persisted]
    val = (env_value or "").strip().lower()
    if val in THEMES:
        return THEMES[val]
    if val == "light":
        return LIGHT_TOKENS
    if val == "dark":
        return DARK_TOKENS
    detected = _detect_terminal_background()
    if detected == "light":
        return LIGHT_TOKENS
    return DARK_TOKENS


# ---- Active palette --------------------------------------------------------

# Resolve once at import time. Tests that need a specific palette can either
# set ``BLUETM_THEME`` before import or call :func:`resolve_theme` directly.
ACTIVE: ThemeTokens = resolve_theme(os.environ.get("BLUETM_THEME"))

# Module-level constants — preserved for backward compat with every Sprint 1/2
# call site (``tokens.ACCENT``, ``tokens.OK``, …). These mirror :data:`ACTIVE`.
ACCENT = ACTIVE.ACCENT
OK = ACTIVE.OK
WARN = ACTIVE.WARN
BAD = ACTIVE.BAD
FG = ACTIVE.FG
DIM = ACTIVE.DIM
MUTED_BG = ACTIVE.MUTED_BG

# ANSI 256 fallbacks for the plain Style class — these stay theme-agnostic
# because the 256-colour cube doesn't have a meaningful "light" / "dark"
# distinction at this level; cli.py callers map by status, not by background.
ANSI_ACCENT = "38;5;75"
ANSI_OK     = "38;5;78"
ANSI_WARN   = "38;5;179"
ANSI_BAD    = "38;5;203"
ANSI_FG     = "38;5;252"
ANSI_DIM    = "38;5;243"


# ---- Environment detection -------------------------------------------------

def _is_tty() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def colour_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("CI"):
        return False
    return _is_tty()


def nerd_font_available() -> bool:
    """Heuristic — Nerd Font glyphs render when Windows Terminal or kitty is host.
    Forceable via NERD_FONT=1; force-off via BLUETM_ASCII=1."""
    if os.environ.get("BLUETM_ASCII") == "1":
        return False
    if os.environ.get("NERD_FONT") == "1":
        return True
    if not _is_tty():
        return False
    # Windows Terminal exposes WT_SESSION; modern WT ships Cascadia Code NF since 1.21
    if os.environ.get("WT_SESSION"):
        return True
    # kitty / wezterm / alacritty also have NF support; users opt-in via NERD_FONT
    return False


# ---- Iconography (Nerd Font when supported, ASCII fallback otherwise) ------

if nerd_font_available():
    ICON_OK       = ""   # nf-fa-check
    ICON_BAD      = ""   # nf-fa-times
    ICON_WARN     = ""   # nf-fa-exclamation
    ICON_QUESTION = ""   # nf-fa-question
    ICON_SKIP     = ""   # nf-fa-minus
    ICON_RUN      = ""   # nf-fa-refresh (used as spinner anchor)
    # Module glyphs (used sparingly in the left gutter)
    ICON_GITHUB   = ""   # nf-fa-github
    ICON_TELEGRAM = ""   # nf-fa-telegram
    ICON_EMAIL    = ""   # nf-fa-envelope
    ICON_SEARCH   = ""   # nf-fa-search
    ICON_WEB      = ""   # nf-fa-globe
    ICON_PHONE    = ""   # nf-fa-phone
    ICON_IP       = ""   # nf-fa-server
else:
    ICON_OK       = "+"
    ICON_BAD      = "x"
    ICON_WARN     = "!"
    ICON_QUESTION = "?"
    ICON_SKIP     = "-"
    ICON_RUN      = "*"
    ICON_GITHUB   = "GH"
    ICON_TELEGRAM = "TG"
    ICON_EMAIL    = "@"
    ICON_SEARCH   = "Q"
    ICON_WEB      = "W"
    ICON_PHONE    = "P"
    ICON_IP       = "IP"

# Per-module glyph mapping (best-effort — fall back to nothing)
MODULE_GLYPHS = {
    "username":  ICON_SEARCH,
    "email":     ICON_EMAIL,
    "phone":     ICON_PHONE,
    "telegram":  ICON_TELEGRAM,
    "whatsapp":  ICON_PHONE,
    "ip":        ICON_IP,
    "domain":    ICON_WEB,
    "discovery": ICON_SEARCH,
    "patterns":  ICON_SEARCH,
}


# ---- Box drawing — rounded > BBS doubles ------------------------------------

BOX_TL = "╭"  # ╭
BOX_TR = "╮"  # ╮
BOX_BL = "╰"  # ╰
BOX_BR = "╯"  # ╯
BOX_H  = "─"  # ─
BOX_V  = "│"  # │


# ---- Public API ------------------------------------------------------------

__all__ = (
    "ThemeTokens",
    "DARK_TOKENS",
    "LIGHT_TOKENS",
    "ACTIVE",
    "resolve_theme",
    "ACCENT", "OK", "WARN", "BAD", "FG", "DIM", "MUTED_BG",
    "ANSI_ACCENT", "ANSI_OK", "ANSI_WARN", "ANSI_BAD", "ANSI_FG", "ANSI_DIM",
    "colour_enabled", "nerd_font_available",
    "ICON_OK", "ICON_BAD", "ICON_WARN", "ICON_QUESTION", "ICON_SKIP", "ICON_RUN",
    "ICON_GITHUB", "ICON_TELEGRAM", "ICON_EMAIL", "ICON_SEARCH", "ICON_WEB",
    "ICON_PHONE", "ICON_IP",
    "MODULE_GLYPHS",
    "BOX_TL", "BOX_TR", "BOX_BL", "BOX_BR", "BOX_H", "BOX_V",
)
