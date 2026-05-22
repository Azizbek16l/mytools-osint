"""Design tokens — single source of truth for palette + iconography.

Used by cli.py (plain ANSI Style class) and interactive.py (rich/questionary).
Mirrors the Qt theme constants in app/ui/theme.py so GUI + CLI feel cohesive.
"""
from __future__ import annotations

import os
import sys

# ---- Palette (hex for rich; ANSI 256 indices for the plain Style class) ----

ACCENT     = "#58A6FF"   # azure — brand, headers, prompt caret. Reserve for brand moments.
OK         = "#3FB950"   # found / confirmed
WARN       = "#D29922"   # maybe / rate-limited
BAD        = "#F85149"   # not found / error
FG         = "#C9D1D9"   # body text
DIM        = "#6E7681"   # labels, separators, chrome
MUTED_BG   = "#161B22"

# ANSI 256 fallbacks for the plain Style class
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
    ICON_OK       = ""   # nf-fa-check
    ICON_BAD      = ""   # nf-fa-times
    ICON_WARN     = ""   # nf-fa-exclamation
    ICON_QUESTION = ""   # nf-fa-question
    ICON_SKIP     = ""   # nf-fa-minus
    ICON_RUN      = ""   # nf-fa-refresh (used as spinner anchor)
    # Module glyphs (used sparingly in the left gutter)
    ICON_GITHUB   = ""   # nf-fa-github
    ICON_TELEGRAM = ""   # nf-fa-telegram
    ICON_EMAIL    = ""   # nf-fa-envelope
    ICON_SEARCH   = ""   # nf-fa-search
    ICON_WEB      = ""   # nf-fa-globe
    ICON_PHONE    = ""   # nf-fa-phone
    ICON_IP       = ""   # nf-fa-server
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
