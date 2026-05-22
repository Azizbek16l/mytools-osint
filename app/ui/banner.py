"""ASCII art banner for CLI startup. Single source of truth.

Used by cli.py at startup and by main.py for the GUI About dialog.

Two flavours:
  - render()         — the full 6-row figlet. Used once on cold start.
  - render_compact() — single-line brandmark. Used on every other screen.
"""
from __future__ import annotations

from app import __version__

BRAND = "Bluetm.uz"
TAGLINE = "personal OSINT — authorised use only"

# ANSI Shadow style figlet — 6 lines, ~75 cols. Each letter = 7-cell block.
ASCII_ART = r"""
██████╗ ██╗     ██╗   ██╗███████╗████████╗███╗   ███╗   ██╗   ██╗███████╗
██╔══██╗██║     ██║   ██║██╔════╝╚══██╔══╝████╗ ████║   ██║   ██║╚══███╔╝
██████╔╝██║     ██║   ██║█████╗     ██║   ██╔████╔██║   ██║   ██║  ███╔╝
██╔══██╗██║     ██║   ██║██╔══╝     ██║   ██║╚██╔╝██║   ██║   ██║ ███╔╝
██████╔╝███████╗╚██████╔╝███████╗   ██║   ██║ ╚═╝ ██║██╗╚██████╔╝███████╗
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝     ╚═╝╚═╝ ╚═════╝ ╚══════╝
"""


def stats_line() -> str:
    """Counts shown under the banner. Imports are local to avoid bootstrap cycle."""
    from app.core.runner import runner
    from app.modules.username import load_sites

    sites = len(load_sites())
    mods = len(runner().all_modules())
    return f"{sites:,} sites · {mods} modules · free APIs"


def render(style=None) -> str:
    """Plain (uncoloured) banner. style is an optional cli.Style instance."""
    art = ASCII_ART
    sub = f"   mytools-osint v{__version__} — by {BRAND}"
    try:
        sub2 = f"   {stats_line()} — {TAGLINE}"
    except Exception:
        sub2 = f"   {TAGLINE}"
    if style is None:
        return f"{art}\n{sub}\n{sub2}\n"
    return (
        style.accent(art) + "\n"
        + style.bold(sub) + "\n"
        + style.dim(sub2) + "\n"
    )


def render_compact(style=None) -> str:
    """Single-line brandmark for repeated screens.

    Format:  bluetm·uz  osint · v0.1.0 · 1,008 sites · 9 modules
    Accent only on the brand half; everything else dimmed.
    """
    try:
        stats = "  " + stats_line()
    except Exception:
        stats = ""
    brand = "bluetm·uz"
    suffix = f"  osint · v{__version__}{stats}"
    if style is None:
        return brand + suffix
    return style.accent(style.bold(brand)) + style.dim(suffix)
