"""Dark theme stylesheet. Single source of truth for colours.

Also re-exports the CLI ``tokens`` module so ``from app.ui.theme import tokens``
resolves to the same object as ``from app.ui import tokens``. The CLI theme
contract (adaptive light/dark via ``BLUETM_THEME``) lives in :mod:`app.ui.tokens`;
this module owns the Qt stylesheet for the desktop UI.
"""
from __future__ import annotations

from app.ui import tokens

__all__ = (
    "BG", "BG_ELEVATED", "BG_HOVER", "BORDER",
    "TEXT", "TEXT_DIM", "TEXT_BRIGHT",
    "ACCENT", "ACCENT_FG", "OK", "WARN", "BAD", "INFO",
    "SEV_HIGH", "SEV_MED", "SEV_LOW",
    "STYLE", "apply", "tokens",
)

# Palette — neutral dark with a single accent
BG          = "#0e1117"
BG_ELEVATED = "#161b22"
BG_HOVER    = "#1c2128"
BORDER      = "#30363d"
TEXT        = "#c9d1d9"
TEXT_DIM    = "#8b949e"
TEXT_BRIGHT = "#f0f6fc"
ACCENT      = "#58a6ff"
ACCENT_FG   = "#0d1117"
OK          = "#3fb950"
WARN        = "#d29922"
BAD         = "#f85149"
INFO        = "#a5a5a5"
SEV_HIGH    = "#f85149"
SEV_MED     = "#d29922"
SEV_LOW     = "#3fb950"

STYLE = f"""
* {{ outline: 0; }}
QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: 'Segoe UI Variable', 'Segoe UI', 'Inter', system-ui;
    font-size: 13px;
}}
QMainWindow, QDialog {{
    background-color: {BG};
}}
QStatusBar {{
    background-color: {BG_ELEVATED};
    color: {TEXT_DIM};
    border-top: 1px solid {BORDER};
}}
QToolBar {{
    background-color: {BG_ELEVATED};
    border-bottom: 1px solid {BORDER};
    padding: 6px;
    spacing: 6px;
}}
QLineEdit, QPlainTextEdit, QTextEdit {{
    background-color: {BG_ELEVATED};
    color: {TEXT_BRIGHT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 10px;
    selection-background-color: {ACCENT};
    selection-color: {ACCENT_FG};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{
    border: 1px solid {ACCENT};
}}
QPushButton {{
    background-color: {BG_ELEVATED};
    color: {TEXT_BRIGHT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 7px 14px;
}}
QPushButton:hover {{
    background-color: {BG_HOVER};
    border-color: {ACCENT};
}}
QPushButton:pressed {{
    background-color: {BORDER};
}}
QPushButton[accent="true"] {{
    background-color: {ACCENT};
    color: {ACCENT_FG};
    border: 0;
    font-weight: 600;
}}
QPushButton[accent="true"]:hover {{
    background-color: #79b8ff;
}}
QPushButton[accent="true"]:disabled {{
    background-color: {BG_HOVER};
    color: {TEXT_DIM};
}}
QComboBox {{
    background-color: {BG_ELEVATED};
    color: {TEXT_BRIGHT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px 10px;
    min-width: 120px;
}}
QComboBox:hover {{
    border-color: {ACCENT};
}}
QComboBox QAbstractItemView {{
    background-color: {BG_ELEVATED};
    color: {TEXT};
    selection-background-color: {ACCENT};
    selection-color: {ACCENT_FG};
    border: 1px solid {BORDER};
}}
QTableWidget, QTableView, QListWidget, QTreeWidget, QTreeView {{
    background-color: {BG};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    gridline-color: {BORDER};
    alternate-background-color: {BG_ELEVATED};
}}
QTableWidget::item:selected, QListWidget::item:selected, QTreeWidget::item:selected {{
    background-color: #1f6feb55;
    color: {TEXT_BRIGHT};
}}
QHeaderView::section {{
    background-color: {BG_ELEVATED};
    color: {TEXT_BRIGHT};
    border: 0;
    border-right: 1px solid {BORDER};
    border-bottom: 1px solid {BORDER};
    padding: 7px 10px;
    font-weight: 600;
}}
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 6px;
    background-color: {BG};
    top: -1px;
}}
QTabBar::tab {{
    background-color: {BG};
    color: {TEXT_DIM};
    border: 1px solid {BORDER};
    border-bottom: 0;
    padding: 7px 14px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}}
QTabBar::tab:selected {{
    background-color: {BG_ELEVATED};
    color: {TEXT_BRIGHT};
    border-bottom: 2px solid {ACCENT};
}}
QTabBar::tab:hover {{ color: {TEXT}; }}
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 6px;
    margin-top: 14px;
    padding-top: 8px;
    color: {TEXT_BRIGHT};
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
}}
QScrollBar:vertical, QScrollBar:horizontal {{
    background: transparent;
    border: 0;
}}
QScrollBar:vertical {{ width: 10px; }}
QScrollBar:horizontal {{ height: 10px; }}
QScrollBar::handle {{
    background: {BORDER};
    border-radius: 5px;
    min-height: 28px;
    min-width: 28px;
}}
QScrollBar::handle:hover {{ background: {TEXT_DIM}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ background: none; border: 0; height: 0; width: 0; }}
QProgressBar {{
    background-color: {BG_ELEVATED};
    color: {TEXT_BRIGHT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    text-align: center;
    height: 8px;
}}
QProgressBar::chunk {{
    background-color: {ACCENT};
    border-radius: 5px;
}}
QToolTip {{
    background-color: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER};
    padding: 6px;
}}
QLabel[role="title"] {{ font-size: 18px; font-weight: 600; color: {TEXT_BRIGHT}; }}
QLabel[role="subtitle"] {{ color: {TEXT_DIM}; }}
QLabel[role="badge-ok"]   {{ color: {OK};   font-weight: 600; }}
QLabel[role="badge-bad"]  {{ color: {BAD};  font-weight: 600; }}
QLabel[role="badge-warn"] {{ color: {WARN}; font-weight: 600; }}
QLabel[role="badge-dim"]  {{ color: {TEXT_DIM}; }}
"""


def apply(app) -> None:
    app.setStyleSheet(STYLE)
