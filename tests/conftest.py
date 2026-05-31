"""Test bootstrap — keep tests offline-friendly by default."""
from __future__ import annotations

import os
import sys
from pathlib import Path

# put repo root on sys.path so `import app` works
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# isolated data dir for the test run (so we don't touch real %LOCALAPPDATA%)
os.environ.setdefault("HTTP_TIMEOUT_SEC", "2")

# v4.2: redirect the persisted-theme file to a tmp path so user-side picks
# (e.g. `~/.config/mytools-osint/theme = "nord"`) don't pollute test fixtures.
import tempfile

_TMP_THEME_DIR = tempfile.mkdtemp(prefix="mytools-test-theme-")
_TMP_THEME = os.path.join(_TMP_THEME_DIR, "theme")
# Monkey-patch the module-level constant BEFORE any test imports tokens.
import app.ui.tokens as _t

_t._THEME_CONFIG_PATH = _TMP_THEME
