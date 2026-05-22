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
