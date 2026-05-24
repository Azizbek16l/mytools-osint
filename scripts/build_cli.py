"""Nuitka one-file build for the `osint` CLI (no Qt, no PySide6 plugin).

Run with: python scripts/build_cli.py
Output:   dist/osint(.exe on Windows)  ~25-40 MB single-file
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "cli.py"
OUT = ROOT / "dist"
sys.path.insert(0, str(ROOT))

try:
    from app import __version__ as VERSION
except Exception:
    VERSION = "0.0.0"

# Nuitka writes the literal filename you give it; Windows adds .exe iff missing.
# Match the local-OS convention so release.yml's `cp dist/osint${{ matrix.ext }}`
# always finds the file (Linux/macOS: `osint`, Windows: `osint.exe`).
FILENAME = "osint.exe" if sys.platform == "win32" else "osint"


def main() -> int:
    OUT.mkdir(exist_ok=True)
    cmd = [
        sys.executable, "-m", "nuitka",
        "--onefile",
        "--standalone",
        "--include-package=app",
        "--include-package=telethon",
        "--include-package-data=phonenumbers",
        "--include-data-dir=data=data",
        "--include-data-files=.env.example=.env.example",
        "--nofollow-import-to=PySide6",
        "--nofollow-import-to=qasync",
        "--nofollow-import-to=shiboken6",
        "--nofollow-import-to=textual",  # TUI is optional, keep CLI binary slim
        "--windows-console-mode=force",
        "--company-name=MarsIT",
        "--product-name=osint",
        f"--file-version={VERSION}",
        f"--product-version={VERSION}",
        "--output-dir=" + str(OUT),
        "--output-filename=" + FILENAME,
        "--remove-output",
        "--assume-yes-for-downloads",
        str(ENTRY),
    ]
    print(" ".join(cmd))
    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
