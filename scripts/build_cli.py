"""Nuitka one-file build for the `osint` CLI (no Qt, no PySide6 plugin).

Run with: python scripts/build_cli.py
Output:   dist/osint.exe (~25-40 MB single-file)
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "cli.py"
OUT = ROOT / "dist"


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
        "--windows-console-mode=force",
        "--company-name=MarsIT",
        "--product-name=osint",
        "--file-version=0.1.0",
        "--product-version=0.1.0",
        "--output-dir=" + str(OUT),
        "--output-filename=osint.exe",
        "--remove-output",
        "--assume-yes-for-downloads",
        str(ENTRY),
    ]
    print(" ".join(cmd))
    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
