"""Nuitka one-file Windows build for mytools-osint.

Run with: python scripts/build_exe.py
Output:   dist/mytools-osint.exe (≈70-95 MB single-file, no Python install needed)

First build takes ~5-10 min as Nuitka compiles. Subsequent builds reuse the cache.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "main.py"
OUT = ROOT / "dist"


def main() -> int:
    if shutil.which("python") is None:
        print("python not on PATH", file=sys.stderr)
        return 2
    OUT.mkdir(exist_ok=True)
    cmd = [
        sys.executable, "-m", "nuitka",
        "--onefile",
        "--standalone",
        "--enable-plugin=pyside6",
        "--include-package=app",
        "--include-package=telethon",
        "--include-package-data=phonenumbers",
        "--include-data-dir=data=data",
        "--include-data-files=.env.example=.env.example",
        "--windows-console-mode=disable",
        "--company-name=MarsIT",
        "--product-name=mytools-osint",
        "--file-version=0.1.0",
        "--product-version=0.1.0",
        "--output-dir=" + str(OUT),
        "--output-filename=mytools-osint.exe",
        "--remove-output",
        "--assume-yes-for-downloads",
        str(ENTRY),
    ]
    print(" ".join(cmd))
    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
