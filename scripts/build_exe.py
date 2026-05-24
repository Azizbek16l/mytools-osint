"""Nuitka one-file build for the mytools-osint GUI (PySide6).

Run with: python scripts/build_exe.py
Output:   dist/mytools-osint(.exe on Windows)  ~70-95 MB single-file

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
sys.path.insert(0, str(ROOT))

try:
    from app import __version__ as VERSION
except Exception:
    VERSION = "0.0.0"

# See build_cli.py for rationale — must match release.yml `cp dist/mytools-osint${ext}`.
FILENAME = "mytools-osint.exe" if sys.platform == "win32" else "mytools-osint"


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
