"""Add D:\\Code\\mytools\\dist to the user PATH (User-scope, not Machine).

Idempotent — re-run is a no-op if the path is already present.
Verifies the result by reading back PATH from the registry.
"""
from __future__ import annotations

import os
import subprocess
import sys
import winreg
from pathlib import Path


def get_user_path() -> str:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
        try:
            value, _ = winreg.QueryValueEx(k, "Path")
        except FileNotFoundError:
            return ""
    return str(value)


def set_user_path(new: str) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as k:
        # REG_EXPAND_SZ preserves environment variables like %USERPROFILE% if present
        winreg.SetValueEx(k, "Path", 0, winreg.REG_EXPAND_SZ, new)


def main() -> int:
    target = str(Path(__file__).resolve().parents[1] / "dist")
    target_norm = os.path.normpath(target).rstrip("\\")
    current = get_user_path()
    entries = [p for p in current.split(";") if p]
    if any(os.path.normpath(p).rstrip("\\").lower() == target_norm.lower() for p in entries):
        print(f"already on User PATH: {target}", flush=True)
    else:
        entries.append(target_norm)
        new = ";".join(entries)
        set_user_path(new)
        print(f"added to User PATH: {target}", flush=True)
        # broadcast WM_SETTINGCHANGE so new shells see the update immediately
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "[void][Environment]::GetEnvironmentVariable('Path','User')"],
                check=False, capture_output=True,
            )
        except Exception:
            pass

    # verify
    after = get_user_path()
    ok = any(os.path.normpath(p).rstrip("\\").lower() == target_norm.lower()
             for p in after.split(";") if p)
    if not ok:
        print("VERIFICATION FAILED — PATH does not contain the target.", file=sys.stderr)
        return 1
    print(f"User PATH now contains {target}", flush=True)
    print("Open a NEW PowerShell to pick up the change, then run:  osint torvalds",
          flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
