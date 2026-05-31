"""`osint self-update` — pull the latest release binary in place.

Behavior:
  1. Hit https://api.github.com/repos/Azizbek16l/mytools-osint/releases/latest
  2. Compare tag with our embedded __version__
  3. If newer, download the right asset for the current platform from the
     release page, verify SHA-256 against the SHA256SUMS asset, swap it in
     atomically via `os.rename` (works across same-fs path on every OS).

Pipx/brew users get an instruction to update via their package manager
instead — replacing the binary in those layouts would break the wrapper.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from app import __version__ as CURRENT_VERSION
from app.core.http import close_client
from app.core.http import request as http_request

REPO = "Azizbek16l/mytools-osint"
RELEASE_API = f"https://api.github.com/repos/{REPO}/releases/latest"


def _platform_asset() -> str | None:
    if sys.platform == "darwin":
        import platform
        return ("osint-macos-arm64" if platform.machine() in ("arm64", "aarch64")
                else "osint-macos-x86_64")
    if sys.platform == "win32":
        return "osint-windows-x64.exe"
    if sys.platform.startswith("linux"):
        return "osint-linux-x86_64"
    return None


async def _afetch(url: str) -> bytes | None:
    """Fetch ``url`` through the shared SSRF-guarded / OPSEC-aware client.

    Routing through ``app.core.http`` means self-update honours the same
    egress policy as scans: under ``OSINT_OPSEC=1`` traffic goes via the
    SOCKS/Tor proxy (no real-IP leak to GitHub), and internal/metadata
    targets are rejected. httpx uses certifi's CA bundle by default, so the
    macOS Python.framework trust-store gap is covered too.
    """
    # GitHub's REST API requires application/vnd.github+json for the
    # /releases/* endpoints; release-asset downloads need octet-stream.
    accept = ("application/vnd.github+json"
              if "api.github.com" in url else "application/octet-stream")
    headers = {
        "User-Agent": f"mytools-osint/{CURRENT_VERSION}",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    resp = await http_request("GET", url, retries=1, timeout=30.0, headers=headers)
    if resp is None:
        return None
    if resp.status_code != 200:
        print(f"  fetch failed: HTTP {resp.status_code} for {url}", file=sys.stderr)
        return None
    return resp.content


def _fetch(url: str, dest: Path | None = None) -> bytes | None:
    """Sync wrapper around :func:`_afetch`. Optionally writes to ``dest``."""
    try:
        data = asyncio.run(_run_fetch(url))
    except Exception as e:
        print(f"  fetch failed: {e}", file=sys.stderr)
        return None
    if data is None:
        return None
    if dest:
        dest.write_bytes(data)
        return None
    return data


async def _run_fetch(url: str) -> bytes | None:
    """Fetch then close the shared client (we own no long-lived loop here)."""
    try:
        return await _afetch(url)
    finally:
        await close_client()


def _is_pipx_install() -> bool:
    return "pipx" in str(Path(sys.argv[0]).resolve())


def _is_brew_install() -> bool:
    return "Cellar" in str(Path(sys.argv[0]).resolve()) or \
           "/opt/homebrew" in str(Path(sys.argv[0]).resolve())


def _is_scoop_install() -> bool:
    return os.name == "nt" and "scoop" in str(Path(sys.argv[0]).resolve()).lower()


def cmd_self_update(check_only: bool = False) -> int:
    """Entry point for `osint self-update`."""
    print(f"  current: v{CURRENT_VERSION}")
    raw = _fetch(RELEASE_API)
    if raw is None:
        return 1
    try:
        meta = json.loads(raw)
    except Exception as e:
        print(f"  bad release json: {e}", file=sys.stderr)
        return 1
    latest_tag = meta.get("tag_name", "").lstrip("v")
    if not latest_tag:
        print("  could not determine latest release tag", file=sys.stderr)
        return 1
    print(f"  latest:  v{latest_tag}")
    if _ver_tuple(latest_tag) <= _ver_tuple(CURRENT_VERSION):
        print("  ✓ already up to date")
        return 0
    if check_only:
        print("  ⤴ update available — run `osint self-update` to install")
        return 0

    # Detect package-manager installs and bail out with the right hint.
    if _is_pipx_install():
        print("  detected pipx install — run `pipx upgrade mytools-osint` to update")
        return 0
    if _is_brew_install():
        print("  detected Homebrew install — run `brew upgrade mytools-osint` to update")
        return 0
    if _is_scoop_install():
        print("  detected Scoop install — run `scoop update mytools-osint` to update")
        return 0

    # Direct-binary install path: download + verify + swap.
    asset_name = _platform_asset()
    if asset_name is None:
        print(f"  unsupported platform {sys.platform!r}", file=sys.stderr)
        return 1
    assets = {a["name"]: a for a in meta.get("assets") or []}
    if asset_name not in assets:
        print(f"  release doesn't have asset {asset_name}", file=sys.stderr)
        return 1
    if "SHA256SUMS" not in assets:
        print("  release missing SHA256SUMS — refusing unverified update", file=sys.stderr)
        return 1

    print(f"  downloading {asset_name} …")
    with tempfile.TemporaryDirectory(prefix="osint-update-") as tmp:
        tmpdir = Path(tmp)
        bin_dest = tmpdir / asset_name
        _fetch(assets[asset_name]["browser_download_url"], bin_dest)
        if not bin_dest.exists() or bin_dest.stat().st_size < 1_000_000:
            print("  download failed or file too small", file=sys.stderr)
            return 1
        sums = _fetch(assets["SHA256SUMS"]["browser_download_url"])
        if sums is None:
            return 1
        expected = None
        for line in sums.decode("utf-8", "replace").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[-1].lstrip("*") == asset_name:
                expected = parts[0]
                break
        if not expected:
            print(f"  no SHA-256 for {asset_name} in SHA256SUMS", file=sys.stderr)
            return 1
        got = hashlib.sha256(bin_dest.read_bytes()).hexdigest()
        if got != expected:
            print(f"  SHA-256 mismatch! expected {expected[:12]}…  got {got[:12]}…",
                  file=sys.stderr)
            return 1
        print(f"  ✓ SHA-256 verified ({expected[:16]}…)")

        # Swap in place — works only if argv[0] is a real file we can replace.
        target = Path(sys.argv[0]).resolve()
        if target.suffix == ".py":
            print(f"  detected source install — {target} is a .py file, "
                  "use `pip install --upgrade .` from your checkout", file=sys.stderr)
            return 0
        # Move via os.rename to be atomic-on-same-fs
        try:
            shutil.copymode(target, bin_dest)
            backup = target.with_suffix(target.suffix + ".bak")
            shutil.move(str(target), str(backup))
            shutil.move(str(bin_dest), str(target))
            backup.unlink(missing_ok=True)
            print(f"  ✓ updated → {target}")
            return 0
        except Exception as e:
            print(f"  swap failed: {e}", file=sys.stderr)
            return 1


def _ver_tuple(v: str) -> tuple:
    """Parse 'X.Y.Z' to a tuple; non-numeric components compare last."""
    parts = []
    for p in v.split("."):
        try:
            parts.append((0, int(p)))
        except ValueError:
            parts.append((1, p))
    return tuple(parts)
