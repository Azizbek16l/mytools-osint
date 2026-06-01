"""`osint doctor` — environment + AI + network diagnostic.

This must work on every laptop osint runs on: Apple-Silicon Macs, Intel Macs,
average Linux/Windows machines. So we keep the dep surface to httpx + stdlib
and degrade gracefully when an optional helper (``psutil``) isn't installed.

Exit codes follow standard tool convention so CI/scripts can react:
  0 — all green
  1 — warnings (works, but recommendations apply)
  2 — errors (something the user must fix before AI / scans work end-to-end)
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import platform
import shutil
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from app.core.config import settings, user_config_path
from app.core.http import get_client
from app.features.ai import (
    DEFAULT_OLLAMA_MODEL,
    OLLAMA_URL,
    ClaudeProvider,
    NoneProvider,
    OllamaProvider,
    select_provider,
)

# --------------------------------------------------------------------------- #
# Status reporting helpers
# --------------------------------------------------------------------------- #

OK = "ok"
WARN = "warn"
ERR = "err"


@dataclass
class Check:
    label: str
    value: str = ""
    status: str = OK
    hint: str = ""


@dataclass
class Section:
    title: str
    checks: list[Check] = field(default_factory=list)

    def add(self, label: str, value: str = "", status: str = OK, hint: str = "") -> None:
        self.checks.append(Check(label, value, status, hint))


# --------------------------------------------------------------------------- #
# Individual probes
# --------------------------------------------------------------------------- #

def _ram_total_bytes() -> int | None:
    """Best-effort total RAM in bytes — works without psutil on every OS we ship."""
    # Prefer psutil if the user already has it. Don't make it a runtime dep.
    try:
        import psutil

        return int(psutil.virtual_memory().total)
    except ImportError:
        pass
    if sys.platform == "linux":
        try:
            with open("/proc/meminfo", encoding="ascii") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) * 1024
        except OSError:
            return None
    if sys.platform == "darwin":
        try:
            import subprocess
            # Pin to the absolute path so ruff S607 is happy and we don't pick
            # up a PATH-injected `sysctl`. /usr/sbin/sysctl ships with macOS.
            out = subprocess.check_output(  # noqa: S603 - args are literal
                ["/usr/sbin/sysctl", "-n", "hw.memsize"], timeout=2,
            )
            return int(out.strip())
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
    if sys.platform == "win32":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            stat_struct = MEMORYSTATUSEX()
            stat_struct.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat_struct)):
                return int(stat_struct.ullTotalPhys)
        except Exception:
            return None
    return None


def _human_bytes(n: int | None) -> str:
    if n is None:
        return "?"
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024.0:
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{size:.1f}PB"


def _is_apple_silicon() -> bool:
    return sys.platform == "darwin" and platform.machine().lower() in ("arm64", "aarch64")


def _arch_label() -> str:
    m = platform.machine().lower()
    if sys.platform == "darwin":
        return "Apple Silicon" if m in ("arm64", "aarch64") else f"Intel Mac ({m})"
    return f"{platform.system()} {m}"


def _dir_size(path: Path) -> int:
    total = 0
    if not path.is_dir():
        return 0
    for p in path.rglob("*"):
        if p.is_file():
            with contextlib.suppress(OSError):
                total += p.stat().st_size
    return total


def _check_system() -> Section:
    sect = Section("System")
    sect.add("OS", f"{platform.system()} {platform.release()}")
    sect.add("Arch", _arch_label())
    sect.add("Python", platform.python_version())
    ram = _ram_total_bytes()
    sect.add("RAM (total)", _human_bytes(ram),
             status=WARN if ram is not None and ram < 8 * 1024**3 else OK,
             hint=("under 8GB — recommend cloud LLM instead of local Ollama"
                   if ram is not None and ram < 8 * 1024**3 else ""))
    sect.add("Apple Silicon", "yes" if _is_apple_silicon() else "no")
    try:
        usage = shutil.disk_usage(settings().data_dir)
        sect.add("Data dir free", _human_bytes(usage.free))
        if usage.free < 1 * 1024**3:
            sect.checks[-1].status = WARN
            sect.checks[-1].hint = "<1GB free — Ollama models won't fit"
    except OSError as e:
        sect.add("Data dir free", "?", status=WARN, hint=str(e))
    return sect


async def _ollama_models() -> tuple[bool, list[str], str]:
    """Reach Ollama and list installed models.

    Returns ``(reachable, [model names], status_text)``. We use a fresh
    httpx client so this probe is isolated from the shared singleton (which
    might be tied up by a parallel scan).
    """
    try:
        async with httpx.AsyncClient(timeout=0.5) as c:
            r = await c.get(f"{OLLAMA_URL}/api/tags")
    except (httpx.HTTPError, OSError):
        return False, [], "unreachable"
    if r.status_code != 200:
        return True, [], f"HTTP {r.status_code}"
    try:
        data = r.json()
    except ValueError:
        return True, [], "bad JSON"
    models = [m.get("name", "") for m in data.get("models", []) if m.get("name")]
    return True, models, f"{len(models)} model(s)"


async def _check_ai() -> Section:
    sect = Section("AI")
    reachable, models, status_text = await _ollama_models()
    sect.add(
        "Ollama @ localhost:11434",
        status_text if reachable else "unreachable",
        status=OK if reachable else WARN,
        hint="" if reachable else "install: https://ollama.com — then `ollama serve`",
    )
    if models:
        sect.add("Ollama models", ", ".join(m for m in models[:6]))
    elif reachable:
        sect.add(
            "Ollama models", "none installed", status=WARN,
            hint=f"`ollama pull {DEFAULT_OLLAMA_MODEL}`",
        )
    _have_key = bool(os.getenv("ANTHROPIC_API_KEY"))
    sect.add(
        "ANTHROPIC_API_KEY",
        "set" if _have_key else "unset",
        status=OK if _have_key else WARN,
        # Only show the call-to-action when the key is actually missing; a
        # healthy "set" row shouldn't carry a now-irrelevant hint.
        hint="" if _have_key
        else "set to enable Claude provider (`osint config set ANTHROPIC_API_KEY …`)",
    )
    opsec = os.getenv("OSINT_OPSEC", "").strip().lower() in {"1", "true", "yes", "on"}
    sect.add(
        "OPSEC mode", "ON" if opsec else "off",
        hint=("OPSEC blocks Claude — only Ollama is allowed" if opsec else ""),
    )
    provider = select_provider()
    pstatus = OK if not isinstance(provider, NoneProvider) else WARN
    sect.add(
        "Active provider", provider.name, status=pstatus,
        hint=("set OSINT_AI_PROVIDER or run Ollama"
              if isinstance(provider, NoneProvider) else ""),
    )
    return sect


def _model_recommendation(ram_bytes: int | None) -> tuple[Section, list[str]]:
    """Return (section, list-of-exact-commands)."""
    sect = Section("Model recommendation")
    commands: list[str] = []
    if ram_bytes is None:
        sect.add("RAM detection", "unavailable", status=WARN,
                 hint="install psutil for a precise read")
        sect.add("Recommendation", f"start with {DEFAULT_OLLAMA_MODEL} (~2GB)")
        commands.append(f"ollama pull {DEFAULT_OLLAMA_MODEL}")
        return sect, commands
    gb = ram_bytes / (1024**3)
    if gb < 8:
        sect.add(
            f"RAM {gb:.1f}GB", "no local LLM",
            status=WARN,
            hint="use Claude (ANTHROPIC_API_KEY) or run scans without AI",
        )
    elif gb < 16:
        sect.add(f"RAM {gb:.1f}GB", "qwen2.5:3b (~2GB Q4)")
        commands.append("ollama pull qwen2.5:3b")
    else:
        sect.add(f"RAM {gb:.1f}GB", "llama3.1:8b or qwen2.5:7b (~5GB Q4)")
        commands.append("ollama pull llama3.1:8b")
        commands.append("ollama pull qwen2.5:7b")
    for cmd in commands:
        sect.add("    →", cmd)
    return sect, commands


def _check_config() -> Section:
    sect = Section("Config")
    cfg = user_config_path()
    sect.add("Config file", str(cfg), status=OK if cfg.exists() else WARN,
             hint="" if cfg.exists() else "run `osint config wizard`")
    if cfg.exists():
        try:
            st = cfg.stat()
            mode = stat.S_IMODE(st.st_mode)
            if sys.platform != "win32" and mode & 0o077:
                sect.add("Config perms", f"{oct(mode)}", status=WARN,
                         hint="contains secrets — chmod 600")
            else:
                sect.add("Config perms", f"{oct(mode)}")
        except OSError as e:
            sect.add("Config perms", "?", status=WARN, hint=str(e))
        # Mask secrets when echoing config keys.
        keys: list[str] = []
        try:
            for line in cfg.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k = line.split("=", 1)[0].strip()
                    if k:
                        keys.append(k)
        except OSError:
            pass
        sect.add("Config keys", ", ".join(keys) if keys else "(empty)")
    s = settings()
    sect.add("Data dir", str(s.data_dir))
    sect.add("Cache size", _human_bytes(_dir_size(s.cache_dir)))
    return sect


async def _check_network() -> Section:
    sect = Section("Network")
    # Single, harmless HEAD against a CT log we already use. Route it through
    # the shared SSRF-guarded / OPSEC-aware client so the probe honours the
    # same egress policy (Tor/SOCKS under OPSEC, no internal targets) as real
    # scans — a bare client would leak the host's real IP under OPSEC.
    try:
        client = await get_client()
        r = await client.head("https://crt.sh", follow_redirects=True,
                              timeout=5.0)
        sect.add("crt.sh reachability", f"HTTP {r.status_code}",
                 status=OK if r.status_code < 500 else WARN)
    except (httpx.HTTPError, OSError) as e:
        # A network probe failure is upstream/transport, not a tool bug — keep
        # it a WARN (osint still runs); the hint carries the cause.
        sect.add("crt.sh reachability", "FAIL",
                 status=WARN, hint=f"{type(e).__name__}: {e}")
    return sect


# --------------------------------------------------------------------------- #
# Public entry point + formatter
# --------------------------------------------------------------------------- #

async def gather() -> tuple[list[Section], int]:
    """Run every check and return ``(sections, exit_code)``."""
    sections: list[Section] = []
    sections.append(_check_system())
    sections.append(await _check_ai())
    rec_section, _cmds = _model_recommendation(_ram_total_bytes())
    sections.append(rec_section)
    sections.append(_check_config())
    sections.append(await _check_network())

    statuses = {c.status for s in sections for c in s.checks}
    if ERR in statuses:
        return sections, 2
    if WARN in statuses:
        return sections, 1
    return sections, 0


_GLYPH = {OK: "✓", WARN: "!", ERR: "✗"}


def render(sections: Iterable[Section], exit_code: int) -> str:
    out: list[str] = []
    out.append("")
    out.append("  osint doctor — local diagnostic")
    out.append("  " + "─" * 38)
    for s in sections:
        out.append("")
        out.append(f"  {s.title}")
        for c in s.checks:
            g = _GLYPH.get(c.status, "·")
            line = f"    {g} {c.label:24} {c.value}"
            out.append(line)
            if c.hint:
                out.append(f"        ↳ {c.hint}")
    out.append("")
    if exit_code == 0:
        out.append("  Verdict: ✓ all green")
    elif exit_code == 1:
        out.append("  Verdict: ! warnings — osint will still run; see hints above")
    else:
        out.append("  Verdict: ✗ errors — fix the items above before scanning")
    out.append("")
    return "\n".join(out)


def cmd_doctor(argv: list[str] | None = None) -> int:
    """`osint doctor` entrypoint."""
    sections, code = asyncio.run(gather())
    sys.stdout.write(render(sections, code))
    return code


# Re-export so tests / programmatic callers can use the checks directly
# without having to read the env.
__all__ = [
    "Check", "Section", "OK", "WARN", "ERR",
    "gather", "render", "cmd_doctor",
    "_ram_total_bytes", "_is_apple_silicon", "_model_recommendation",
    "_check_system", "_check_ai", "_check_config", "_check_network",
    "_ollama_models",
    "ClaudeProvider", "OllamaProvider",  # for tests/monkeypatching convenience
]
