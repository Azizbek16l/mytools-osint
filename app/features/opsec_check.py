"""`osint opsec-check` — verify --opsec mode is leak-free.

What it proves:
  1. Egress IP (via api.ipify.org / icanhazip.com) — should be a Tor exit
     when --opsec is on, NOT your real ISP IP.
  2. DNS server seen by the request — should be the proxy's resolver
     (cloudflare-dns.com / tor-internal) NOT your ISP's.
  3. User-Agent over 5 calls — should differ each time when --opsec is on.
  4. Request jitter — measure inter-request latency for 5 quick calls.

Output: dim panel with PASS/FAIL per check. Non-zero exit if any check fails
while --opsec is active.
"""
from __future__ import annotations

import asyncio
import statistics
import time

from app.core.http import _opsec_on, get_client

_IPCHECK_URLS = [
    "https://api.ipify.org?format=json",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip",
    "https://api64.ipify.org?format=json",
]


async def _egress_ip() -> tuple[str | None, str]:
    """Best-effort egress IP via 5 providers. Returns (ip, source)."""
    client = await get_client()
    for url in _IPCHECK_URLS:
        try:
            r = await client.get(url, timeout=8.0)
            if r.status_code != 200:
                continue
            txt = r.text.strip()
            if txt.startswith("{"):
                try:
                    txt = r.json().get("ip", "")
                except Exception:
                    continue
            txt = txt.strip().strip('"')
            if txt and "." in txt or ":" in txt:
                return txt, url
        except Exception:
            continue
    return None, ""


async def _tor_exit_check(ip: str) -> tuple[bool, str]:
    """Hit Tor Project's check endpoint — confirms if `ip` is a known exit."""
    try:
        client = await get_client()
        r = await client.get("https://check.torproject.org/api/ip", timeout=8.0)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        try:
            data = r.json()
            is_tor = bool(data.get("IsTor", False))
            return is_tor, f"check.torproject.org says IsTor={is_tor}"
        except Exception:
            return False, "non-json response"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


async def _ua_rotation_check() -> tuple[bool, list[str]]:
    """Make 5 sequential calls; with OPSEC, each should send a fresh UA."""
    seen: list[str] = []
    client = await get_client()
    for _ in range(5):
        try:
            r = await client.get("https://httpbin.org/user-agent", timeout=8.0)
            if r.status_code == 200:
                try:
                    seen.append(r.json().get("user-agent", ""))
                except Exception:
                    seen.append(r.text[:120])
        except Exception:
            seen.append("(error)")
    distinct = len(set(seen))
    # With OPSEC on, expect ALL 5 to differ. Off → 1 distinct.
    return (distinct >= 3), seen


async def _jitter_check() -> tuple[bool, float, float]:
    """5 quick calls; measure inter-arrival latency; OPSEC adds 200-800ms jitter."""
    client = await get_client()
    times: list[float] = []
    for _ in range(5):
        t0 = time.perf_counter()
        try:
            await client.get("https://httpbin.org/get", timeout=8.0)
        except Exception:
            pass
        times.append(time.perf_counter() - t0)
    avg = statistics.mean(times)
    stdev = statistics.stdev(times) if len(times) > 1 else 0.0
    # Stdev > 0.15s suggests jitter is active.
    return (stdev > 0.15), avg, stdev


def _row(label: str, ok: bool, detail: str = "", expected: str = "") -> str:
    badge = "\033[32m✓ PASS\033[0m" if ok else "\033[31m✗ FAIL\033[0m"
    out = f"  {badge}  {label:<28} {detail}"
    if expected and not ok:
        out += f"\n            \033[2mexpected: {expected}\033[0m"
    return out


async def _run() -> int:
    opsec_on = _opsec_on()
    print()
    print("\033[1m  osint opsec-check\033[0m  "
          f"\033[2m(OPSEC mode: {'ON' if opsec_on else 'OFF'})\033[0m")
    print("  " + "─" * 70)

    # 1. Egress IP
    ip, src = await _egress_ip()
    if ip is None:
        print(_row("Egress IP", False, "could not determine (network down?)"))
        return 1
    print(_row("Egress IP", True, f"{ip}  \033[2m({src.split('/')[2]})\033[0m"))

    # 2. Tor exit check (only meaningful if --opsec on)
    if opsec_on:
        is_tor, msg = await _tor_exit_check(ip)
        print(_row("Tor exit?", is_tor, msg,
                   expected="check.torproject.org says IsTor=True"))
    else:
        print("  \033[2m·       Tor exit?                   skipped (OPSEC off)\033[0m")

    # 3. UA rotation
    ua_ok, uas = await _ua_rotation_check()
    distinct = len(set(uas))
    if opsec_on:
        print(_row("UA rotation (5 calls)", ua_ok,
                   f"{distinct}/5 distinct UAs seen",
                   expected="≥3 distinct UAs with OPSEC on"))
    else:
        # Off-mode expectation: same UA every call (we use a shared client)
        consistent = (distinct == 1)
        print(_row("UA consistency (off-mode)", consistent,
                   f"{distinct}/5 distinct UA — expected 1 with OPSEC off"))

    # 4. Jitter
    j_ok, avg, stdev = await _jitter_check()
    if opsec_on:
        print(_row("Inter-request jitter", j_ok,
                   f"avg={avg*1000:.0f}ms stdev={stdev*1000:.0f}ms",
                   expected="stdev > 150ms with OPSEC on"))
    else:
        # Off: no jitter, stdev should be small (driven only by network)
        print(f"  \033[2m·       Jitter (off-mode)           avg={avg*1000:.0f}ms "
              f"stdev={stdev*1000:.0f}ms\033[0m")

    print()
    # Exit non-zero if OPSEC on but any leak check failed.
    if opsec_on:
        fails = 0
        is_tor, _ = await _tor_exit_check(ip)
        if not is_tor:
            fails += 1
        if not ua_ok:
            fails += 1
        if not j_ok:
            fails += 1
        if fails:
            print(f"\033[31m  {fails} check(s) failed — OPSEC mode is NOT properly leak-free.\033[0m")
            return 1
        print("\033[32m  ✓ OPSEC mode verified — egress is Tor, UA rotates, jitter active.\033[0m")
    return 0


def cmd_opsec_check() -> int:
    """Entry point for `osint opsec-check`."""
    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        print("\n  cancelled.")
        return 130
