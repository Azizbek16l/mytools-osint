"""Typosquat / IDN-homograph candidate generator + live DNS check.

Generates a deliberately small set of high-quality typosquat candidates
for a domain (no need to ship a 10k-candidate firehose — that drowns the
analyst). Strategies:

  - 1-char deletion / insertion / substitution (qwerty-adjacent only)
  - 1-char transposition
  - homoglyph substitution (latin↔cyrillic look-alikes)
  - TLD swap (.com↔.co/.cm/.net/.org/.io/.app)
  - bitsquat (single-bit flip in each char)
  - prepend/append common terms (login-, -app, -secure)

Then resolve each candidate's A record concurrently. Any candidate that
*currently* resolves is suspicious and yielded as a Hit (HIGH).

No external API. Capped at ~150 candidates worst-case.
"""
from __future__ import annotations

import asyncio
import string
from collections.abc import AsyncIterator

import dns.asyncresolver

from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "typosquat"

_DNS_TIMEOUT = 4.0
_CONCURRENCY = 30

QWERTY_ADJ: dict[str, str] = {
    "q": "wa", "w": "qase", "e": "wsdr", "r": "edft", "t": "rfgy",
    "y": "tghu", "u": "yhji", "i": "ujko", "o": "iklp", "p": "ol",
    "a": "qwsz", "s": "awedxz", "d": "serfcx", "f": "drtgvc",
    "g": "ftyhbv", "h": "gyujnb", "j": "huikmn", "k": "jiolm",
    "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk",
    "0": "9o", "1": "2q", "2": "13qw", "3": "24we", "4": "35er",
    "5": "46rt", "6": "57ty", "7": "68yu", "8": "79ui", "9": "80io",
}

HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["а"],          # cyrillic a
    "e": ["е"],          # cyrillic ie
    "o": ["о", "0"],     # cyrillic o, digit zero
    "p": ["р"],          # cyrillic er
    "c": ["с"],          # cyrillic es
    "x": ["х"],          # cyrillic ha
    "y": ["у"],          # cyrillic u
    "i": ["і", "1", "l"], # cyrillic dotted i, digit one, lowercase L
    "l": ["1", "i"],
    "m": ["rn"],         # rn approximates m at low DPI
    "n": ["п"],          # cyrillic pe
    "s": ["5"],
    "g": ["q", "9"],
    "k": ["к"],
    "h": ["һ"],
    "b": ["6"],
}

ALT_TLDS = [".com", ".co", ".cm", ".net", ".org", ".io", ".app",
            ".online", ".info", ".biz", ".xyz", ".sh", ".dev"]

PREPEND = ["login", "secure", "account", "support", "verify", "my", "mail"]
APPEND = ["-login", "-secure", "-app", "-support", "-online"]


def _ascii(s: str) -> bool:
    return all(c in string.ascii_lowercase + string.digits for c in s)


def _split_root_tld(domain: str) -> tuple[str, str]:
    if "." not in domain:
        return domain, ""
    parts = domain.split(".")
    # Treat last two labels for tlds like .co.uk roughly — not perfect but fine.
    if len(parts) >= 2 and parts[-2] in {"co", "com", "net", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[:-2]), "." + ".".join(parts[-2:])
    return ".".join(parts[:-1]), "." + parts[-1]


def _bitflip_char(c: str) -> list[str]:
    out: list[str] = []
    b = ord(c)
    for bit in range(7):
        flipped = b ^ (1 << bit)
        ch = chr(flipped)
        if ch in string.ascii_lowercase + string.digits + "-":
            out.append(ch)
    return out


def generate_candidates(domain: str) -> list[str]:
    """Return a deduped, capped list of typosquat candidates."""
    root, tld = _split_root_tld(domain)
    if not root or not _ascii(root):
        return []
    out: set[str] = set()

    # 1-char deletion
    for i in range(len(root)):
        c = root[:i] + root[i+1:]
        if 2 <= len(c) <= 40:
            out.add(c + tld)
    # 1-char insertion (qwerty-adjacent)
    for i in range(len(root) + 1):
        prev = root[i-1] if i > 0 else ""
        for ch in QWERTY_ADJ.get(prev, "abcdefghijklmnopqrstuvwxyz"):
            c = root[:i] + ch + root[i:]
            if 2 <= len(c) <= 40:
                out.add(c + tld)
    # 1-char substitution (qwerty-adjacent)
    for i, c in enumerate(root):
        for nb in QWERTY_ADJ.get(c, ""):
            out.add(root[:i] + nb + root[i+1:] + tld)
    # 1-char transposition
    for i in range(len(root) - 1):
        out.add(root[:i] + root[i+1] + root[i] + root[i+2:] + tld)
    # bitsquat
    for i, c in enumerate(root):
        for nb in _bitflip_char(c):
            out.add(root[:i] + nb + root[i+1:] + tld)
    # TLD swap
    for alt in ALT_TLDS:
        if alt != tld:
            out.add(root + alt)
    # prepend / append (kept small)
    for p in PREPEND[:3]:
        out.add(f"{p}-{root}{tld}")
    for a in APPEND[:3]:
        out.add(f"{root}{a}{tld}")

    # Drop the original
    out.discard(domain)
    cands = sorted(out)
    return cands[:160]


async def _resolve(host: str) -> tuple[str, list[str]]:
    try:
        ans = await dns.asyncresolver.resolve(host, "A", lifetime=_DNS_TIMEOUT)
        return host, [r.to_text() for r in ans]
    except Exception:
        return host, []


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    if not domain or "." not in domain:
        return
    candidates = generate_candidates(domain)
    if not candidates:
        return
    sem = asyncio.Semaphore(_CONCURRENCY)

    async def gated(host: str) -> tuple[str, list[str]]:
        async with sem:
            return await _resolve(host)

    tasks = [asyncio.create_task(gated(c)) for c in candidates]
    registered = 0
    for fut in asyncio.as_completed(tasks):
        try:
            host, ips = await fut
        except Exception as e:
            yield Hit(module=NAME, source=NAME, status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")
            continue
        if not ips:
            continue
        registered += 1
        yield Hit(
            module=NAME, source="typosquat", category="domain-risk",
            url=f"http://{host}/",
            status=HitStatus.FOUND, title=host,
            detail=f"registered → {', '.join(ips[:3])}",
            severity=Severity.HIGH,
            extra={"candidate": host, "ips": ips},
        )
    yield Hit(module=NAME, source="summary", category="domain-risk",
              status=HitStatus.FOUND if registered else HitStatus.NO_DATA,
              title=domain,
              detail=f"{registered}/{len(candidates)} typosquat candidates registered",
              severity=Severity.INFO,
              extra={"candidates": len(candidates), "registered": registered})


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
