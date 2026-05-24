"""HTTP response cache — per-URL TTL via aiosqlite.

When `OSINT_CACHE=1` is set, every GET via app.core.http is cached at
`%LOCALAPPDATA%/mytools-osint/cache/http.sqlite` with a per-source TTL:

  - subdomain enumeration (crt.sh, urlscan, OTX, ...)  → 6 h
  - IP intel (InternetDB, GreyNoise, Spamhaus)          → 24 h
  - threat-intel (URLhaus, ThreatFox, MalwareBazaar)    → 2 h  (stale → still useful)
  - DNS / network records                                → 1 h
  - identity / username / email probes                   → 30 m (faster decay)
  - everything else                                      → 6 h

Why this matters: re-running `osint mycorp.com --profile red-team` to
test report formatting should NOT re-hit 1000 sites. With cache on,
the second run is sub-second and zero-network-traffic. Perfect for the
analyst iteration loop.

Wipe cache: `osint cache clear`  (or just `rm -rf $CACHE_DIR`).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import aiosqlite

from app.core.config import settings

_DB_LOCK = asyncio.Lock()
_INIT_DONE = False

# Per-source-host TTL (seconds). Anything not matched defaults to 6 h.
_TTL_PER_HOST: dict[str, int] = {
    "crt.sh":                      6 * 3600,
    "urlscan.io":                  6 * 3600,
    "otx.alienvault.com":          6 * 3600,
    "api.hackertarget.com":        6 * 3600,
    "rapiddns.io":                 6 * 3600,
    "api.subdomain.center":        6 * 3600,
    "api.threatminer.org":         6 * 3600,
    "web.archive.org":             6 * 3600,
    "internetdb.shodan.io":       24 * 3600,
    "api.greynoise.io":           24 * 3600,
    "www.spamhaus.org":           24 * 3600,
    "urlhaus-api.abuse.ch":        2 * 3600,
    "threatfox-api.abuse.ch":      2 * 3600,
    "mb-api.abuse.ch":             2 * 3600,
    "checkurl.phishtank.com":      2 * 3600,
    "onionoo.torproject.org":     24 * 3600,
    "api.bgpview.io":             24 * 3600,
    "whois.cymru.com":            24 * 3600,
    "keys.openpgp.org":            6 * 3600,
    "keyserver.ubuntu.com":        6 * 3600,
    "api.github.com":              1 * 3600,
    "haveibeenpwned.com":         24 * 3600,
    "api.pwnedpasswords.com":     24 * 3600,
    "emailrep.io":                 6 * 3600,
    # identity probes — short
    "gravatar.com":               30 * 60,
}
_DEFAULT_TTL = 6 * 3600


def is_enabled() -> bool:
    import os
    return os.getenv("OSINT_CACHE", "").strip().lower() in {"1", "true", "yes", "on"}


def ttl_for(url: str) -> int:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return _DEFAULT_TTL
    return _TTL_PER_HOST.get(host, _DEFAULT_TTL)


def cache_path() -> str:
    s = settings()
    return str(s.cache_dir / "http.sqlite")


@asynccontextmanager
async def _conn():
    global _INIT_DONE
    db = await aiosqlite.connect(cache_path())
    try:
        if not _INIT_DONE:
            async with _DB_LOCK:
                await db.execute(
                    "CREATE TABLE IF NOT EXISTS http_cache ("
                    " key TEXT PRIMARY KEY,"
                    " url TEXT NOT NULL,"
                    " status INTEGER NOT NULL,"
                    " headers TEXT NOT NULL,"
                    " body BLOB NOT NULL,"
                    " stored_at INTEGER NOT NULL,"
                    " expires_at INTEGER NOT NULL"
                    ")"
                )
                await db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_expires ON http_cache(expires_at)"
                )
                await db.execute("PRAGMA journal_mode=WAL")
                await db.commit()
                _INIT_DONE = True
        yield db
    finally:
        await db.close()


def _key(method: str, url: str, body: bytes = b"") -> str:
    h = hashlib.sha256()
    h.update(method.upper().encode())
    h.update(b"\0")
    h.update(url.encode())
    if body:
        h.update(b"\0")
        h.update(body)
    return h.hexdigest()


async def get(method: str, url: str, body: bytes = b"") -> dict | None:
    if not is_enabled():
        return None
    if method.upper() != "GET":
        return None
    k = _key(method, url, body)
    now = int(time.time())
    async with _conn() as db:
        cur = await db.execute(
            "SELECT status, headers, body FROM http_cache "
            "WHERE key = ? AND expires_at > ?",
            (k, now),
        )
        row = await cur.fetchone()
        await cur.close()
    if not row:
        return None
    return {"status": row[0], "headers": json.loads(row[1]), "body": row[2]}


async def put(method: str, url: str, status: int, headers: dict, body: bytes) -> None:
    if not is_enabled() or method.upper() != "GET":
        return
    k = _key(method, url)
    now = int(time.time())
    ttl = ttl_for(url)
    async with _conn() as db:
        await db.execute(
            "INSERT OR REPLACE INTO http_cache "
            "(key, url, status, headers, body, stored_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (k, url, status, json.dumps(dict(headers)), body, now, now + ttl),
        )
        await db.commit()


async def stats() -> dict:
    async with _conn() as db:
        cur = await db.execute(
            "SELECT COUNT(*), SUM(LENGTH(body)), MAX(stored_at), MIN(stored_at) "
            "FROM http_cache"
        )
        row = await cur.fetchone()
        await cur.close()
        cur2 = await db.execute(
            "SELECT COUNT(*) FROM http_cache WHERE expires_at < ?",
            (int(time.time()),),
        )
        expired_row = await cur2.fetchone()
        await cur2.close()
    return {
        "entries": row[0] or 0,
        "bytes": row[1] or 0,
        "newest": row[2],
        "oldest": row[3],
        "expired": expired_row[0] or 0,
        "path": cache_path(),
    }


async def clear(only_expired: bool = False) -> int:
    async with _conn() as db:
        if only_expired:
            cur = await db.execute(
                "DELETE FROM http_cache WHERE expires_at < ?",
                (int(time.time()),),
            )
        else:
            cur = await db.execute("DELETE FROM http_cache")
        await db.commit()
        n = cur.rowcount
        await cur.close()
    return n or 0


def cmd_cache(argv: list[str]) -> int:
    """`osint cache [stats|clear|clear-expired]`."""
    sub = argv[0] if argv else "stats"

    async def _run() -> int:
        if sub == "stats":
            s = await stats()
            from app import __version__ as v
            mb = s["bytes"] / (1024 * 1024)
            print(f"  cache (mytools-osint v{v})")
            print(f"    path:    {s['path']}")
            print(f"    entries: {s['entries']:,}  ({s['expired']:,} expired)")
            print(f"    size:    {mb:.1f} MiB")
            import os
            print(f"    enabled: {'yes' if is_enabled() else 'no (set OSINT_CACHE=1)'}")
            return 0
        if sub == "clear":
            n = await clear(only_expired=False)
            print(f"  cleared {n:,} entries")
            return 0
        if sub == "clear-expired":
            n = await clear(only_expired=True)
            print(f"  pruned {n:,} expired entries")
            return 0
        print("usage: osint cache [stats|clear|clear-expired]", file=__import__("sys").stderr)
        return 2

    return asyncio.run(_run())
