"""Crypto / blockchain wallet recon (C1).

Free public explorers — NO API keys required:
  - blockchain.info        — BTC balance, tx count, first/last seen
  - api.blockchair.com     — BTC / ETH dashboards (balance, tx count, ages)
  - bitcoinabuse.com       — scam-report aggregator (key optional; works anon for read)
  - cryptoscamdb           — separate scam DB; checked via HEAD first (host may be dead)

Each source emits its own Hit. Severity escalates with confirmed abuse-report
count. A single summary Hit closes the run.
"""
from __future__ import annotations

import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "wallet"

# Address shape detection — also re-used by app.core.infer.
_BTC_BASE58_RE = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$")
_BTC_BECH32_RE = re.compile(r"^bc1[0-9ac-hj-np-z]{6,87}$", re.IGNORECASE)
_ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

_TIMEOUT = 15.0


def detect_address(value: str) -> str | None:
    """Return 'btc' | 'eth' if value looks like a wallet address, else None."""
    v = (value or "").strip()
    if not v:
        return None
    if _ETH_RE.match(v):
        return "eth"
    if _BTC_BECH32_RE.match(v):
        return "btc"
    if _BTC_BASE58_RE.match(v):
        return "btc"
    return None


def _ts(epoch: int | float | None) -> str:
    if not epoch:
        return ""
    try:
        return datetime.fromtimestamp(int(epoch), tz=UTC).strftime("%Y-%m-%d")
    except Exception:
        return ""


def _btc_amount(satoshis: Any) -> float:
    """satoshis -> BTC. Robust to None / strings."""
    try:
        return float(int(satoshis)) / 1e8
    except Exception:
        return 0.0


# ---- per-source probes ----------------------------------------------------

async def _blockchain_info(addr: str) -> Hit:
    url = f"https://blockchain.info/rawaddr/{addr}?limit=1"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"Accept": "application/json"})
    except Exception as e:
        return Hit(module=NAME, source="blockchain.info", category="wallet",
                   url=url, status=classify_exception(e),
                   title=addr, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200:
        return Hit(module=NAME, source="blockchain.info", category="wallet",
                   url=url, status=classify_http(r.status_code),
                   title=addr, detail=f"HTTP {r.status_code}")
    try:
        data = r.json() or {}
    except Exception:
        return Hit(module=NAME, source="blockchain.info", category="wallet",
                   url=url, status=HitStatus.ERROR,
                   title=addr, detail="unparseable JSON")
    balance = _btc_amount(data.get("final_balance"))
    n_tx = int(data.get("n_tx") or 0)
    txs = data.get("txs") or []
    first_ts = ""
    if txs:
        try:
            first_ts = _ts(min(int(t.get("time", 0)) for t in txs if t.get("time")))
        except ValueError:
            first_ts = ""
    return Hit(
        module=NAME, source="blockchain.info", category="wallet",
        url=f"https://www.blockchain.com/btc/address/{addr}",
        status=HitStatus.FOUND, title=addr,
        detail=f"BTC balance={balance:.8f} tx_count={n_tx}"
               + (f" first_tx={first_ts}" if first_ts else ""),
        extra={"balance_btc": balance, "n_tx": n_tx, "first_tx": first_ts},
        severity=Severity.MEDIUM if balance > 0 else Severity.INFO,
        confidence=1.0 if balance > 0 else 0.85,
        evidence={"chain": "btc", "balance_btc": f"{balance:.8f}",
                  "n_tx": str(n_tx)},
    )


async def _blockchair(addr: str, chain: str) -> Hit:
    """Blockchair dashboard. chain ∈ {bitcoin, ethereum}."""
    url = f"https://api.blockchair.com/{chain}/dashboards/address/{addr}"
    sym = "BTC" if chain == "bitcoin" else "ETH"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"Accept": "application/json"})
    except Exception as e:
        return Hit(module=NAME, source=f"blockchair/{chain}", category="wallet",
                   url=url, status=classify_exception(e),
                   title=addr, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200:
        return Hit(module=NAME, source=f"blockchair/{chain}", category="wallet",
                   url=url, status=classify_http(r.status_code),
                   title=addr, detail=f"HTTP {r.status_code}")
    try:
        data = r.json() or {}
    except Exception:
        return Hit(module=NAME, source=f"blockchair/{chain}", category="wallet",
                   url=url, status=HitStatus.ERROR,
                   title=addr, detail="unparseable JSON")
    payload = (data.get("data") or {}).get(addr) or {}
    info = payload.get("address") or {}
    if not info:
        return Hit(module=NAME, source=f"blockchair/{chain}", category="wallet",
                   url=url, status=HitStatus.NO_DATA,
                   title=addr, detail="address not seen on chain")
    if chain == "bitcoin":
        bal = _btc_amount(info.get("balance"))
    else:
        try:
            bal = float(info.get("balance", 0)) / 1e18
        except Exception:
            bal = 0.0
    n_tx = int(info.get("transaction_count") or 0)
    first_seen = (info.get("first_seen_receiving") or "").split("T", 1)[0]
    last_seen = (info.get("last_seen_spending") or info.get("last_seen_receiving") or "").split("T", 1)[0]
    return Hit(
        module=NAME, source=f"blockchair/{chain}", category="wallet",
        url=url,
        status=HitStatus.FOUND, title=addr,
        detail=f"{sym} balance={bal:.8f} tx={n_tx}"
               + (f" first={first_seen}" if first_seen else "")
               + (f" last={last_seen}" if last_seen else ""),
        extra={f"balance_{sym.lower()}": bal, "n_tx": n_tx,
               "first_seen": first_seen, "last_seen": last_seen},
        severity=Severity.MEDIUM if bal > 0 else Severity.INFO,
        confidence=1.0 if bal > 0 else 0.85,
        evidence={"chain": chain, "balance": f"{bal:.8f}", "n_tx": str(n_tx)},
    )


async def _bitcoinabuse(addr: str) -> Hit:
    """Anonymous read-only check (works without API key).

    Returns FOUND with severity scaling on report count, or NO_DATA when clean.
    """
    url = f"https://www.bitcoinabuse.com/api/reports/check?address={addr}"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"Accept": "application/json"})
    except Exception as e:
        return Hit(module=NAME, source="bitcoinabuse.com", category="wallet",
                   url=url, status=classify_exception(e),
                   title=addr, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200:
        return Hit(module=NAME, source="bitcoinabuse.com", category="wallet",
                   url=url, status=classify_http(r.status_code),
                   title=addr, detail=f"HTTP {r.status_code}")
    try:
        data = r.json() or {}
    except Exception:
        return Hit(module=NAME, source="bitcoinabuse.com", category="wallet",
                   url=url, status=HitStatus.ERROR,
                   title=addr, detail="unparseable JSON")
    count = int(data.get("count", 0) or 0)
    if count <= 0:
        return Hit(module=NAME, source="bitcoinabuse.com", category="wallet",
                   url=url, status=HitStatus.NO_DATA,
                   title=addr, detail="no abuse reports")
    if count >= 10:
        sev = Severity.CRITICAL
    elif count >= 3:
        sev = Severity.HIGH
    else:
        sev = Severity.MEDIUM
    return Hit(
        module=NAME, source="bitcoinabuse.com", category="wallet",
        url=f"https://www.bitcoinabuse.com/reports/{addr}",
        status=HitStatus.FOUND, title=addr,
        detail=f"{count} abuse report(s)",
        extra={"abuse_reports": count, "last_seen": data.get("last_seen", "")},
        severity=sev,
        confidence=0.95,
        evidence={"abuse_reports": str(count)},
    )


async def _cryptoscamdb(addr: str) -> Hit:
    """CryptoScamDB. Host availability is verified via HEAD first; if the DB is
    down we emit UNAVAILABLE (NOT ERROR — it's external)."""
    base = "https://check.cryptoscamdb.org"
    url = f"{base}/?search={addr}"
    api = f"https://api.cryptoscamdb.org/v1/check/{addr}"
    try:
        client = await get_client()
        # quick reachability probe
        ping = await client.head(base, timeout=8.0, follow_redirects=True)
        if ping.status_code >= 500:
            return Hit(module=NAME, source="cryptoscamdb", category="wallet",
                       url=url, status=HitStatus.UNAVAILABLE,
                       title=addr, detail=f"site down (HEAD {ping.status_code})")
    except Exception as e:
        return Hit(module=NAME, source="cryptoscamdb", category="wallet",
                   url=url, status=HitStatus.UNAVAILABLE,
                   title=addr, detail=f"site unreachable: {type(e).__name__}")
    try:
        r = await client.get(api, timeout=_TIMEOUT,
                             headers={"Accept": "application/json"})
    except Exception as e:
        return Hit(module=NAME, source="cryptoscamdb", category="wallet",
                   url=url, status=classify_exception(e),
                   title=addr, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200:
        return Hit(module=NAME, source="cryptoscamdb", category="wallet",
                   url=url, status=classify_http(r.status_code),
                   title=addr, detail=f"HTTP {r.status_code}")
    try:
        data = r.json() or {}
    except Exception:
        return Hit(module=NAME, source="cryptoscamdb", category="wallet",
                   url=url, status=HitStatus.NO_DATA,
                   title=addr, detail="unparseable JSON (treated as clean)")
    success = data.get("success")
    result = data.get("result") or data.get("entries") or []
    if success is False or not result:
        return Hit(module=NAME, source="cryptoscamdb", category="wallet",
                   url=url, status=HitStatus.NO_DATA,
                   title=addr, detail="no scam-DB entry")
    n = len(result) if isinstance(result, list) else 1
    return Hit(
        module=NAME, source="cryptoscamdb", category="wallet",
        url=url, status=HitStatus.FOUND, title=addr,
        detail=f"{n} scam-DB entry/entries — likely scam wallet",
        severity=Severity.CRITICAL,
        confidence=0.95,
        extra={"entries": n},
        evidence={"entries": str(n)},
    )


# ---- main coroutine -------------------------------------------------------

async def run(query: Query) -> AsyncIterator[Hit]:
    addr = (query.value or "").strip()
    chain = detect_address(addr)
    if not chain:
        return

    found = 0
    n_abuse = 0
    n_scam = 0

    # 1. balance / activity
    if chain == "btc":
        h = await _blockchain_info(addr)
        yield h
        if h.status == HitStatus.FOUND:
            found += 1
        h = await _blockchair(addr, "bitcoin")
        yield h
        if h.status == HitStatus.FOUND:
            found += 1
    else:
        h = await _blockchair(addr, "ethereum")
        yield h
        if h.status == HitStatus.FOUND:
            found += 1

    # 2. abuse / scam DBs — only meaningful for BTC for now (the public DBs
    #    we use don't index ETH addresses).
    if chain == "btc":
        h = await _bitcoinabuse(addr)
        yield h
        if h.status == HitStatus.FOUND:
            n_abuse = int(h.extra.get("abuse_reports", 0) or 0)

    h = await _cryptoscamdb(addr)
    yield h
    if h.status == HitStatus.FOUND:
        n_scam = int(h.extra.get("entries", 0) or 0)

    # 3. summary
    if n_abuse + n_scam >= 5:
        sev = Severity.CRITICAL
    elif n_abuse + n_scam > 0:
        sev = Severity.HIGH
    else:
        sev = Severity.INFO
    yield Hit(
        module=NAME, source="summary", category="wallet",
        status=HitStatus.FOUND if found or n_abuse or n_scam else HitStatus.NO_DATA,
        title=addr,
        detail=f"chain={chain} sources_found={found} abuse_reports={n_abuse} "
               f"scam_entries={n_scam}",
        severity=sev,
        extra={"chain": chain, "sources_found": found,
               "abuse_reports": n_abuse, "scam_entries": n_scam},
        confidence=1.0,
    )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.WALLET], run)
