"""Crypto / blockchain wallet recon (C1).

Free public explorers — NO API keys required:
  - blockchain.info        — BTC balance, tx count, first/last seen
  - api.blockchair.com     — BTC dashboard (balance, tx count, ages)
  - bitcoinabuse.com       — BTC scam-report aggregator (works anon for read)
  - eth.blockscout.com     — ETH balance, tx count, contract/ENS, is_scam flag

ETH note: Blockchair's free tier returns HTTP 200 with ``{"data": null,
"context":{"code":430,...}}`` once an unauthenticated IP exceeds its quota
(common on shared/laptop IPs). The old code read that as "address not seen on
chain", so funded ETH addresses silently returned 0 findings. We now use
Blockscout's public v2 API for ETH (no key, returns balance + tx-count via a
separate /counters endpoint, plus a free ``is_scam`` flag) and keep Blockchair
for BTC only.

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


async def _blockchair(addr: str, chain: str = "bitcoin") -> Hit:
    """Blockchair dashboard — BTC only.

    ETH moved to Blockscout (see ``_blockscout_eth``) because Blockchair's free
    tier 430-rate-limits unauthenticated IPs while still returning HTTP 200 +
    ``data: null`` — indistinguishable, at the HTTP layer, from a clean lookup.
    We detect that ``context.code`` here and surface it as RATELIMITED rather
    than silently reporting "not seen on chain".
    """
    url = f"https://api.blockchair.com/{chain}/dashboards/address/{addr}"
    sym = "BTC"
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
    # 200-with-error: free-tier quota exhaustion ("code":430) returns data:null.
    ctx_code = (data.get("context") or {}).get("code")
    if data.get("data") is None and ctx_code and int(ctx_code) >= 400:
        return Hit(module=NAME, source=f"blockchair/{chain}", category="wallet",
                   url=url, status=HitStatus.RATELIMITED, title=addr,
                   detail=f"blockchair quota (code {ctx_code}) — set an API key to enable")
    # Blockchair lowercases neither BTC (case-sensitive) addrs nor the data key;
    # match the address case-insensitively to be safe.
    bucket = data.get("data") or {}
    payload = bucket.get(addr) or bucket.get(addr.lower()) or {}
    info = payload.get("address") or {}
    if not info:
        return Hit(module=NAME, source=f"blockchair/{chain}", category="wallet",
                   url=url, status=HitStatus.NO_DATA,
                   title=addr, detail="address not seen on chain")
    bal = _btc_amount(info.get("balance"))
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


async def _blockscout_eth(addr: str) -> Hit:
    """ETH balance + activity via Blockscout's public v2 API (free, no key).

    Two calls: the address record (``coin_balance`` in wei, ``is_scam``,
    ``is_contract``, ``ens_domain_name``) plus a ``/counters`` call for the
    transaction count. Blockscout returns HTTP 200 even for never-used
    addresses (balance "0", tx_count "0") — we map that to NO_DATA. A genuine
    404 (and 5xx/timeout) is classified the usual way.
    """
    base = "https://eth.blockscout.com/api/v2/addresses"
    url = f"{base}/{addr}"
    explorer = f"https://eth.blockscout.com/address/{addr}"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT,
                             headers={"Accept": "application/json"})
    except Exception as e:
        return Hit(module=NAME, source="blockscout/ethereum", category="wallet",
                   url=explorer, status=classify_exception(e),
                   title=addr, detail=f"{type(e).__name__}: {e}")
    if r.status_code != 200:
        # 404 = address not indexed (no activity) → NO_DATA via classify_http.
        return Hit(module=NAME, source="blockscout/ethereum", category="wallet",
                   url=explorer, status=classify_http(r.status_code),
                   title=addr, detail=f"HTTP {r.status_code}")
    try:
        data = r.json() or {}
    except Exception:
        return Hit(module=NAME, source="blockscout/ethereum", category="wallet",
                   url=explorer, status=HitStatus.ERROR,
                   title=addr, detail="unparseable JSON")
    try:
        bal_eth = int(data.get("coin_balance") or 0) / 1e18
    except (TypeError, ValueError):
        bal_eth = 0.0

    # Transaction count lives on a separate counters endpoint.
    n_tx = 0
    try:
        rc = await client.get(f"{base}/{addr}/counters", timeout=_TIMEOUT,
                              headers={"Accept": "application/json"})
        if rc.status_code == 200:
            n_tx = int((rc.json() or {}).get("transactions_count") or 0)
    except Exception:
        n_tx = 0

    is_contract = bool(data.get("is_contract"))
    is_scam = bool(data.get("is_scam"))
    ens = data.get("ens_domain_name") or ""

    # Never-used address: 200 but no balance and no transactions.
    if bal_eth == 0 and n_tx == 0 and not is_contract:
        return Hit(module=NAME, source="blockscout/ethereum", category="wallet",
                   url=explorer, status=HitStatus.NO_DATA,
                   title=addr, detail="address not seen on chain")

    kind = "contract" if is_contract else "EOA"
    detail = f"ETH balance={bal_eth:.8f} tx={n_tx} ({kind})"
    if ens:
        detail += f" ens={ens}"
    if is_scam:
        detail += " ⚠ flagged is_scam"
    extra: dict[str, Any] = {
        "balance_eth": bal_eth, "n_tx": n_tx,
        "is_contract": is_contract, "is_scam": is_scam,
    }
    if ens:
        extra["ens"] = ens
    if is_scam:
        sev = Severity.CRITICAL
    elif bal_eth > 0:
        sev = Severity.MEDIUM
    else:
        sev = Severity.INFO
    evidence = {"chain": "ethereum", "balance": f"{bal_eth:.8f}",
                "n_tx": str(n_tx), "is_scam": "true" if is_scam else "false"}
    return Hit(
        module=NAME, source="blockscout/ethereum", category="wallet",
        url=explorer, status=HitStatus.FOUND, title=addr,
        detail=detail, extra=extra, severity=sev,
        confidence=1.0 if (bal_eth > 0 or n_tx > 0) else 0.85,
        evidence=evidence,
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
        # ETH: Blockscout carries balance + tx-count + a free is_scam flag.
        h = await _blockscout_eth(addr)
        yield h
        if h.status == HitStatus.FOUND:
            found += 1
            if h.extra.get("is_scam"):
                n_scam += 1

    # 2. abuse DB — only BTC is indexed by the free public source we use.
    if chain == "btc":
        h = await _bitcoinabuse(addr)
        yield h
        if h.status == HitStatus.FOUND:
            n_abuse = int(h.extra.get("abuse_reports", 0) or 0)

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
