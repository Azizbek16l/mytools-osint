"""Hermetic tests for app/modules/wallet.py and the WALLET kind inference."""
from __future__ import annotations

import httpx

from app.core.infer import infer_kind
from app.core.types import HitStatus, QueryKind, Severity
from app.modules import wallet as wallet_mod

from .factories import make_query

BTC_ADDR = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
BTC_BECH = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
ETH_ADDR = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
# A real funded ETH address (the canonical "1 ETH = 1e18 wei" demo address).
ETH_FUNDED = "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae"


def _patch_client(monkeypatch, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(wallet_mod, "get_client", _fake_get_client, raising=False)


async def _consume(agen):
    return [h async for h in agen]


class TestInferenceAndDetection:
    def test_infer_btc_base58(self):
        assert infer_kind(BTC_ADDR) == QueryKind.WALLET

    def test_infer_btc_bech32(self):
        assert infer_kind(BTC_BECH) == QueryKind.WALLET

    def test_infer_eth(self):
        assert infer_kind(ETH_ADDR) == QueryKind.WALLET

    def test_detect_address_returns_chain(self):
        assert wallet_mod.detect_address(BTC_ADDR) == "btc"
        assert wallet_mod.detect_address(BTC_BECH) == "btc"
        assert wallet_mod.detect_address(ETH_ADDR) == "eth"
        assert wallet_mod.detect_address("garbage") is None
        assert wallet_mod.detect_address("") is None

    def test_non_wallet_input_handled_elsewhere(self):
        # The async no-op path is covered in TestWalletFailureModes below.
        # detect_address() is the synchronous gate.
        assert wallet_mod.detect_address("not-an-addr") is None


class TestWalletHappyPath:
    async def test_btc_full_flow_returns_balance_and_summary(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "blockchain.info/rawaddr" in url:
                return httpx.Response(200, json={
                    "final_balance": 12345678,  # 0.12345678 BTC
                    "n_tx": 3,
                    "txs": [{"time": 1_600_000_000}, {"time": 1_700_000_000}],
                })
            if "blockchair.com/bitcoin/dashboards" in url:
                return httpx.Response(200, json={
                    "data": {BTC_ADDR: {"address": {
                        "balance": 12345678,
                        "transaction_count": 3,
                        "first_seen_receiving": "2020-09-13T12:00:00Z",
                        "last_seen_spending": "2023-11-14T12:00:00Z",
                    }}}})
            if "bitcoinabuse.com" in url:
                return httpx.Response(200, json={"count": 0, "address": BTC_ADDR})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            wallet_mod.run(make_query(BTC_ADDR, kind=QueryKind.WALLET))
        )
        sources = {h.source for h in hits}
        assert "blockchain.info" in sources
        assert "blockchair/bitcoin" in sources
        assert "bitcoinabuse.com" in sources
        # cryptoscamdb (defunct host) was removed — must NOT be probed any more.
        assert "cryptoscamdb" not in sources
        assert "summary" in sources
        bc = next(h for h in hits if h.source == "blockchain.info")
        assert bc.status == HitStatus.FOUND
        assert "0.12345678" in bc.detail
        assert bc.severity == Severity.MEDIUM
        abuse = next(h for h in hits if h.source == "bitcoinabuse.com")
        assert abuse.status == HitStatus.NO_DATA
        summary = next(h for h in hits if h.source == "summary")
        assert summary.extra["chain"] == "btc"
        assert summary.extra["sources_found"] == 2  # blockchain.info + blockchair

    async def test_eth_funded_address_returns_balance_and_tx(self, monkeypatch):
        """ETH funded address → Blockscout balance + tx-count + first/last.

        Regression: the old Blockchair-ethereum path returned 0 findings for
        funded addresses because Blockchair's free tier 430-rate-limits with a
        200 + ``data:null`` body. ETH now goes through Blockscout's v2 API.
        """
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            # Blockscout address record (balance in wei) + counters (tx count).
            if "eth.blockscout.com/api/v2/addresses" in url and url.endswith("/counters"):
                return httpx.Response(200, json={"transactions_count": "3237"})
            if "eth.blockscout.com/api/v2/addresses" in url:
                return httpx.Response(200, json={
                    "coin_balance": "9774452322498812330011",  # ~9774.45 ETH (wei)
                    "is_contract": True,
                    "is_scam": False,
                    "ens_domain_name": None,
                })
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            wallet_mod.run(make_query(ETH_FUNDED, kind=QueryKind.WALLET))
        )
        sources = {h.source for h in hits}
        assert "blockscout/ethereum" in sources
        # Blockchair-ethereum must NOT be probed any more; no BTC sources for ETH.
        assert "blockchair/ethereum" not in sources
        assert "blockchain.info" not in sources
        assert "bitcoinabuse.com" not in sources
        eth = next(h for h in hits if h.source == "blockscout/ethereum")
        assert eth.status == HitStatus.FOUND
        assert eth.severity == Severity.MEDIUM        # funded → MEDIUM
        assert eth.extra["balance_eth"] > 9774.0
        assert eth.extra["n_tx"] == 3237
        assert "ETH balance=9774" in eth.detail
        assert "tx=3237" in eth.detail
        assert eth.confidence == 1.0
        summary = next(h for h in hits if h.source == "summary")
        assert summary.extra["chain"] == "eth"
        assert summary.extra["sources_found"] == 1

    async def test_eth_scam_flagged_is_critical(self, monkeypatch):
        """Blockscout's free is_scam flag drives a CRITICAL hit + summary bump."""
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if url.endswith("/counters"):
                return httpx.Response(200, json={"transactions_count": "12"})
            if "eth.blockscout.com/api/v2/addresses" in url:
                return httpx.Response(200, json={
                    "coin_balance": "0", "is_contract": False, "is_scam": True,
                })
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(wallet_mod.run(make_query(ETH_ADDR, kind=QueryKind.WALLET)))
        eth = next(h for h in hits if h.source == "blockscout/ethereum")
        assert eth.status == HitStatus.FOUND
        assert eth.severity == Severity.CRITICAL
        assert eth.extra["is_scam"] is True
        assert "is_scam" in eth.detail
        summary = next(h for h in hits if h.source == "summary")
        assert summary.extra["scam_entries"] == 1

    async def test_eth_never_used_address_is_no_data(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if url.endswith("/counters"):
                return httpx.Response(200, json={"transactions_count": "0"})
            if "eth.blockscout.com/api/v2/addresses" in url:
                return httpx.Response(200, json={
                    "coin_balance": "0", "is_contract": False, "is_scam": False,
                })
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(wallet_mod.run(make_query(ETH_ADDR, kind=QueryKind.WALLET)))
        eth = next(h for h in hits if h.source == "blockscout/ethereum")
        assert eth.status == HitStatus.NO_DATA

    async def test_blockchair_btc_ratelimit_200_with_null_data(self, monkeypatch):
        """Blockchair free-tier quota: HTTP 200 + data:null + context.code 430.

        Must surface as RATELIMITED, never as a false "not seen on chain"
        (NO_DATA) — that masking was the ETH-zero-findings root cause.
        """
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "blockchain.info" in url:
                return httpx.Response(200, json={"final_balance": 0, "n_tx": 0, "txs": []})
            if "blockchair.com/bitcoin/dashboards" in url:
                return httpx.Response(200, json={
                    "data": None,
                    "context": {"code": 430, "error": "temporary blacklisted"},
                })
            if "bitcoinabuse.com" in url:
                return httpx.Response(200, json={"count": 0})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(wallet_mod.run(make_query(BTC_ADDR, kind=QueryKind.WALLET)))
        bc = next(h for h in hits if h.source == "blockchair/bitcoin")
        assert bc.status == HitStatus.RATELIMITED
        assert "430" in bc.detail
        assert bc.status != HitStatus.NO_DATA

    async def test_zero_balance_is_low_severity(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "blockchain.info" in url:
                return httpx.Response(200, json={"final_balance": 0, "n_tx": 0, "txs": []})
            if "blockchair.com" in url:
                return httpx.Response(200, json={
                    "data": {BTC_ADDR: {"address": {
                        "balance": 0, "transaction_count": 0,
                        "first_seen_receiving": "", "last_seen_spending": "",
                    }}}})
            if "bitcoinabuse.com" in url:
                return httpx.Response(200, json={"count": 0})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            wallet_mod.run(make_query(BTC_ADDR, kind=QueryKind.WALLET))
        )
        bc = next(h for h in hits if h.source == "blockchain.info")
        assert bc.status == HitStatus.FOUND
        assert bc.severity == Severity.INFO  # zero balance = INFO
        assert bc.confidence == 0.85


class TestWalletFailureModes:
    async def test_5xx_classifies_as_unavailable(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            if "blockchain.info" in str(req.url):
                return httpx.Response(503)
            if "blockchair.com" in str(req.url):
                return httpx.Response(502)
            if "bitcoinabuse" in str(req.url):
                return httpx.Response(504)
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            wallet_mod.run(make_query(BTC_ADDR, kind=QueryKind.WALLET))
        )
        bc = next(h for h in hits if h.source == "blockchain.info")
        assert bc.status == HitStatus.UNAVAILABLE
        cb = next(h for h in hits if h.source == "blockchair/bitcoin")
        assert cb.status == HitStatus.UNAVAILABLE
        # never ERROR — upstream outage is not our bug
        assert all(h.status != HitStatus.ERROR for h in hits)

    async def test_abuse_reports_emit_critical(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "blockchain.info" in url:
                return httpx.Response(200, json={"final_balance": 0, "n_tx": 0, "txs": []})
            if "blockchair.com" in url:
                return httpx.Response(200, json={
                    "data": {BTC_ADDR: {"address": {
                        "balance": 0, "transaction_count": 0,
                        "first_seen_receiving": "", "last_seen_spending": "",
                    }}}})
            if "bitcoinabuse.com" in url:
                return httpx.Response(200, json={"count": 12})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            wallet_mod.run(make_query(BTC_ADDR, kind=QueryKind.WALLET))
        )
        abuse = next(h for h in hits if h.source == "bitcoinabuse.com")
        assert abuse.status == HitStatus.FOUND
        assert abuse.severity == Severity.CRITICAL  # >=10 reports → CRITICAL
        summary = next(h for h in hits if h.source == "summary")
        # 12 abuse reports ≥ 5 → CRITICAL summary
        assert summary.severity == Severity.CRITICAL

    async def test_non_wallet_value_skips_run(self, monkeypatch):
        _patch_client(monkeypatch, lambda r: httpx.Response(404))
        hits = await _consume(
            wallet_mod.run(make_query("not-a-wallet", kind=QueryKind.WALLET))
        )
        assert hits == []
