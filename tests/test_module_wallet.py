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
            if "cryptoscamdb.org" in url:
                if req.method == "HEAD":
                    return httpx.Response(200)
                return httpx.Response(200, json={"success": True, "result": []})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            wallet_mod.run(make_query(BTC_ADDR, kind=QueryKind.WALLET))
        )
        sources = {h.source for h in hits}
        assert "blockchain.info" in sources
        assert "blockchair/bitcoin" in sources
        assert "bitcoinabuse.com" in sources
        assert "cryptoscamdb" in sources
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

    async def test_eth_uses_blockchair_only(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "blockchair.com/ethereum/dashboards" in url:
                return httpx.Response(200, json={
                    "data": {ETH_ADDR: {"address": {
                        "balance": "1000000000000000000",  # 1 ETH (wei)
                        "transaction_count": 50,
                        "first_seen_receiving": "2018-01-02T00:00:00Z",
                        "last_seen_spending": "",
                    }}}})
            if "cryptoscamdb.org" in url:
                if req.method == "HEAD":
                    return httpx.Response(200)
                return httpx.Response(200, json={"success": True, "result": []})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            wallet_mod.run(make_query(ETH_ADDR, kind=QueryKind.WALLET))
        )
        sources = {h.source for h in hits}
        assert "blockchair/ethereum" in sources
        # No bitcoinabuse or blockchain.info for ETH
        assert "blockchain.info" not in sources
        assert "bitcoinabuse.com" not in sources
        bc = next(h for h in hits if h.source == "blockchair/ethereum")
        assert bc.status == HitStatus.FOUND
        assert "ETH balance=1.00000000" in bc.detail

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
            if "cryptoscamdb.org" in url:
                if req.method == "HEAD":
                    return httpx.Response(200)
                return httpx.Response(200, json={"success": True, "result": []})
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
            if "cryptoscamdb" in str(req.url):
                if req.method == "HEAD":
                    return httpx.Response(503)
                return httpx.Response(503)
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            wallet_mod.run(make_query(BTC_ADDR, kind=QueryKind.WALLET))
        )
        bc = next(h for h in hits if h.source == "blockchain.info")
        assert bc.status == HitStatus.UNAVAILABLE
        scam = next(h for h in hits if h.source == "cryptoscamdb")
        assert scam.status == HitStatus.UNAVAILABLE
        # never ERROR — upstream outage is not our bug
        assert all(h.status != HitStatus.ERROR for h in hits)

    async def test_scam_db_hit_emits_critical(self, monkeypatch):
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
            if "cryptoscamdb.org" in url:
                if req.method == "HEAD":
                    return httpx.Response(200)
                return httpx.Response(200, json={"success": True,
                                                  "result": [{"name": "Scam"}, {"name": "Phish"}]})
            return httpx.Response(404)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            wallet_mod.run(make_query(BTC_ADDR, kind=QueryKind.WALLET))
        )
        scam = next(h for h in hits if h.source == "cryptoscamdb")
        assert scam.status == HitStatus.FOUND
        assert scam.severity == Severity.CRITICAL
        abuse = next(h for h in hits if h.source == "bitcoinabuse.com")
        assert abuse.severity == Severity.CRITICAL  # >=10 reports → CRITICAL
        summary = next(h for h in hits if h.source == "summary")
        assert summary.severity == Severity.CRITICAL  # abuse + scam ≥ 5

    async def test_non_wallet_value_skips_run(self, monkeypatch):
        _patch_client(monkeypatch, lambda r: httpx.Response(404))
        hits = await _consume(
            wallet_mod.run(make_query("not-a-wallet", kind=QueryKind.WALLET))
        )
        assert hits == []
