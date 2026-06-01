"""Hermetic tests for app/modules/hash_lookup.py (CIRCL hashlookup).

Drives the HTTP code paths only (httpx MockTransport). Three real CIRCL shapes:
known-malicious (200 + KnownMalicious), known-good (200, no KnownMalicious),
and unknown (404). Plus the sha512/non-hex skip path.
"""
from __future__ import annotations

import httpx

from app.core.types import HitStatus, QueryKind, Severity
from app.modules import hash_lookup as hl_mod

from .factories import make_query

# EICAR test file (genuinely flagged malicious by CIRCL — see live verification).
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
UNKNOWN_MD5 = "ffffffffffffffffffffffffffffffff"
SHA512 = "a" * 128


def _patch_client(monkeypatch, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(hl_mod, "get_client", _fake_get_client, raising=False)


async def _consume(agen):
    return [h async for h in agen]


class TestHashType:
    def test_path_for_lengths(self):
        assert hl_mod._hash_path(EICAR_MD5) == "md5"
        assert hl_mod._hash_path(SHA1) == "sha1"
        assert hl_mod._hash_path(SHA256) == "sha256"

    def test_sha512_and_garbage_have_no_path(self):
        assert hl_mod._hash_path(SHA512) is None
        assert hl_mod._hash_path("nothex") is None
        assert hl_mod._hash_path("") is None


class TestKnownMalicious:
    async def test_known_malicious_is_critical_found(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            assert f"/lookup/md5/{EICAR_MD5}" in str(req.url)
            return httpx.Response(200, json={
                "FileName": "eicar.com",
                "KnownMalicious": "malshare.com",
                "source": "RDS_2025.03.1_android.db",
                "hashlookup:trust": 100,
                "mimetype": "text/plain",
                "SHA-256": SHA256,
            })

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            hl_mod.run(make_query(EICAR_MD5, kind=QueryKind.HASH))
        )
        assert len(hits) == 1
        h = hits[0]
        assert h.source == "CIRCL hashlookup"
        assert h.status == HitStatus.FOUND
        assert h.severity == Severity.CRITICAL
        assert "malshare.com" in h.detail
        assert h.extra["known_malicious"] == "malshare.com"
        assert h.extra["hash_type"] == "md5"
        assert h.evidence["known_malicious"] == "malshare.com"

    async def test_known_malicious_list_value(self, monkeypatch):
        # CIRCL sometimes returns a list for KnownMalicious.
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "FileName": "x.bin",
                "KnownMalicious": ["malshare.com", "vxvault"],
            })

        _patch_client(monkeypatch, handler)
        hits = await _consume(hl_mod.run(make_query(SHA256, kind=QueryKind.HASH)))
        assert hits[0].status == HitStatus.FOUND
        assert hits[0].severity == Severity.CRITICAL
        assert "malshare.com" in hits[0].detail and "vxvault" in hits[0].detail


class TestKnownGood:
    async def test_known_but_not_malicious_is_info_found(self, monkeypatch):
        # An NSRL known-good file: 200 with metadata but no KnownMalicious key.
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "FileName": "kernel32.dll",
                "source": "NSRL",
                "hashlookup:trust": 55,
                "SHA-1": SHA1,
            })

        _patch_client(monkeypatch, handler)
        hits = await _consume(hl_mod.run(make_query(SHA1, kind=QueryKind.HASH)))
        assert len(hits) == 1
        h = hits[0]
        assert h.status == HitStatus.FOUND
        assert h.severity == Severity.INFO          # benign → INFO, not CRITICAL
        assert h.extra["known_malicious"] is False
        assert "kernel32.dll" in h.detail


class TestNoDataAndErrors:
    async def test_404_is_no_data_not_error(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"message": "Non existing MD5",
                                             "query": UNKNOWN_MD5})

        _patch_client(monkeypatch, handler)
        hits = await _consume(hl_mod.run(make_query(UNKNOWN_MD5, kind=QueryKind.HASH)))
        assert len(hits) == 1
        assert hits[0].status == HitStatus.NO_DATA
        assert hits[0].status != HitStatus.ERROR

    async def test_200_with_non_existing_body_is_no_data(self, monkeypatch):
        # Defensive: some deployments answer 200 with the "Non existing" body.
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"message": "Non existing MD5",
                                             "query": UNKNOWN_MD5})

        _patch_client(monkeypatch, handler)
        hits = await _consume(hl_mod.run(make_query(UNKNOWN_MD5, kind=QueryKind.HASH)))
        assert hits[0].status == HitStatus.NO_DATA

    async def test_5xx_is_unavailable(self, monkeypatch):
        _patch_client(monkeypatch, lambda r: httpx.Response(503))
        hits = await _consume(hl_mod.run(make_query(EICAR_MD5, kind=QueryKind.HASH)))
        assert hits[0].status == HitStatus.UNAVAILABLE   # upstream, not our bug

    async def test_transport_error_is_unavailable(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=req)

        _patch_client(monkeypatch, handler)
        hits = await _consume(hl_mod.run(make_query(EICAR_MD5, kind=QueryKind.HASH)))
        assert hits[0].status == HitStatus.UNAVAILABLE

    async def test_sha512_skips_cleanly(self, monkeypatch):
        # No network call should be made for sha512 (CIRCL has no endpoint).
        def handler(req: httpx.Request) -> httpx.Response:
            raise AssertionError("should not hit the network for sha512")

        _patch_client(monkeypatch, handler)
        hits = await _consume(hl_mod.run(make_query(SHA512, kind=QueryKind.HASH)))
        assert len(hits) == 1
        assert hits[0].status == HitStatus.SKIPPED

    async def test_non_hash_kind_is_noop(self, monkeypatch):
        _patch_client(monkeypatch, lambda r: httpx.Response(404))
        hits = await _consume(hl_mod.run(make_query("acme.com", kind=QueryKind.DOMAIN)))
        assert hits == []


class TestRegistration:
    def test_registered_for_hash_kind(self):
        from app.core.runner import Runner
        r = Runner()
        hl_mod.register(r)
        mods = r.modules_for(QueryKind.HASH)
        assert any(m.name == "hash_lookup" for m in mods)
