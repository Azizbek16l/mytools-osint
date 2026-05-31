"""Hermetic tests for app/modules/image.py.

Builds a minimal Intel-byte-order TIFF blob inline (Make, Model, DateTime,
GPS) and wraps it in a JPEG APP1 segment so the module's EXIF locator finds
it the same way it would for a real photo.
"""
from __future__ import annotations

import struct
from pathlib import Path

import httpx

from app.core.infer import infer_kind
from app.core.types import HitStatus, QueryKind, Severity
from app.modules import image as image_mod

from .factories import make_query


def _patch_client(monkeypatch, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(image_mod, "get_client", _fake_get_client, raising=False)


async def _consume(agen):
    return [h async for h in agen]


# --------------------------------------------------------------------------- #
# EXIF fixture builder                                                         #
# --------------------------------------------------------------------------- #

def _build_tiff(make: bytes = b"Canon\x00",
                model: bytes = b"EOS 5D\x00",
                dt: bytes = b"2024:01:15 12:30:45\x00",
                with_gps: bool = True,
                lat_deg: int = 41, lat_min: int = 18, lat_sec: int = 30,
                lon_deg: int = 69, lon_min: int = 14, lon_sec: int = 15,
                lat_ref: bytes = b"N\x00", lon_ref: bytes = b"E\x00") -> bytes:
    """Hand-roll a tiny TIFF with IFD0 (Make/Model/DateTime, optional GPS ptr)
    + optional GPS IFD with lat/lon rationals.

    Layout (offsets relative to the TIFF header start):
      0   : "II*\0" + IFD0 offset (8)
      8   : IFD0
      ... : value/string blobs
    """
    out = bytearray()
    # TIFF header
    out += b"II"
    out += struct.pack("<H", 0x002A)
    out += struct.pack("<I", 8)  # IFD0 starts at offset 8

    # Plan: write IFD0 with N entries, point GPS to an IFD later in the blob.
    # We need to know offsets ahead. We'll precompute lengths.
    n_ifd0 = 4 if with_gps else 3
    ifd0_size = 2 + n_ifd0 * 12 + 4  # n_entries + entries + next-ifd ptr
    ifd0_start = 8
    after_ifd0 = ifd0_start + ifd0_size
    # Inline strings (length > 4 → stored after IFD0)
    make_off = after_ifd0
    after_make = make_off + len(make)
    model_off = after_make
    after_model = model_off + len(model)
    dt_off = after_model
    after_dt = dt_off + len(dt)
    # GPS IFD (if any)
    gps_ifd_off = after_dt if with_gps else 0
    gps_n = 4
    gps_size = 2 + gps_n * 12 + 4 if with_gps else 0
    after_gps_ifd = gps_ifd_off + gps_size if with_gps else after_dt
    # GPS rationals (3 rationals each = 24 bytes)
    lat_off = after_gps_ifd
    lon_off = lat_off + 24 if with_gps else 0
    # We don't store separate refs since they're 2 bytes (fits inline)

    # --- IFD0 ---
    out += struct.pack("<H", n_ifd0)
    # Make (tag 0x010F, ASCII type 2)
    out += struct.pack("<HHI", 0x010F, 2, len(make))
    out += struct.pack("<I", make_off)
    # Model
    out += struct.pack("<HHI", 0x0110, 2, len(model))
    out += struct.pack("<I", model_off)
    # DateTime
    out += struct.pack("<HHI", 0x0132, 2, len(dt))
    out += struct.pack("<I", dt_off)
    if with_gps:
        # GPSInfoIFDPointer (LONG type 4, count 1)
        out += struct.pack("<HHI", 0x8825, 4, 1)
        out += struct.pack("<I", gps_ifd_off)
    out += struct.pack("<I", 0)  # next-IFD ptr (none)
    # value blobs
    out += make + model + dt
    # GPS IFD
    if with_gps:
        out += struct.pack("<H", gps_n)
        # GPSLatitudeRef (ASCII 2 chars) — fits inline (count 2 < 4)
        out += struct.pack("<HHI", 0x0001, 2, len(lat_ref))
        out += lat_ref + b"\x00\x00"  # pad to 4 bytes
        # GPSLatitude (RATIONAL count 3 → 24 bytes, stored externally)
        out += struct.pack("<HHI", 0x0002, 5, 3)
        out += struct.pack("<I", lat_off)
        # GPSLongitudeRef
        out += struct.pack("<HHI", 0x0003, 2, len(lon_ref))
        out += lon_ref + b"\x00\x00"
        # GPSLongitude
        out += struct.pack("<HHI", 0x0004, 5, 3)
        out += struct.pack("<I", lon_off)
        out += struct.pack("<I", 0)  # next IFD = 0
        # lat/lon rationals (num, den per component)
        out += struct.pack("<IIIIII", lat_deg, 1, lat_min, 1, lat_sec, 1)
        out += struct.pack("<IIIIII", lon_deg, 1, lon_min, 1, lon_sec, 1)
    return bytes(out)


def _build_jpeg_with_exif(tiff: bytes) -> bytes:
    """Wrap TIFF blob in a minimal JPEG APP1 (Exif) segment + SOI/EOI."""
    payload = b"Exif\x00\x00" + tiff
    seg_len = len(payload) + 2
    return (b"\xff\xd8"          # SOI
            + b"\xff\xe1"        # APP1
            + struct.pack(">H", seg_len)
            + payload
            + b"\xff\xd9")       # EOI


# --------------------------------------------------------------------------- #
# Tests                                                                         #
# --------------------------------------------------------------------------- #

class TestInference:
    def test_jpg_url_detected_as_image(self):
        assert infer_kind("https://example.com/photo.jpg") == QueryKind.IMAGE
        assert infer_kind("http://example.com/x.PNG?cb=1") == QueryKind.IMAGE
        assert infer_kind("https://example.com/x.heic") == QueryKind.IMAGE

    def test_abs_path_detected_as_image(self):
        assert infer_kind("/tmp/photo.jpg") == QueryKind.IMAGE
        assert infer_kind("/var/img/x.tiff") == QueryKind.IMAGE
        assert infer_kind("C:/Users/foo/x.png") == QueryKind.IMAGE

    def test_non_image_value_not_classified(self):
        assert infer_kind("https://example.com/page.html") != QueryKind.IMAGE
        assert infer_kind("notanimage") != QueryKind.IMAGE  # no image extension

    def test_relative_image_filename_is_image(self):
        # Canonical inference (WP-D / finding #18): a bare filename ending in an
        # image extension routes to the IMAGE module, not DOMAIN. The image
        # module then handles a missing file gracefully (regular-file check).
        assert infer_kind("not_a_path.jpg") == QueryKind.IMAGE


class TestParser:
    def test_parses_make_model_datetime(self):
        tiff = _build_tiff(with_gps=False)
        meta = image_mod.parse_exif(tiff)
        assert meta["Make"].startswith("Canon")
        assert meta["Model"].startswith("EOS")
        assert "2024:01:15" in meta["DateTime"]
        assert "GPSLatitude" not in meta  # disabled

    def test_parses_gps_to_decimal_degrees(self):
        # 41°18'30" N = 41.308333
        tiff = _build_tiff(with_gps=True)
        meta = image_mod.parse_exif(tiff)
        assert "GPSLatitude" in meta
        assert "GPSLongitude" in meta
        assert abs(meta["GPSLatitude"] - (41 + 18/60 + 30/3600)) < 1e-4
        assert abs(meta["GPSLongitude"] - (69 + 14/60 + 15/3600)) < 1e-4

    def test_gps_south_west_flips_sign(self):
        tiff = _build_tiff(with_gps=True, lat_ref=b"S\x00", lon_ref=b"W\x00")
        meta = image_mod.parse_exif(tiff)
        assert meta["GPSLatitude"] < 0
        assert meta["GPSLongitude"] < 0

    def test_jpeg_app1_wrapper_parsed(self):
        blob = _build_jpeg_with_exif(_build_tiff(with_gps=True))
        meta = image_mod.parse_exif(blob)
        assert meta.get("Make", "").startswith("Canon")
        assert "GPSLatitude" in meta

    def test_unsupported_payload_returns_empty(self):
        # PNG signature, no EXIF — should return {}
        assert image_mod.parse_exif(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100) == {}
        assert image_mod.parse_exif(b"random bytes") == {}


class TestRunURL:
    async def test_url_fetch_emits_exif_gps_and_reverse_pivots(self, monkeypatch):
        blob = _build_jpeg_with_exif(_build_tiff(with_gps=True))

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=blob,
                                   headers={"content-type": "image/jpeg"})

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            image_mod.run(make_query("https://example.com/x.jpg", kind=QueryKind.IMAGE))
        )
        sources = {h.source for h in hits}
        assert "camera" in sources
        assert "datetime" in sources
        assert "gps" in sources
        # All four reverse-image-search engines as pivots
        for engine in ("Google Lens", "Bing Visual", "Yandex Images", "TinEye"):
            assert engine in sources
        gps = next(h for h in hits if h.source == "gps")
        assert gps.severity == Severity.HIGH
        assert "openstreetmap.org" in gps.url
        lens = next(h for h in hits if h.source == "Google Lens")
        assert "lens.google.com" in lens.url
        # WP-C: source URL is percent-encoded before embedding in the pivot.
        from urllib.parse import quote
        assert quote("https://example.com/x.jpg", safe="") in lens.url

    async def test_url_unreachable_emits_unavailable(self, monkeypatch):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(503)

        _patch_client(monkeypatch, handler)
        hits = await _consume(
            image_mod.run(make_query("https://example.com/x.jpg", kind=QueryKind.IMAGE))
        )
        fetch = next(h for h in hits if h.source == "fetch")
        assert fetch.status == HitStatus.UNAVAILABLE


class TestRunFile:
    async def test_local_path_with_exif(self, monkeypatch, tmp_path: Path):
        p = tmp_path / "sample.jpg"
        p.write_bytes(_build_jpeg_with_exif(_build_tiff(with_gps=True)))
        _patch_client(monkeypatch, lambda r: httpx.Response(404))
        hits = await _consume(
            image_mod.run(make_query(str(p), kind=QueryKind.IMAGE))
        )
        gps = next(h for h in hits if h.source == "gps")
        assert "openstreetmap.org" in gps.url
        # File path → engines emit no source_url, so URL stays the base host
        lens = next(h for h in hits if h.source == "Google Lens")
        assert lens.url == "https://lens.google.com"

    async def test_local_path_no_exif_returns_no_data(self, monkeypatch, tmp_path: Path):
        p = tmp_path / "bare.png"
        p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        _patch_client(monkeypatch, lambda r: httpx.Response(404))
        hits = await _consume(
            image_mod.run(make_query(str(p), kind=QueryKind.IMAGE))
        )
        exif = next(h for h in hits if h.source == "exif")
        assert exif.status == HitStatus.NO_DATA
        # Pivots still emitted
        assert any(h.source == "TinEye" for h in hits)

    async def test_missing_path_no_data(self, monkeypatch):
        _patch_client(monkeypatch, lambda r: httpx.Response(404))
        hits = await _consume(
            image_mod.run(make_query("/nonexistent/abc.jpg", kind=QueryKind.IMAGE))
        )
        assert any(h.status == HitStatus.NO_DATA for h in hits)
