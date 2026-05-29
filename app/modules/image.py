"""Image EXIF + reverse-image-search pivots (C2).

Deliberately lightweight: no Pillow, no exifread, no local CV. We hand-roll a
tiny TIFF/IFD0/GPS parser that's enough to surface the high-signal fields
without dragging Pillow into base install.

Inputs:
  - URL  → fetched through the shared SSRF-guarded HTTP client (cap 25 MB)
  - PATH → read from local filesystem

Outputs (each its own Hit):
  - camera make/model
  - datetime / software / owner / artist
  - GPS lat/lon (decimal degrees) + OpenStreetMap pivot URL
  - one pivot Hit per reverse-image-search engine (Lens / Bing / Yandex / TinEye)
"""
from __future__ import annotations

import asyncio
import os
import struct
from collections.abc import AsyncIterator

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "image"

_MAX_BYTES = 25 * 1024 * 1024  # 25 MB hard cap on fetched payload

# IFD tag IDs we care about (TIFF spec + EXIF private IFD).
_IFD0_TAGS = {
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8769: "ExifIFDPointer",
    0x8825: "GPSInfoIFDPointer",
}
_GPS_TAGS = {
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
}

# Field-type sizes, per TIFF 6.0.
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _read_value(blob: bytes, ifd_off: int, entry_off: int,
                bo: str) -> tuple[int, int, int, bytes] | None:
    """Return (tag, ftype, count, raw_bytes) for one IFD entry, or None on bad data."""
    try:
        tag, ftype, count = struct.unpack_from(bo + "HHI", blob, entry_off)
    except struct.error:
        return None
    size = _TYPE_SIZE.get(ftype, 0)
    if size == 0:
        return None
    nbytes = size * count
    if nbytes <= 4:
        raw = blob[entry_off + 8:entry_off + 8 + nbytes]
    else:
        try:
            (val_off,) = struct.unpack_from(bo + "I", blob, entry_off + 8)
        except struct.error:
            return None
        # offsets are relative to the start of the TIFF header (== blob)
        start = ifd_off + val_off if False else val_off  # TIFF offsets are
        # actually relative to the start of the TIFF header which is `blob[0]`,
        # so val_off works directly as a slice index here.
        start = val_off
        if start + nbytes > len(blob):
            return None
        raw = blob[start:start + nbytes]
    return tag, ftype, count, raw


def _decode(ftype: int, raw: bytes, count: int, bo: str):
    if ftype == 2:  # ASCII
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()
    if ftype == 3:  # SHORT
        return list(struct.unpack(bo + ("H" * count), raw[:2 * count]))
    if ftype == 4:  # LONG
        return list(struct.unpack(bo + ("I" * count), raw[:4 * count]))
    if ftype == 5:  # RATIONAL
        vals = []
        for i in range(count):
            num, den = struct.unpack(bo + "II", raw[i * 8:i * 8 + 8])
            vals.append((num, den))
        return vals
    if ftype == 1:  # BYTE
        return list(raw[:count])
    return raw


def _walk_ifd(blob: bytes, ifd_off: int, bo: str,
              wanted: dict[int, str]) -> dict[str, object]:
    """Walk a single IFD and return {name: decoded_value} for tags in `wanted`."""
    out: dict[str, object] = {}
    if ifd_off + 2 > len(blob):
        return out
    try:
        (n_entries,) = struct.unpack_from(bo + "H", blob, ifd_off)
    except struct.error:
        return out
    for i in range(n_entries):
        entry_off = ifd_off + 2 + i * 12
        if entry_off + 12 > len(blob):
            break
        rec = _read_value(blob, ifd_off, entry_off, bo)
        if not rec:
            continue
        tag, ftype, count, raw = rec
        name = wanted.get(tag)
        if not name:
            continue
        try:
            out[name] = _decode(ftype, raw, count, bo)
        except Exception:  # noqa: S112 — malformed tag, skip silently
            continue
    return out


def _find_tiff(payload: bytes) -> tuple[bytes, int, str] | None:
    """Locate the TIFF header inside a JPEG (Exif APP1) or raw TIFF blob.

    Returns (tiff_blob, ifd0_offset, byte_order) — byte_order is the struct
    prefix '<' / '>'. None if no readable EXIF is found.
    """
    if payload[:2] == b"\xff\xd8":  # JPEG SOI
        # Scan markers for APP1 "Exif\0\0"
        i = 2
        while i < len(payload) - 4:
            if payload[i] != 0xFF:
                i += 1
                continue
            marker = payload[i + 1]
            if marker == 0xDA or marker == 0xD9:  # SOS or EOI: no more meta
                return None
            seg_len = int.from_bytes(payload[i + 2:i + 4], "big")
            if marker == 0xE1 and payload[i + 4:i + 10] == b"Exif\x00\x00":
                tiff = payload[i + 10:i + 2 + seg_len]
                break
            i += 2 + seg_len
        else:
            return None
    elif payload[:2] in (b"II", b"MM"):
        tiff = payload
    else:
        return None
    if len(tiff) < 8:
        return None
    bo = "<" if tiff[:2] == b"II" else ">"
    if struct.unpack_from(bo + "H", tiff, 2)[0] != 0x002A:
        return None
    (ifd0_off,) = struct.unpack_from(bo + "I", tiff, 4)
    return tiff, ifd0_off, bo


def _rational_to_float(rat) -> float:
    try:
        num, den = rat
        return float(num) / float(den) if den else 0.0
    except Exception:
        return 0.0


def _dms_to_deg(dms) -> float:
    """[(deg_num,deg_den),(min_num,min_den),(sec_num,sec_den)] → decimal degrees."""
    if not dms or len(dms) < 3:
        return 0.0
    d = _rational_to_float(dms[0])
    m = _rational_to_float(dms[1])
    s = _rational_to_float(dms[2])
    return d + m / 60.0 + s / 3600.0


def parse_exif(payload: bytes) -> dict[str, object]:
    """Best-effort extraction of common EXIF/IFD0/GPS fields.

    Returns a dict; missing fields are simply omitted. Bytes that don't look
    like EXIF return an empty dict (caller should emit NO_DATA gracefully).
    """
    located = _find_tiff(payload)
    if not located:
        return {}
    tiff, ifd0_off, bo = located
    out: dict[str, object] = {}
    ifd0 = _walk_ifd(tiff, ifd0_off, bo, _IFD0_TAGS)
    for k in ("Make", "Model", "Software", "DateTime", "Artist", "Copyright",
              "ImageDescription"):
        if k in ifd0:
            out[k] = ifd0[k]
    # GPS sub-IFD
    gps_ptr = ifd0.get("GPSInfoIFDPointer")
    gps_off = 0
    if isinstance(gps_ptr, list) and gps_ptr:
        try:
            gps_off = int(gps_ptr[0])
        except Exception:
            gps_off = 0
    if gps_off:
        gps = _walk_ifd(tiff, gps_off, bo, _GPS_TAGS)
        lat = _dms_to_deg(gps.get("GPSLatitude") or [])
        lon = _dms_to_deg(gps.get("GPSLongitude") or [])
        lat_ref = gps.get("GPSLatitudeRef") or ""
        lon_ref = gps.get("GPSLongitudeRef") or ""
        if isinstance(lat_ref, str) and lat_ref.upper().startswith("S"):
            lat = -lat
        if isinstance(lon_ref, str) and lon_ref.upper().startswith("W"):
            lon = -lon
        if lat or lon:
            out["GPSLatitude"] = round(lat, 7)
            out["GPSLongitude"] = round(lon, 7)
    return out


# ---- I/O ------------------------------------------------------------------

async def _fetch_url(url: str) -> tuple[bytes, str]:
    """Returns (payload, error). Empty payload + error str → fail."""
    try:
        client = await get_client()
        r = await client.get(url, timeout=30.0,
                             headers={"Accept": "image/*"})
    except Exception as e:
        return b"", f"{type(e).__name__}: {e}"
    if r.status_code != 200:
        return b"", f"HTTP {r.status_code}"
    ct = r.headers.get("content-type", "").lower()
    if ct and "image/" not in ct and ct != "application/octet-stream":
        return b"", f"unexpected content-type: {ct}"
    payload = r.content[:_MAX_BYTES]
    if len(r.content) > _MAX_BYTES:
        return payload, ""  # truncated but usable
    return payload, ""


def _reverse_pivots(source_url: str | None) -> list[tuple[str, str, str]]:
    """Return (engine, url, detail) tuples — one per reverse-image-search engine."""
    if source_url:
        return [
            ("Google Lens", f"https://lens.google.com/uploadbyurl?url={source_url}",
             "drop into Google Lens for reverse-image-search"),
            ("Bing Visual", f"https://www.bing.com/images/search?q=imgurl:{source_url}&view=detailv2&iss=sbi",
             "Bing Visual Search via image URL"),
            ("Yandex Images", f"https://yandex.com/images/search?rpt=imageview&url={source_url}",
             "Yandex Images reverse search"),
            ("TinEye", f"https://www.tineye.com/search?url={source_url}",
             "TinEye reverse search"),
        ]
    return [
        ("Google Lens", "https://lens.google.com",
         "drop the image file into https://lens.google.com (no public upload URL)"),
        ("Bing Visual", "https://www.bing.com/visualsearch",
         "drop the image file into Bing Visual Search"),
        ("Yandex Images", "https://yandex.com/images",
         "drop the image file into Yandex Images"),
        ("TinEye", "https://tineye.com",
         "drop the image file into TinEye"),
    ]


# ---- main coroutine -------------------------------------------------------

async def run(query: Query) -> AsyncIterator[Hit]:
    value = (query.value or "").strip()
    if not value:
        return

    is_url = value.lower().startswith(("http://", "https://"))
    payload = b""
    source_url: str | None = value if is_url else None

    if is_url:
        payload, err = await _fetch_url(value)
        if err:
            # Distinguish transport/upstream failure from our bug — both end
            # without payload, so no further parsing.
            status = (HitStatus.UNAVAILABLE if err.startswith("HTTP")
                      or "Timeout" in err or "Connect" in err
                      or "Network" in err else HitStatus.ERROR)
            if err.startswith("HTTP "):
                try:
                    code = int(err.split(" ", 1)[1])
                    status = classify_http(code)
                except ValueError:
                    pass
            elif err.startswith(("TimeoutError", "ConnectError", "NetworkError",
                                 "ReadError", "RemoteProtocolError")):
                status = classify_exception(Exception(err))
            yield Hit(module=NAME, source="fetch", category="image",
                      url=value, status=status, title=value, detail=err)
            return
    else:
        # Local filesystem — keep blocking I/O off the event loop.
        def _read_local(path: str) -> tuple[bool, bytes, str]:
            if not os.path.exists(path):
                return False, b"", "path does not exist"
            try:
                with open(path, "rb") as f:
                    return True, f.read(_MAX_BYTES), ""
            except Exception as e:
                return False, b"", f"{type(e).__name__}: {e}"

        ok, payload, err = await asyncio.to_thread(_read_local, value)
        if not ok:
            status = HitStatus.NO_DATA if "does not exist" in err else HitStatus.ERROR
            yield Hit(module=NAME, source="fetch", category="image",
                      status=status, title=value, detail=err)
            return

    if not payload:
        yield Hit(module=NAME, source="exif", category="image",
                  status=HitStatus.NO_DATA, title=value, detail="empty payload")
        return

    meta = parse_exif(payload)

    if not meta:
        yield Hit(module=NAME, source="exif", category="image",
                  status=HitStatus.NO_DATA, title=value,
                  detail="no readable EXIF (format unsupported or stripped)")
    else:
        # Emit one Hit per high-signal field.
        if meta.get("Make") or meta.get("Model"):
            yield Hit(
                module=NAME, source="camera", category="image",
                status=HitStatus.FOUND, title=value,
                detail=f"{meta.get('Make','?')} {meta.get('Model','?')}".strip(),
                severity=Severity.MEDIUM, confidence=0.95,
                extra={"Make": meta.get("Make"), "Model": meta.get("Model")},
                evidence={"Make": str(meta.get("Make", "")),
                          "Model": str(meta.get("Model", ""))},
            )
        if meta.get("DateTime"):
            yield Hit(
                module=NAME, source="datetime", category="image",
                status=HitStatus.FOUND, title=value,
                detail=f"captured {meta['DateTime']}",
                severity=Severity.LOW, confidence=0.9,
                extra={"DateTime": meta["DateTime"]},
            )
        if meta.get("Software"):
            yield Hit(
                module=NAME, source="software", category="image",
                status=HitStatus.FOUND, title=value,
                detail=f"software={meta['Software']}",
                severity=Severity.LOW, confidence=0.85,
                extra={"Software": meta["Software"]},
            )
        if meta.get("Artist") or meta.get("Copyright"):
            yield Hit(
                module=NAME, source="owner", category="image",
                status=HitStatus.FOUND, title=value,
                detail=f"artist={meta.get('Artist','')} copyright={meta.get('Copyright','')}".strip(),
                severity=Severity.MEDIUM, confidence=0.9,
                extra={"Artist": meta.get("Artist"),
                       "Copyright": meta.get("Copyright")},
            )
        lat = meta.get("GPSLatitude")
        lon = meta.get("GPSLongitude")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)) and (lat or lon):
            osm = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=15"
            yield Hit(
                module=NAME, source="gps", category="geo",
                status=HitStatus.FOUND, title=f"{lat:.6f}, {lon:.6f}",
                detail=f"lat={lat:.6f} lon={lon:.6f} — geo pivot",
                url=osm, severity=Severity.HIGH, confidence=0.98,
                extra={"lat": lat, "lon": lon, "osm": osm},
                evidence={"lat": f"{lat:.6f}", "lon": f"{lon:.6f}"},
            )

    # Always emit reverse-search pivots — these are how the analyst pivots
    # the image regardless of whether EXIF was readable.
    for engine, url, detail in _reverse_pivots(source_url):
        yield Hit(
            module=NAME, source=engine, category="pivot",
            status=HitStatus.UNCERTAIN, title=engine, detail=detail,
            url=url, severity=Severity.INFO, confidence=0.5,
        )


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.IMAGE], run)
