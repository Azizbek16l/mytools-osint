"""Lock-in regression: P0 + P1 security fixes from v4.2.0 security audit."""
import asyncio
import os
from unittest.mock import patch

from app.core.types import HitStatus, Query, QueryKind


def test_favicon_hash_uses_in_tree_mmh3_no_external_dep():
    """Module must import from web_recon, not from external `mmh3` package."""
    from app.modules import favicon_hash
    # Verify it doesn't try to import the external mmh3 at module level.
    assert "mmh3" not in [m for m in dir(favicon_hash) if not m.startswith("_")]
    # And the function works.
    h = favicon_hash._shodan_mmh3(b"hello world")
    assert isinstance(h, int)
    assert h == favicon_hash._shodan_mmh3(b"hello world")  # deterministic


def test_favicon_hash_refuses_private_ip():
    """SSRF guard — must refuse 192.168/10/127/169.254/100.64."""
    from app.modules.favicon_hash import _is_private_host
    for ip in ["192.168.1.1", "10.0.0.1", "127.0.0.1", "169.254.169.254",
               "::1", "fe80::1", "0.0.0.0", "224.0.0.1"]:
        assert _is_private_host(ip), f"{ip} should be flagged private"
    for ip in ["8.8.8.8", "1.1.1.1", "example.com", "github.com"]:
        assert not _is_private_host(ip), f"{ip} should be allowed"


def test_favicon_hash_respects_opsec_env():
    """OPSEC P0 — module MUST refuse on OSINT_OPSEC=1 (not the wrong OSINT_OPSEC_MODE)."""
    from app.modules.favicon_hash import _run
    async def collect(q):
        out = []
        async for h in _run(q):
            out.append(h)
        return out
    with patch.dict(os.environ, {"OSINT_OPSEC": "1"}, clear=False):
        # Make sure the per-module override is NOT set.
        os.environ.pop("OSINT_FAVICON_HASH_OVER_TOR", None)
        hits = asyncio.run(collect(Query(value="example.com", kind=QueryKind.DOMAIN)))
    assert len(hits) == 1
    assert hits[0].status == HitStatus.SKIPPED
    assert "opsec" in hits[0].title.lower()


def test_subdomain_takeover_respects_opsec_env():
    """OPSEC P0 — same fix for subdomain_takeover."""
    from app.modules.subdomain_takeover import _run
    async def collect(q):
        out = []
        async for h in _run(q):
            out.append(h)
        return out
    with patch.dict(os.environ, {"OSINT_OPSEC": "1"}, clear=False):
        os.environ.pop("OSINT_SUBDOMAIN_TAKEOVER_OVER_TOR", None)
        hits = asyncio.run(collect(Query(value="example.com", kind=QueryKind.DOMAIN)))
    assert len(hits) == 1
    assert hits[0].status == HitStatus.SKIPPED


def test_url_injection_protected_certspotter():
    """P1 — query.value with `&` must be url-quoted to prevent param injection."""
    # We don't make a real call; just inspect that quote() is used.
    import inspect

    from app.modules import certspotter
    src = inspect.getsource(certspotter._run)
    assert "quote(" in src, "certspotter must url-quote the domain"


def test_url_injection_protected_wayback():
    import inspect

    from app.modules import wayback_urls
    src = inspect.getsource(wayback_urls._run)
    assert "quote(" in src, "wayback_urls must url-quote the host pattern"


def test_url_injection_protected_hackertarget():
    import inspect

    from app.modules import hackertarget
    src = inspect.getsource(hackertarget._call)
    assert "quote(" in src, "hackertarget must url-quote resource"


def test_url_injection_protected_ripestat():
    import inspect

    from app.modules import ripestat
    src = inspect.getsource(ripestat._call)
    assert "quote(" in src, "ripestat must url-quote resource"


# ---- v4.2.1 polish regressions from UX audit ----------------------------

def test_command_palette_use_jk_keys_disabled():
    """Regression: questionary 2.1.1 crashes if use_search_filter + jk both on."""
    import inspect

    from app.ui import command_palette
    src = inspect.getsource(command_palette.open_palette)
    # Verify the workaround is in place — must be explicitly False.
    assert "use_jk_keys=False" in src, (
        "palette will crash: questionary rejects search-filter + jk-keys combo"
    )


def test_main_menu_label_casing_no_collision():
    """Regression: settings ('t') and theme ('T') must render different labels."""
    from app.ui.main_menu import _ENTRIES
    labels = [label for (_key, _act, label, _desc) in _ENTRIES]
    assert len(set(labels)) == len(labels), \
        f"main menu has duplicate labels — keys become indistinguishable: {labels}"


def test_no_splash_flag_in_argparse():
    """Regression: --no-splash was advertised but not declared."""
    import sys
    sys.argv = ["osint", "--no-splash", "--version"]
    from cli import _build_parser
    p = _build_parser()
    # Must not raise SystemExit on --no-splash.
    ns = p.parse_args(["--no-splash", "--version"])
    assert ns.no_splash is True


def test_theme_picker_default_uses_value_not_label():
    """v4.2.2 regression: questionary expects value (not label) for default=.
    Passing the label raises ValueError 'Invalid default value passed'.
    """
    import inspect

    from app.ui import interactive
    src = inspect.getsource(interactive._action_theme_picker)
    # The fixed form must pass current_name (which is in choice.value), not
    # default_label (the rendered string).
    assert "default=current_name" in src, "theme picker must pass value, not label"
    assert "default=default_label" not in src, "still passing label — crashes questionary"
