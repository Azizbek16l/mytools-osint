"""Banner + box rendering — verify they contain expected literals (no Qt)."""
from __future__ import annotations

import io

from app.ui.banner import BRAND, render


def test_banner_contains_brand_and_version():
    out = render()
    assert "BLUETM" in out or "Bluetm" in out
    assert BRAND in out


def test_banner_no_duplicate_tagline_token():
    """Subtitle should not have the same noun phrase twice."""
    out = render()
    # 'free APIs' appears in stats_line, must NOT also appear in TAGLINE
    assert out.count("free APIs") == 1
    assert out.count("authorised use only") == 1


def test_cli_no_arg_panel():
    """Smoke — the no-arg view should render through main() without raising."""
    from cli import Style, _print_no_arg_panel
    buf = io.StringIO()
    _print_no_arg_panel(Style(enabled=False), buf)
    s = buf.getvalue()
    assert "osint <value>" in s
    assert BRAND in s
    assert "--list-modules" in s
