"""Regression guards for the public landing + docs pages (docs/*.html).

These are static-HTML invariants that drift silently when the product moves
(version bumps, module-count changes, copy that outlives a removed feature).
WP-A fixed a batch of them; this test stops them from regressing.

No network, no heavy deps — pure file reads + stdlib html.parser.
"""
from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[1] / "docs"
INDEX = DOCS / "index.html"
DOCSPAGE = DOCS / "docs.html"

# Source-of-truth values for the current release.
EXPECTED_VERSION = "v4.3.2"
EXPECTED_MODULE_COUNT = 47
STALE_VERSION = "v4.2.2"

VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


class _WellFormed(HTMLParser):
    """Minimal balance checker: every non-void open tag must close."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, attrs: object) -> None:
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID:
            return
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
            return
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i] == tag:
                self.errors.append(
                    f"</{tag}> closes over unclosed {self.stack[i + 1:]}"
                )
                del self.stack[i:]
                return
        self.errors.append(f"</{tag}> has no opener")


@pytest.fixture(scope="module")
def index_html() -> str:
    return _read(INDEX)


@pytest.fixture(scope="module")
def docs_html() -> str:
    return _read(DOCSPAGE)


@pytest.mark.parametrize("page", [INDEX, DOCSPAGE], ids=["index", "docs"])
def test_html_is_well_formed(page: Path) -> None:
    parser = _WellFormed()
    parser.feed(_read(page))
    parser.close()
    assert not parser.errors, f"{page.name}: {parser.errors}"
    assert not parser.stack, f"{page.name}: unclosed tags {parser.stack}"


@pytest.mark.parametrize("page", [INDEX, DOCSPAGE], ids=["index", "docs"])
def test_no_stale_version(page: Path) -> None:
    html = _read(page)
    # The only allowed v4.2.2 mentions in docs are the historical socksio note
    # (one prose line + one explanatory HTML comment) — both deliberate.
    if page is DOCSPAGE:
        assert html.count(STALE_VERSION) <= 2, "unexpected extra v4.2.2 refs"
    else:
        assert STALE_VERSION not in html
    assert EXPECTED_VERSION in html


@pytest.mark.parametrize("page", [INDEX, DOCSPAGE], ids=["index", "docs"])
def test_module_count_is_current(page: Path) -> None:
    html = _read(page)
    assert "45 modul" not in html, "stale '45 modules' copy"
    assert str(EXPECTED_MODULE_COUNT) in html


def test_index_drops_single_fire_shell_copy(index_html: str) -> None:
    # v4.3 removed the menu-first single-fire shell; the hero must not sell it.
    assert "Single-fire shell" not in index_html
    assert "Bir-tugma shell" not in index_html
    assert "chat shell" in index_html.lower()


def test_docs_quickstart_drops_single_fire_keys(docs_html: str) -> None:
    assert "press <code>l</code> for a new lookup" not in docs_html
    assert "persistent" in docs_html.lower()


@pytest.mark.parametrize("page", [INDEX, DOCSPAGE], ids=["index", "docs"])
def test_social_and_favicon_meta(page: Path) -> None:
    html = _read(page)
    assert 'rel="canonical"' in html
    assert "https://cyber.bluetm.uz/" in html
    assert 'property="og:image"' in html
    assert "og-image.svg" in html
    assert 'name="twitter:card"' in html
    assert 'rel="icon"' in html
    assert "favicon.svg" in html


def test_asset_files_exist_and_parse() -> None:
    import xml.dom.minidom as minidom

    for name in ("favicon.svg", "og-image.svg"):
        f = DOCS / name
        assert f.exists(), f"missing {name}"
        minidom.parseString(f.read_text(encoding="utf-8"))  # raises on bad XML


@pytest.mark.parametrize("page", [INDEX, DOCSPAGE], ids=["index", "docs"])
def test_reduced_motion_guard_present(page: Path) -> None:
    assert "prefers-reduced-motion" in _read(page)


def test_index_aria_hygiene(index_html: str) -> None:
    # Decorative logo SVG + emoji must be hidden from the a11y tree.
    assert 'aria-hidden="true" focusable="false"' in index_html
    # Every feature emoji card wraps the glyph in aria-hidden.
    assert index_html.count('class="text-2xl mb-3" aria-hidden="true"') == 9
    # Icon-only/ambiguous external links get an accessible name.
    assert "github (opens in a new tab)" in index_html


def test_install_tablist_is_keyboard_operable(index_html: str) -> None:
    assert 'role="tabpanel"' in index_html
    assert "aria-controls=" in index_html
    assert "aria-labelledby=" in index_html
    assert 'tabindex="-1"' in index_html  # roving tabindex
    assert "ArrowRight" in index_html and "keydown" in index_html


def test_footer_has_no_unbreakable_ascii_rule(index_html: str) -> None:
    # The literal 36-char box-drawing rule caused mobile horizontal overflow.
    assert "────────────────────────────────────" not in index_html


def test_uzbek_glyphs_use_modifier_letter(index_html: str) -> None:
    # UZ o'/g' must use U+02BB MODIFIER LETTER TURNED COMMA, not ASCII '.
    assert "ʻ" in index_html
    # No ASCII-apostrophe UZ words should remain in the lang="uz" copy.
    for bad in ("o'rnatish", "bo'yicha", "to'plam", "bog'liq"):
        assert bad not in index_html, f"ASCII-apostrophe UZ word left: {bad}"


def test_changelog_link_has_noopener(index_html: str) -> None:
    # The hero changelog link previously had target=_blank without rel=noopener.
    marker = "CHANGELOG.md"
    idx = index_html.find(marker)
    assert idx != -1
    snippet = index_html[idx - 200 : idx + 100]
    assert 'rel="noopener"' in snippet
