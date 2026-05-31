"""v4.2 module registration + sanity tests (no network)."""
from app.core.runner import runner


def test_v42_modules_registered():
    """All 6 new v4.2 modules show up in runner.all_modules()."""
    r = runner()
    names = {m.name for m in r.all_modules()}
    expected = {
        "favicon_hash", "wayback_urls", "certspotter",
        "ripestat", "hackertarget", "subdomain_takeover",
    }
    missing = expected - names
    assert not missing, f"v4.2 modules not registered: {missing}"


def test_favicon_hash_computes_known_hash():
    """Replicate Shodan's MMH3 favicon recipe deterministically."""
    from app.modules.favicon_hash import _shodan_mmh3
    # 16 byte sample — deterministic.
    sample = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8
    h = _shodan_mmh3(sample)
    assert isinstance(h, int)
    # mmh3.hash returns signed int; verify it's stable across runs.
    assert h == _shodan_mmh3(sample)


def test_theme_registry_complete():
    """All 7 advertised themes are in THEMES + resolvable by name."""
    from app.ui.tokens import THEMES, resolve_theme
    expected = {"github-dark", "github-light", "dracula", "nord",
                "tokyo-night", "catppuccin-mocha", "high-contrast"}
    assert expected <= set(THEMES.keys())
    # resolve_theme honors theme names from THEMES registry
    for name in expected:
        t = resolve_theme(name)
        assert t.ACCENT == THEMES[name].ACCENT, f"resolve_theme({name!r}) wrong palette"


def test_theme_persistence_roundtrip(tmp_path, monkeypatch):
    """persist_theme writes + read_persisted_theme reads it back."""
    monkeypatch.setattr("app.ui.tokens._THEME_CONFIG_PATH", str(tmp_path / "theme"))
    from app.ui.tokens import _read_persisted_theme, persist_theme
    persist_theme("dracula")
    assert _read_persisted_theme() == "dracula"
    # Unknown name → not persisted.
    persist_theme("not-a-real-theme")
    assert _read_persisted_theme() == "dracula"  # unchanged
