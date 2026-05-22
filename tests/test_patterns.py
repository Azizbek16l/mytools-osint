"""Pattern generators — pure CPU, no network."""
from __future__ import annotations

from app.modules.patterns import email_pattern_guesses, username_variations


def test_username_variations_for_compound_name():
    seeds = username_variations("azizbektopilboyev7")
    assert "azizbektopilboyev7" in seeds
    # camel-/digit-split splits "azizbektopilboyev" + "7"
    assert any("azizbektopilboyev" in s for s in seeds)


def test_username_variations_compound_dot():
    seeds = username_variations("john.doe")
    assert "john.doe" in seeds
    assert "john" in seeds
    assert "doe" in seeds
    assert "john_doe" in seeds or "johndoe" in seeds
    assert "doejohn" in seeds or "doe.john" in seeds
    # dedup
    assert len(seeds) == len(set(seeds))


def test_username_variations_short_input():
    seeds = username_variations("ab")
    # 'ab' alone (2 chars) is below the 3-char floor, but its suffixed forms qualify
    assert "ab" not in seeds
    # we still get suffixed variants
    assert all(len(s) >= 3 for s in seeds)
    assert all(s.startswith("ab") for s in seeds)


def test_username_variations_dedup():
    seeds = username_variations("alice.smith")
    assert len(seeds) == len(set(seeds))


def test_email_pattern_guesses_for_full_name():
    out = email_pattern_guesses("John Doe", "example.com")
    assert "john.doe@example.com" in out
    assert "j.doe@example.com" in out
    assert "doe.john@example.com" in out
    # all entries are well-formed
    assert all("@" in v and v.endswith("example.com") for v in out)


def test_email_pattern_guesses_no_lastname():
    out = email_pattern_guesses("Cher", "example.com")
    assert out == ["cher@example.com"]
