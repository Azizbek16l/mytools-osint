"""Query-kind inference logic. Pure CPU, no Qt, no network."""
from __future__ import annotations

import pytest

from app.core.infer import infer_kind
from app.core.types import QueryKind
from app.modules.base import clean_email, clean_phone, clean_username


@pytest.mark.parametrize(
    "value, expected",
    [
        ("john@example.com", QueryKind.EMAIL),
        ("john.doe+tag@sub.example.co.uk", QueryKind.EMAIL),
        ("+998901234567", QueryKind.PHONE),
        ("998901234567", QueryKind.PHONE),
        ("+1 (415) 555-0102", QueryKind.PHONE),
        ("@durov", QueryKind.USERNAME),
        ("torvalds", QueryKind.USERNAME),
        ("github.com", QueryKind.DOMAIN),
        ("", None),
    ],
)
def test_infer_kind(value, expected):
    assert infer_kind(value) == expected


# --- WALLET ----------------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",          # BTC base58 (genesis)
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",          # BTC base58 (P2SH)
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",  # BTC bech32
        "0x52908400098527886E0F7030069857D2E4169EE7",  # ETH address (40 hex)
        "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",  # ETH address lowercase
    ],
)
def test_infer_kind_wallet(value):
    assert infer_kind(value) == QueryKind.WALLET


# --- IMAGE -----------------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/photo.jpg",     # http url
        "http://example.com/x.PNG?cb=1",     # query string + uppercase ext
        "/tmp/photo.jpg",                    # absolute POSIX path
        "/var/img/x.tiff",                   # absolute, alt ext
        "C:/Users/foo/x.png",                # windows drive path
        "photo.jpg",                         # RELATIVE bare filename — the regression
        "vacation.heic",                     # relative, heic
        "screenshot.jpeg",                   # relative, jpeg
    ],
)
def test_infer_kind_image(value):
    assert infer_kind(value) == QueryKind.IMAGE


def test_infer_kind_relative_image_not_domain():
    """Lock the fix: a relative image path must NOT be classified DOMAIN
    (which would route it to domain-recon instead of the image module)."""
    assert infer_kind("photo.jpg") == QueryKind.IMAGE
    assert infer_kind("a.tiff") == QueryKind.IMAGE


# --- IP --------------------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    [
        "1.2.3.4",            # IPv4
        "203.0.113.5",        # IPv4 (TEST-NET-3)
        "2001:db8::1",        # IPv6
        "::1",                # IPv6 loopback
        "10.0.0.0/24",        # IPv4 CIDR
        "2001:db8::/32",      # IPv6 CIDR
    ],
)
def test_infer_kind_ip(value):
    assert infer_kind(value) == QueryKind.IP


# --- HASH ------------------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    [
        "d41d8cd98f00b204e9800998ecf8427e",                                  # md5 (32)
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",                          # sha1 (40)
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256 (64)
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",  # sha512 (128)
    ],
)
def test_infer_kind_hash(value):
    assert infer_kind(value) == QueryKind.HASH


def test_eth_address_is_wallet_not_username_or_hash():
    """An ETH 0x… address is 42 chars (0x + 40 hex). It must route to WALLET,
    NOT USERNAME (the 1000-site probe blast) and NOT HASH."""
    eth = "0x52908400098527886E0F7030069857D2E4169EE7"
    assert infer_kind(eth) == QueryKind.WALLET


@pytest.mark.parametrize(
    "value",
    [
        "abc",                 # 3 chars — too short for a hash / wallet
        "deadbeef",            # 8 hex — not a recognised hash length
        "a1b2c3",              # short, stays username
        "john_doe",            # plain handle
    ],
)
def test_short_values_stay_username(value):
    """Short hex / handles must not be mis-promoted to HASH or WALLET."""
    assert infer_kind(value) == QueryKind.USERNAME


def test_clean_username():
    assert clean_username("  @durov ") == "durov"
    assert clean_username("torvalds") == "torvalds"


def test_clean_email():
    assert clean_email(" John@Example.COM ") == "john@example.com"


def test_clean_phone():
    assert clean_phone("+998 90 123 45 67") == "+998901234567"
    assert clean_phone("(415) 555-0102") == "4155550102"
    assert clean_phone("+1-415-555-0102") == "+14155550102"
