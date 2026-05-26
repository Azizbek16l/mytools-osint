"""Module presets — let the user dial scope by intent instead of by module name.

A profile is just a set of module names plus an optional kind-filter.
The runner is set_enabled-toggled on the selected names before each query.

Profiles aren't mutually exclusive with module flags — the CLI's
`--profile` is applied first, then `--enable foo --disable bar` may
override individual modules.
"""
from __future__ import annotations

from app.core.runner import Runner

# A "Tier A" probe = always fast, always informative, never noisy.
_TIER_A = {
    "username", "email", "email_extras", "email_security", "phone",
    "telegram", "whatsapp", "ip", "ip_extras", "internetdb",
    "domain", "asn_bgp", "ssl_tls", "http_headers",
    "tech_fingerprint", "threat_intel", "tor_check", "pgp_keys",
    "well_known", "web_hardening",
}

# Anything that takes longer or generates many rows.
_TIER_B = {
    "discovery", "patterns", "adjacency", "takeover", "web_recon",
    "typosquat", "cloud_buckets", "subdomain_brute", "github_leaks",
    "malware_bazaar", "hibp_passwords",
    # v4.1 active recon (loud — Tier B)
    "route_discover", "subdomain_permute", "port_scan",
    "waf_detect", "cms_detect", "graphql_probe", "source_maps",
    # v4.2 — passive (wayback/certspotter/ripestat/hackertarget) + light active
    # (favicon_hash, subdomain_takeover). All free-API, low noise per call.
    "favicon_hash", "wayback_urls", "certspotter", "ripestat",
    "hackertarget", "subdomain_takeover",
}


PROFILES: dict[str, set[str]] = {
    # --- defaults ---
    "default": _TIER_A | _TIER_B,            # everything
    "all": _TIER_A | _TIER_B,                # alias

    # --- speed-vs-depth dial ---
    "quick": _TIER_A,
    "deep": _TIER_A | _TIER_B,

    # --- intent presets ---
    "person": {
        "username", "email", "email_extras", "phone", "telegram",
        "whatsapp", "patterns", "pgp_keys", "discovery", "github_leaks",
    },
    "domain-recon": {
        "domain", "ssl_tls", "http_headers", "tech_fingerprint",
        "asn_bgp", "email_security", "web_recon", "takeover",
        "typosquat", "threat_intel", "internetdb", "well_known",
        "web_hardening", "subdomain_brute",
        # v4.2 passive sources
        "certspotter", "wayback_urls", "ripestat", "hackertarget",
    },
    "red-team": {
        "domain", "ssl_tls", "http_headers", "tech_fingerprint",
        "asn_bgp", "email_security", "web_recon", "takeover",
        "typosquat", "threat_intel", "internetdb", "ip_extras",
        "tor_check", "patterns", "discovery", "adjacency",
        "well_known", "web_hardening", "github_leaks", "cloud_buckets",
        "subdomain_brute", "subdomain_permute",
        # v4.1 active recon
        "route_discover", "port_scan", "waf_detect", "cms_detect",
        "graphql_probe", "source_maps",
        # v4.2 active + passive recon
        "favicon_hash", "wayback_urls", "certspotter", "ripestat",
        "hackertarget", "subdomain_takeover",
    },
    "active-recon": {
        # v4.1 — just the active (loud) probes for a focused offensive scan
        "route_discover", "port_scan", "waf_detect", "cms_detect",
        "graphql_probe", "source_maps", "subdomain_brute", "subdomain_permute",
        # v4.2 — favicon pivot + takeover check
        "favicon_hash", "subdomain_takeover",
    },
    "blue-team": {
        # what would a defender want? exposed surface + reputation.
        "internetdb", "threat_intel", "tor_check", "email_security",
        "ip_extras", "ssl_tls", "http_headers", "takeover", "typosquat",
        "well_known", "web_hardening", "cloud_buckets",
    },
    "ioc": {
        # given a domain/IP/hash, is it known-bad? minimal noise.
        "threat_intel", "tor_check", "ip_extras", "internetdb",
        "malware_bazaar",
    },
    "creds": {
        # password / hash / username breach triage
        "hibp_passwords", "malware_bazaar", "email_extras",
    },
    "leak-hunt": {
        # find leaks of an org's data in public repos + buckets + waybacks
        "github_leaks", "cloud_buckets", "web_recon", "well_known",
    },
}


def apply_profile(runner: Runner, profile: str) -> tuple[set[str], set[str]]:
    """Enable only modules in the profile set; return (enabled, disabled)."""
    if profile not in PROFILES:
        raise ValueError(
            f"unknown profile {profile!r}; choose one of: {', '.join(sorted(PROFILES))}"
        )
    allowed = PROFILES[profile]
    enabled: set[str] = set()
    disabled: set[str] = set()
    for m in runner.all_modules():
        if m.name in allowed:
            runner.set_enabled(m.name, True)
            enabled.add(m.name)
        else:
            runner.set_enabled(m.name, False)
            disabled.add(m.name)
    return enabled, disabled


def list_profiles() -> list[tuple[str, int, list[str]]]:
    """Return [(name, module_count, sorted_module_list)] for display."""
    return [(name, len(mods), sorted(mods)) for name, mods in PROFILES.items()]
