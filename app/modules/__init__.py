"""OSINT modules. Each module registers one or more (kind → producer) entries with the Runner.

To register a module: implement a `register(runner)` callable and append it to MODULES.
"""
from __future__ import annotations

from app.core.runner import Runner

from . import adjacency as _adjacency
from . import asn_bgp as _asn_bgp
from . import business as _business
from . import certspotter as _certspotter
from . import cloud_buckets as _cloud_buckets
from . import discovery as _discovery
from . import domain as _domain
from . import dorks as _dorks
from . import email as _email
from . import email_extras as _email_extras
from . import email_security as _email_security
from . import favicon_hash as _favicon_hash
from . import github_leaks as _github_leaks
from . import hackertarget as _hackertarget
from . import hash_lookup as _hash_lookup
from . import hibp_passwords as _hibp_passwords
from . import http_headers as _http_headers
from . import image as _image
from . import internetdb as _internetdb
from . import ip as _ip
from . import ip_extras as _ip_extras
from . import leaks as _leaks
from . import malware_bazaar as _malware_bazaar
from . import passive_dns as _passive_dns
from . import patterns as _patterns
from . import pgp_keys as _pgp_keys
from . import phone as _phone
from . import port_scan as _port_scan
from . import ripestat as _ripestat
from . import route_discover as _route_discover
from . import ssl_tls as _ssl_tls
from . import subdomain_brute as _subdomain_brute
from . import subdomain_permute as _subdomain_permute
from . import subdomain_takeover as _subdomain_takeover
from . import takeover as _takeover
from . import tech_fingerprint as _tech_fingerprint
from . import telegram as _telegram
from . import threat_intel as _threat_intel
from . import tor_check as _tor_check
from . import typosquat as _typosquat
from . import username as _username
from . import waf_cms_graphql as _waf_cms_graphql
from . import wallet as _wallet
from . import wayback_urls as _wayback_urls
from . import web_hardening as _web_hardening
from . import web_recon as _web_recon
from . import well_known as _well_known
from . import whatsapp as _whatsapp

MODULES = [
    # core identity probes
    _username, _email, _email_extras, _phone, _telegram, _whatsapp,
    # network / domain
    _ip, _ip_extras, _domain, _discovery, _patterns, _adjacency,
    _ssl_tls, _http_headers, _asn_bgp, _tech_fingerprint,
    # red-team v0.2 additions (free sources)
    _internetdb, _threat_intel, _takeover, _web_recon,
    _email_security, _typosquat, _pgp_keys, _tor_check,
    # cyber-pro v0.3 additions
    _github_leaks, _cloud_buckets, _hibp_passwords, _malware_bazaar,
    # free, no-key hash reputation (works out of the box; complements
    # the key-gated malware_bazaar for QueryKind.HASH)
    _hash_lookup,
    _web_hardening, _well_known, _subdomain_brute, _passive_dns,
    # v4.1 active recon
    _route_discover, _subdomain_permute, _port_scan, _waf_cms_graphql,
    # v4.2 — free passive sources + favicon pivot + subdomain takeover
    _favicon_hash, _wayback_urls, _certspotter, _ripestat, _hackertarget,
    _subdomain_takeover,
    # Wave C — new data kinds (alphabetical)
    _business, _dorks, _image, _leaks, _wallet,
]


def register_all(r: Runner) -> None:
    for m in MODULES:
        m.register(r)
    # v4.0: also discover third-party plugins via entry-points
    try:
        from app.core.plugin_loader import register_with_runner
        register_with_runner(r)
    except Exception:
        # Loader is best-effort — never crash the host on plugin failures.
        pass
