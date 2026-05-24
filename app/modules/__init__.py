"""OSINT modules. Each module registers one or more (kind → producer) entries with the Runner.

To register a module: implement a `register(runner)` callable and append it to MODULES.
"""
from __future__ import annotations

from app.core.runner import Runner

from . import adjacency as _adjacency
from . import asn_bgp as _asn_bgp
from . import cloud_buckets as _cloud_buckets
from . import discovery as _discovery
from . import domain as _domain
from . import email as _email
from . import email_extras as _email_extras
from . import email_security as _email_security
from . import github_leaks as _github_leaks
from . import hibp_passwords as _hibp_passwords
from . import http_headers as _http_headers
from . import internetdb as _internetdb
from . import ip as _ip
from . import ip_extras as _ip_extras
from . import malware_bazaar as _malware_bazaar
from . import patterns as _patterns
from . import pgp_keys as _pgp_keys
from . import phone as _phone
from . import ssl_tls as _ssl_tls
from . import subdomain_brute as _subdomain_brute
from . import takeover as _takeover
from . import tech_fingerprint as _tech_fingerprint
from . import telegram as _telegram
from . import threat_intel as _threat_intel
from . import tor_check as _tor_check
from . import typosquat as _typosquat
from . import username as _username
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
    _web_hardening, _well_known, _subdomain_brute,
]


def register_all(r: Runner) -> None:
    for m in MODULES:
        m.register(r)
