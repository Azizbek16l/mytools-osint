"""OSINT modules. Each module registers one or more (kind → producer) entries with the Runner.

To register a module: implement a `register(runner)` callable and append it to MODULES.
"""
from __future__ import annotations

from app.core.runner import Runner

from . import adjacency as _adjacency
from . import asn_bgp as _asn_bgp
from . import discovery as _discovery
from . import domain as _domain
from . import email as _email
from . import email_extras as _email_extras
from . import email_security as _email_security
from . import http_headers as _http_headers
from . import internetdb as _internetdb
from . import ip as _ip
from . import ip_extras as _ip_extras
from . import patterns as _patterns
from . import pgp_keys as _pgp_keys
from . import phone as _phone
from . import ssl_tls as _ssl_tls
from . import takeover as _takeover
from . import tech_fingerprint as _tech_fingerprint
from . import telegram as _telegram
from . import threat_intel as _threat_intel
from . import tor_check as _tor_check
from . import typosquat as _typosquat
from . import username as _username
from . import web_recon as _web_recon
from . import whatsapp as _whatsapp

MODULES = [
    # core identity probes
    _username, _email, _email_extras, _phone, _telegram, _whatsapp,
    # network / domain
    _ip, _ip_extras, _domain, _discovery, _patterns, _adjacency,
    _ssl_tls, _http_headers, _asn_bgp, _tech_fingerprint,
    # red-team additions (free sources, no paid keys)
    _internetdb, _threat_intel, _takeover, _web_recon,
    _email_security, _typosquat, _pgp_keys, _tor_check,
]


def register_all(r: Runner) -> None:
    for m in MODULES:
        m.register(r)
