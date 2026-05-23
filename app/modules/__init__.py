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
from . import http_headers as _http_headers
from . import ip as _ip
from . import ip_extras as _ip_extras
from . import patterns as _patterns
from . import phone as _phone
from . import ssl_tls as _ssl_tls
from . import tech_fingerprint as _tech_fingerprint
from . import telegram as _telegram
from . import username as _username
from . import whatsapp as _whatsapp

MODULES = [_username, _email, _email_extras, _phone, _telegram, _whatsapp,
           _ip, _ip_extras, _domain, _discovery, _patterns, _adjacency,
           _ssl_tls, _http_headers, _asn_bgp, _tech_fingerprint]


def register_all(r: Runner) -> None:
    for m in MODULES:
        m.register(r)
