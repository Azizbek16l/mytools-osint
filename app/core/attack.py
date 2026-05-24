"""MITRE ATT&CK technique mapping for each OSINT module.

Maps `module_name → list of T-IDs` from the Reconnaissance (TA0043) and
Resource Development (TA0042) tactics. Used by HTML / Markdown reports to
tag every finding with the technique it supports, which lets SOC analysts
align our output with their detection / threat-hunting playbooks.

Source: https://attack.mitre.org/tactics/TA0043/ + TA0042
"""
from __future__ import annotations

# Each module mapped to its supporting ATT&CK technique IDs.
# T1589 — Gather Victim Identity Information
# T1590 — Gather Victim Network Information
# T1591 — Gather Victim Org Information
# T1592 — Gather Victim Host Information
# T1593 — Search Open Websites/Domains
# T1594 — Search Victim-Owned Websites
# T1595 — Active Scanning (.001 scanning IP, .002 vulnerability)
# T1596 — Search Open Technical Databases (.001 DNS, .002 WHOIS, .003 digital cert,
#         .004 CDN, .005 scan db)
# T1597 — Search Closed Sources
# T1598 — Phishing for Information
ATTACK_TIDS: dict[str, list[str]] = {
    # Identity / person
    "username":       ["T1589.003"],       # gather victim identity: employee names
    "email":          ["T1589.002"],       # gather victim identity: email addresses
    "email_extras":   ["T1589.002"],
    "email_security": ["T1590.005"],       # gather victim network: ip+config
    "phone":          ["T1589.001"],       # gather victim identity: credentials
    "telegram":       ["T1589.003"],
    "whatsapp":       ["T1589.003"],
    "pgp_keys":       ["T1589.001"],

    # Network / domain
    "ip":             ["T1590.005"],       # ip addresses
    "ip_extras":      ["T1590.005", "T1596.005"],
    "domain":         ["T1590.001", "T1596.003"],  # domain props + CT
    "asn_bgp":        ["T1590.005"],
    "internetdb":     ["T1596.005", "T1595.002"],  # scan-db + vuln scanning intel
    "tor_check":      ["T1596.005"],
    "passive_dns":    ["T1596.001"],       # DNS

    # Web / app
    "ssl_tls":        ["T1596.003"],
    "http_headers":   ["T1594"],           # search victim-owned websites
    "tech_fingerprint": ["T1592.002"],     # software
    "web_recon":      ["T1592.002", "T1594", "T1596"],  # multi
    "web_hardening":  ["T1594"],
    "well_known":     ["T1594"],
    "takeover":       ["T1583.001", "T1584.001"],  # acquire/compromise infra
    "subdomain_brute": ["T1590.005"],

    # Threat intel + IOC
    "threat_intel":   ["T1596.005"],
    "malware_bazaar": ["T1596.005"],
    "hibp_passwords": ["T1589.001"],

    # Discovery / OSINT
    "discovery":      ["T1593", "T1593.002"],   # search open: search engines
    "patterns":       ["T1589"],
    "adjacency":      ["T1589.003"],
    "github_leaks":   ["T1593.003"],       # search open: code repositories
    "cloud_buckets":  ["T1593", "T1530"],  # data from cloud storage
    "typosquat":      ["T1583.001"],       # acquire infra: domains
}


def tids_for(module: str) -> list[str]:
    """Return ATT&CK technique IDs supported by a given module."""
    return ATTACK_TIDS.get(module, [])


def coverage_summary() -> dict[str, int]:
    """How many modules touch each technique. Useful for the README."""
    counts: dict[str, int] = {}
    for tids in ATTACK_TIDS.values():
        for t in tids:
            counts[t] = counts.get(t, 0) + 1
    return counts
