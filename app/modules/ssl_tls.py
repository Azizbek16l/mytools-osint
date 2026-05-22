"""SSL/TLS posture — async cert chain pull + grade. Pure stdlib + cryptography.

No external API, no key. Connects host:443 (configurable), grabs the certificate,
parses CN/SAN/issuer/validity/key/sig/cipher/TLS version, and grades the result.

Hits emitted: one main "found" hit per host with the parsed summary, plus
issue-specific hits when findings warrant (expired, expiring soon, SHA1 sig,
RSA<2048, TLS<1.2, weak cipher).
"""
from __future__ import annotations

import asyncio
import ssl
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "ssl_tls"

WEAK_SIG_ALGS = {"sha1", "md5", "md2"}
WEAK_CIPHERS = {"3DES", "RC4", "EXPORT", "NULL", "DES-CBC"}


def _normalize_host(value: str) -> tuple[str, int]:
    v = value.strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    if ":" in v and not v.startswith("["):
        host, port = v.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return v, 443
    return v, 443


async def _grab_cert(host: str, port: int, timeout: float = 20.0) -> dict | None:
    """Return parsed cert + connection info, or None on failure."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout,
        )
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return {"error": "no ssl_object"}
        parsed = ssl_obj.getpeercert() or {}
        der = ssl_obj.getpeercert(binary_form=True)
        cipher = ssl_obj.cipher()
        version = ssl_obj.version()
        result = {
            "parsed": parsed,
            "der": der,
            "cipher": cipher,
            "version": version,
        }
        # Try to enrich via cryptography if available
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, rsa
            cert = x509.load_der_x509_certificate(der)
            result["subject"] = cert.subject.rfc4514_string()
            result["issuer"] = cert.issuer.rfc4514_string()
            result["serial"] = format(cert.serial_number, "x")
            result["not_before"] = cert.not_valid_before_utc
            result["not_after"] = cert.not_valid_after_utc
            result["sig_alg"] = cert.signature_algorithm_oid._name
            result["sha256"] = cert.fingerprint(hashes.SHA256()).hex()
            result["sha1"] = cert.fingerprint(hashes.SHA1()).hex()
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey):
                result["key_alg"] = "RSA"
                result["key_size"] = pub.key_size
            elif isinstance(pub, ec.EllipticCurvePublicKey):
                result["key_alg"] = "EC"
                result["key_size"] = pub.curve.key_size
                result["curve"] = pub.curve.name
            else:
                result["key_alg"] = type(pub).__name__
            # SAN
            try:
                ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                result["sans"] = [str(n.value) for n in ext.value]
            except x509.ExtensionNotFound:
                result["sans"] = []
        except ImportError:
            # fall back to ssl-only fields
            result["subject"] = ", ".join(f"{k}={v}" for t in parsed.get("subject", [])
                                          for k, v in t)
            result["issuer"] = ", ".join(f"{k}={v}" for t in parsed.get("issuer", [])
                                         for k, v in t)
            try:
                result["not_after"] = datetime.strptime(parsed["notAfter"], "%b %d %H:%M:%S %Y %Z")
                result["not_before"] = datetime.strptime(parsed["notBefore"], "%b %d %H:%M:%S %Y %Z")
            except Exception:
                pass
            result["sans"] = [v for k, v in parsed.get("subjectAltName", []) if k == "DNS"]
        return result
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _probe(host: str, port: int) -> AsyncIterator[Hit]:
    data = await _grab_cert(host, port)
    if data is None or "error" in data:
        yield Hit(
            module=NAME, source=f"{host}:{port}", category="tls",
            status=HitStatus.ERROR,
            detail=data.get("error", "connect failed") if data else "no response",
        )
        return

    not_after = data.get("not_after")
    days_left: int | None = None
    if isinstance(not_after, datetime):
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=UTC)
        days_left = (not_after - datetime.now(UTC)).days

    version = data.get("version", "?")
    cipher = data.get("cipher")
    cipher_name = cipher[0] if cipher else "?"
    sig_alg = (data.get("sig_alg") or "").lower()
    key_alg = data.get("key_alg", "?")
    key_size = data.get("key_size", 0)

    # severity rollup
    severity = Severity.INFO
    issues: list[str] = []
    if days_left is not None and days_left < 0:
        severity = Severity.HIGH
        issues.append(f"EXPIRED ({-days_left}d ago)")
    elif days_left is not None and days_left < 14:
        severity = Severity.MEDIUM
        issues.append(f"expiring in {days_left}d")
    if any(w in sig_alg for w in WEAK_SIG_ALGS):
        severity = Severity.HIGH
        issues.append(f"weak signature ({sig_alg})")
    if key_alg == "RSA" and key_size < 2048:
        severity = Severity.HIGH
        issues.append(f"weak key (RSA {key_size})")
    if version and version < "TLSv1.2":
        severity = Severity.HIGH
        issues.append(f"deprecated TLS ({version})")
    if cipher_name and any(w in cipher_name.upper() for w in WEAK_CIPHERS):
        severity = Severity.HIGH
        issues.append(f"weak cipher ({cipher_name})")

    detail_parts = []
    if data.get("subject"):
        detail_parts.append(f"subject={data['subject']}")
    if data.get("issuer"):
        detail_parts.append(f"issuer={data['issuer']}")
    if days_left is not None:
        detail_parts.append(f"expires in {days_left}d")
    detail_parts.append(f"TLS {version}")
    detail_parts.append(f"cipher {cipher_name}")
    if key_size:
        detail_parts.append(f"key {key_alg}/{key_size}")
    if issues:
        detail_parts.append(" · ".join(issues))

    yield Hit(
        module=NAME, source=f"{host}:{port}", category="tls",
        status=HitStatus.FOUND,
        title=data.get("subject", host),
        detail=" · ".join(detail_parts),
        url=f"https://{host}:{port}" if port != 443 else f"https://{host}",
        severity=severity,
        extra={
            "version": version,
            "cipher": cipher_name,
            "sig_alg": data.get("sig_alg"),
            "key_alg": key_alg,
            "key_size": key_size,
            "sha256": data.get("sha256"),
            "sha1": data.get("sha1"),
            "not_after": not_after.isoformat() if isinstance(not_after, datetime) else None,
            "days_left": days_left,
            "sans": data.get("sans"),
        },
    )


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    host, port = _normalize_host(query.value)
    if not host:
        return
    async for h in _probe(host, port):
        yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
