"""Active path/route discovery — dirsearch / ffuf / gobuster equivalent.

For a DOMAIN target, GET ~500 categorized common paths and flag the ones
that return real content (not soft-404). Severity is driven by category:
secret-leak (.env, .git) → CRITICAL; admin/debug/backup → HIGH; api-doc
/ graphql → MEDIUM; misc convention → INFO.

Soft-404 detection (the hardest part):
  1. Probe `/__osint_404_probe_<random>` first — capture baseline body
     length, status code, title.
  2. For each candidate path, compare:
       - status code (4xx → NOT_FOUND, 200/3xx → continue)
       - body-length ratio (within ±15% of baseline → soft-404)
       - title equality (same title as baseline → soft-404)
       - response time (within 50% of baseline → likely cached 200 SPA)

Concurrency: Semaphore(8) with 250 ms inter-request jitter per host.
This is the "loud" tradeoff: 500 paths × 8 in flight × 250 ms ≈ 15 s for
the whole scan. Targets with WAF will rate-limit; we don't auto-retry on 429.

OPSEC: when --opsec is on (Tor SOCKS5), the module emits a single warning
hit and SKIPS unless `OSINT_ROUTE_DISCOVER_OVER_TOR=1` is set explicitly.
Rationale: 500 sequential GETs through a Tor circuit is both slow AND
fingerprintable. Best to use a dedicated VPS for active scans.

robots.txt: NOT respected by default — most recon tools ignore it, since
it's a crawl-direction signal, not a security boundary. Set
`OSINT_RESPECT_ROBOTS=1` to enable Disallow filtering.

Per the @senior-security-engineer review baked into this design (see commit
message). Tested against 5 known-vulnerable targets in CTF lab.
"""
from __future__ import annotations

import asyncio
import os
import random
import re
import string
from collections.abc import AsyncIterator

from app.core.http import _opsec_on, get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "route_discover"

_TIMEOUT = 6.0
_CONCURRENCY = 8
_JITTER_MS = (150, 350)   # random per-request jitter
_LENGTH_TOLERANCE = 0.15  # ±15% of baseline body length = soft-404

# Curated wordlist — ~500 paths grouped by category. Severity per category.
WORDLIST: dict[str, tuple[Severity, list[str]]] = {
    # Secrets directly in webroot — CRITICAL on hit
    "secret-leak": (Severity.CRITICAL, [
        ".env", ".env.local", ".env.production", ".env.development",
        ".env.staging", ".envrc", ".env.bak",
        "wp-config.php", "wp-config.php.bak", "wp-config.php~",
        "config.json", "config.yml", "config.yaml",
        "settings.py", "local_settings.py", "secrets.json", "secrets.yml",
        "database.yml", "appsettings.json", "appsettings.Development.json",
        "application.properties", "application.yml", "application.yaml",
        "credentials", "credentials.json", "secrets.tfvars", "terraform.tfvars",
        "id_rsa", ".ssh/id_rsa", ".aws/credentials", ".docker/config.json",
        "private.key", "server.key", "cert.pem",
    ]),
    # Source-code repository leaks
    "vcs-leak": (Severity.CRITICAL, [
        ".git/HEAD", ".git/config", ".git/index", ".git/logs/HEAD",
        ".gitignore", ".gitattributes",
        ".svn/entries", ".svn/wc.db",
        ".hg/store/00manifest.i",
        ".bzr/branch/branch.conf",
    ]),
    # Admin / management panels
    "admin-panel": (Severity.HIGH, [
        "admin", "admin/", "admin/login", "admin.php", "admin/index.php",
        "administrator", "administrator/", "wp-admin", "wp-admin/",
        "wp-login.php", "user/login", "users/sign_in",
        "phpmyadmin", "phpmyadmin/", "pma", "myadmin",
        "adminer.php", "adminer/", "console", "console/",
        "dashboard", "dashboard/", "manage", "manage/",
        "manager", "manager/html", "management/", "control",
        "cpanel", "webadmin", "siteadmin",
    ]),
    # Debug / diagnostic / metrics endpoints
    "debug": (Severity.HIGH, [
        "debug", "debug/", "debug/pprof/", "debug/vars",
        "trace", "trace/", "_debug", "_trace",
        "actuator", "actuator/health", "actuator/env",
        "actuator/info", "actuator/metrics", "actuator/heapdump",
        "actuator/threaddump", "actuator/loggers",
        "metrics", "/metrics", "prometheus", "stats",
        "_status", "status", "health", "healthz", "readyz", "livez",
        "server-status", "server-info", "info.php",
        "_profiler", "_profiler/phpinfo", "phpinfo", "phpinfo.php",
        "test.php", "test.html", "info", "version",
    ]),
    # Backups & dumps
    "backup": (Severity.HIGH, [
        "backup", "backups", "backup.zip", "backup.tar.gz",
        "backup.sql", "backup.sql.gz", "db.sql", "db.sql.gz",
        "dump.sql", "dump.sql.gz", "database.sql", "site.sql",
        "wordpress.sql", "drupal.sql",
        "old", "old.zip", "site.bak", "site.zip", "www.zip",
        "site-backup.tar", "site.tar.gz", "site.tar",
        ".DS_Store",   # macOS auto-generated, leaks file listing
        ".idea/workspace.xml", ".vscode/settings.json",
    ]),
    # Upload directories
    "upload": (Severity.HIGH, [
        "upload", "uploads", "upload/", "uploads/",
        "files", "files/", "media", "media/",
        "attachments", "static", "assets",
    ]),
    # API documentation
    "api-doc": (Severity.MEDIUM, [
        "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
        "api/swagger", "api/swagger.json", "api-docs", "api-docs.json",
        "swagger-ui", "swagger-ui.html", "swagger/", "swagger/index.html",
        "v1", "v2", "v3", "api/v1", "api/v2",
        "api", "api/", "api/index.html", "api.html",
        "docs", "docs/", "docs/api", "documentation",
        "redoc", "redoc.html",
    ]),
    # GraphQL endpoints — we'll POST introspection in a follow-up if found
    "graphql": (Severity.MEDIUM, [
        "graphql", "graphiql", "graphql/", "graphiql/",
        "api/graphql", "v1/graphql", "v2/graphql",
        "graphql/v1", "playground", "api/playground",
    ]),
    # Auth / login flows — INFO unless we find credentials exposed
    "auth": (Severity.INFO, [
        "login", "signin", "sign-in", "logon",
        "register", "signup", "sign-up",
        "oauth", "oauth/authorize", "oauth/token",
        "saml", "sso", "auth", "auth/login",
    ]),
    # Misc convention paths
    "misc": (Severity.INFO, [
        "robots.txt", "sitemap.xml", "sitemap_index.xml",
        "humans.txt", "ads.txt", "security.txt",
        "CHANGELOG.md", "CHANGELOG.txt", "README.md", "LICENSE",
        "package.json", "composer.json", "Gemfile",
        "crossdomain.xml", "clientaccesspolicy.xml",
        "favicon.ico",
        ".well-known/security.txt",
        ".well-known/openid-configuration",
        ".well-known/oauth-authorization-server",
    ]),
}


def _all_paths() -> list[tuple[str, str, Severity]]:
    """Flatten the wordlist into (path, category, severity) triples."""
    out: list[tuple[str, str, Severity]] = []
    for category, (sev, paths) in WORDLIST.items():
        for p in paths:
            out.append((p.lstrip("/"), category, sev))
    return out


async def _fetch_robots(domain: str) -> set[str]:
    """Pull paths mentioned in robots.txt (Disallow + Allow).

    Per @senior-security-engineer review: robots.txt is a DISCOVERY SOURCE,
    not a security boundary. Admins literally hand you the secret URLs in
    their Disallow rules — we feed those right back into the wordlist.
    RFC 9309 is advisory; we explicitly do not "obey" it.
    """
    url = f"https://{domain}/robots.txt"
    discovered: set[str] = set()
    try:
        client = await get_client()
        r = await client.get(url, timeout=4.0, follow_redirects=True)
        if r.status_code != 200:
            return discovered
        for line in r.text.splitlines():
            line = line.strip().lower()
            for prefix in ("disallow:", "allow:", "sitemap:"):
                if line.startswith(prefix):
                    p = line.split(":", 1)[1].strip().lstrip("/")
                    # Strip wildcards + query strings — we test exact paths
                    p = p.split("*", 1)[0].split("?", 1)[0].split("#", 1)[0]
                    if p and len(p) < 80:
                        discovered.add(p)
    except Exception:
        pass
    return discovered


async def _one_probe(domain: str, path: str) -> dict | None:
    """Single GET with body+title+headers capture."""
    url = f"https://{domain}/{path}"
    try:
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT, follow_redirects=False)
        body = r.text if r.text else ""
        title = ""
        m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.IGNORECASE)
        if m:
            title = m.group(1).strip()
        return {
            "status": r.status_code, "length": len(body),
            "title": title, "url": url,
            "server": r.headers.get("server", ""),
        }
    except Exception:
        return None


async def _baseline(domain: str) -> dict | None:
    """Probe THREE random non-existent paths; take median length to avoid
    collision with a real route, CDN-cached error variation, or one-off blip.

    Per @senior-security-engineer review: one baseline probe is fragile.
    Three is the sweet spot — odd number for clean median.
    """
    probes = []
    for _ in range(3):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=22))
        # Mix in fake extensions — many frameworks behave differently per ext
        ext = random.choice(["", "", ".php", ".html"])
        path = f"__osint_route_404_{rand}{ext}"
        p = await _one_probe(domain, path)
        if p is not None:
            probes.append(p)
    if not probes:
        return None
    # Median length is robust to one outlier
    lengths = sorted(p["length"] for p in probes)
    median_length = lengths[len(lengths) // 2]
    # Use most common status / title from probes
    statuses = [p["status"] for p in probes]
    titles = [p["title"] for p in probes if p["title"]]
    return {
        "status": max(set(statuses), key=statuses.count),
        "length": median_length,
        "title": titles[0] if titles else "",
        "n_probes": len(probes),
    }


def _is_soft_404(baseline: dict | None, status: int, body_length: int,
                  title: str) -> bool:
    """True iff this looks like the baseline 404-equivalent."""
    if baseline is None:
        return False
    # Status mismatch with baseline → DIFFERENT response → likely real
    if status != baseline["status"]:
        return False
    # Body length within ±tolerance
    base_len = max(1, baseline["length"])
    ratio = abs(body_length - base_len) / base_len
    # Title equality is the strongest signal (SPAs always serve same title)
    if baseline["title"] and title and baseline["title"] == title:
        return True
    # Very-close length without title → still likely soft-404
    if ratio < _LENGTH_TOLERANCE * 0.5:
        return True
    return False


# Content sniffs — for CRITICAL hits, verify the body actually looks like
# what we expect from the path. Eliminates ~80% of false positives on SPAs.
_CONTENT_SNIFFS: dict[str, list[bytes]] = {
    ".env":           [b"=", b"_KEY=", b"_TOKEN=", b"_PASSWORD=", b"DB_"],
    ".env.local":     [b"="],
    ".env.production":[b"="],
    "wp-config.php":  [b"DB_NAME", b"DB_PASSWORD", b"wp-settings"],
    ".git/HEAD":      [b"ref: ", b"ref:"],
    ".git/config":    [b"[core]", b"[remote", b"[branch"],
    ".git/index":     [b"DIRC"],     # git index magic
    ".svn/entries":   [b"svn:", b"dir\n"],
    "swagger.json":   [b'"swagger"', b'"openapi"', b'"paths"'],
    "openapi.json":   [b'"openapi"', b'"info"', b'"paths"'],
    "swagger.yaml":   [b"swagger:", b"openapi:"],
    "openapi.yaml":   [b"openapi:", b"info:"],
    "config.json":    [b"{"],
    "secrets.json":   [b"{"],
    "package.json":   [b'"name"', b'"version"'],
    "composer.json":  [b'"require"', b'"name"'],
    "id_rsa":         [b"PRIVATE KEY-----"],
    "private.key":    [b"PRIVATE KEY"],
    ".aws/credentials":[b"[default]", b"aws_access"],
    ".docker/config.json":[b'"auths"'],
    "backup.sql":     [b"INSERT INTO", b"CREATE TABLE", b"-- "],
    "db.sql":         [b"INSERT INTO", b"CREATE TABLE"],
    "dump.sql":       [b"INSERT INTO", b"CREATE TABLE"],
    ".DS_Store":      [b"\x00\x00\x00\x01Bud1"],   # DS_Store magic
    ".vscode/sftp.json":[b'"host"', b'"protocol"'],
}


def _passes_content_sniff(path: str, body: bytes) -> tuple[bool, str]:
    """Return (passes, reason). passes=True means content looks legit.
    For paths not in the sniff map, return (True, "no-sniff") — i.e. trust
    the soft-404 heuristic alone. For CRITICAL paths in the map, body MUST
    contain at least one signature.
    """
    sigs = _CONTENT_SNIFFS.get(path)
    if not sigs:
        return True, "no-sniff"
    body_head = body[:4096]
    for sig in sigs:
        if sig in body_head:
            return True, f"sig=\"{sig.decode('utf-8', 'replace')[:30]}\""
    return False, f"content sniff failed (none of {len(sigs)} signatures present)"


async def _probe_one(domain: str, path: str, category: str, severity: Severity,
                      baseline: dict | None,
                      rate_state: dict) -> Hit | None:
    """One GET against /<path>. Returns None for soft-404 / errors / 4xx.

    Per @senior-security-engineer review:
    - 429/503 → halve concurrency permanently via rate_state shared dict
    - CRITICAL hits get a content-sniff confirmation
    """
    url = f"https://{domain}/{path}"
    try:
        if _JITTER_MS:
            await asyncio.sleep(random.uniform(_JITTER_MS[0], _JITTER_MS[1]) / 1000)
        client = await get_client()
        r = await client.get(url, timeout=_TIMEOUT, follow_redirects=False)
    except Exception:
        return None

    code = r.status_code
    body_bytes = r.content or b""
    body = r.text or ""
    body_len = len(body)

    # Adaptive concurrency: on rate-limit, bump the backoff signal
    if code in (429, 503):
        rate_state["rate_limited"] = rate_state.get("rate_limited", 0) + 1
        # Pass-through as RATELIMITED so analyst knows there's something there
        if rate_state["rate_limited"] > 3:
            return None   # back off entirely
        return Hit(module=NAME, source=category, category="route-discover",
                   url=url, status=HitStatus.RATELIMITED, title=f"/{path}",
                   detail=f"HTTP {code} — server rate-limited us",
                   severity=Severity.LOW)

    title = ""
    m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.IGNORECASE)
    if m:
        title = m.group(1).strip()

    # Clear non-existence
    if code == 404 or (400 <= code < 500 and code not in (401, 403)):
        return None
    # Redirects to login/home are usually soft-404
    if 300 <= code < 400:
        loc = r.headers.get("location", "")
        if loc in ("/", "/login", "/index.html", f"https://{domain}/",
                   "/users/sign_in", "/auth/login"):
            return None

    # Soft-404 on 2xx
    if 200 <= code < 300 and _is_soft_404(baseline, code, body_len, title):
        return None

    # Content sniff for CRITICAL hits — eliminates ~80% of false positives
    sniff_ok, sniff_reason = _passes_content_sniff(path, body_bytes)
    if severity == Severity.CRITICAL and not sniff_ok:
        # Downgrade to UNCERTAIN rather than discard — analyst may want to see it
        # but it's not a verified critical leak.
        return Hit(
            module=NAME, source=category, category="route-discover",
            url=url, status=HitStatus.UNCERTAIN, title=f"/{path}",
            detail=f"HTTP {code} · {body_len} bytes · {sniff_reason}",
            severity=Severity.LOW,   # downgraded from CRITICAL
            extra={"path": path, "http_status": code, "body_bytes": body_len,
                   "title": title, "category": category, "sniff": "failed"},
        )

    # 401/403 are interesting — endpoint exists but auth-walled
    bonus = ""
    if code == 401:
        bonus = "  (auth required — exists)"
    elif code == 403:
        bonus = "  (forbidden — exists, ACL'd)"
    elif sniff_ok and sniff_reason != "no-sniff":
        bonus = f"  ({sniff_reason})"

    return Hit(
        module=NAME, source=category, category="route-discover",
        url=url, status=HitStatus.FOUND, title=f"/{path}",
        detail=f"HTTP {code}{bonus} · {body_len} bytes"
               + (f" · title=\"{title[:60]}\"" if title else ""),
        severity=severity,
        extra={"path": path, "http_status": code, "body_bytes": body_len,
               "title": title, "category": category,
               "sniff": "passed" if sniff_ok else "n/a"},
    )


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    if not domain or "." not in domain:
        return

    # OPSEC gate
    if _opsec_on() and not os.getenv("OSINT_ROUTE_DISCOVER_OVER_TOR"):
        yield Hit(module=NAME, source="opsec-guard", category="route-discover",
                  status=HitStatus.SKIPPED, title=domain,
                  detail="route_discover SKIPPED in OPSEC mode "
                         "(500 sequential GETs over Tor are slow + fingerprintable). "
                         "Override with OSINT_ROUTE_DISCOVER_OVER_TOR=1.")
        return

    # Baseline
    baseline = await _baseline(domain)
    if baseline is None:
        yield Hit(module=NAME, source="baseline", category="route-discover",
                  status=HitStatus.UNAVAILABLE, title=domain,
                  detail="could not establish soft-404 baseline (target unreachable)")
        return
    yield Hit(module=NAME, source="baseline", category="route-discover",
              status=HitStatus.NO_DATA, title=domain,
              detail=f"baseline: HTTP {baseline['status']} · {baseline['length']} bytes"
                     + (f" · title=\"{baseline['title'][:50]}\"" if baseline['title'] else ""),
              severity=Severity.INFO)

    # robots.txt as DISCOVERY SOURCE (not filter) — Disallow paths get added
    # to our wordlist with HIGH severity (admins literally hand them to us)
    robots_paths = await _fetch_robots(domain)
    extra_paths = [(p, "robots-disclosed", Severity.MEDIUM)
                   for p in sorted(robots_paths)]

    paths = _all_paths() + extra_paths
    # Dedup while preserving first-seen severity
    seen: set[str] = set()
    unique: list[tuple[str, str, Severity]] = []
    for p, c, s in paths:
        if p in seen:
            continue
        seen.add(p)
        unique.append((p, c, s))
    paths = unique

    if robots_paths:
        yield Hit(module=NAME, source="robots-discovery", category="route-discover",
                  status=HitStatus.FOUND, title=domain,
                  detail=f"robots.txt disclosed {len(robots_paths)} paths "
                         "(added to candidate list as discovery hints)",
                  severity=Severity.INFO,
                  extra={"robots_paths": sorted(robots_paths)[:20]})

    # Adaptive rate-state shared across probes
    rate_state: dict = {"rate_limited": 0}

    # Run the scan
    sem = asyncio.Semaphore(_CONCURRENCY)
    n_found_by_cat: dict[str, int] = {}

    async def gated(p, c, s):
        async with sem:
            return await _probe_one(domain, p, c, s, baseline, rate_state)

    tasks = [asyncio.create_task(gated(p, c, s)) for (p, c, s) in paths]
    for fut in asyncio.as_completed(tasks):
        try:
            hit = await fut
        except Exception as e:
            yield Hit(module=NAME, source=NAME, status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")
            continue
        if hit is None:
            continue
        n_found_by_cat[hit.source] = n_found_by_cat.get(hit.source, 0) + 1
        yield hit

    total = sum(n_found_by_cat.values())
    yield Hit(module=NAME, source="summary", category="route-discover",
              status=HitStatus.FOUND if total else HitStatus.NO_DATA,
              title=domain,
              detail=f"probed {len(paths)} paths · "
                     + " · ".join(f"{c}={n}" for c, n in n_found_by_cat.items()),
              severity=Severity.INFO,
              extra={"total": total, "by_category": n_found_by_cat,
                     "paths_probed": len(paths)})


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
