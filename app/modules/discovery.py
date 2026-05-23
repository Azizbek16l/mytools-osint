"""Open-source discovery via free, no-key APIs.

Sources:
  - archive.org Wayback Machine — historical snapshots of profile URLs
  - GitHub public search — code/commit references to email or username (no key needed,
    rate-limited; user can paste a PAT in env as GITHUB_TOKEN for higher limits)
  - Google Dorks generator — produces ready-to-click queries for the input
"""
from __future__ import annotations

import os
import urllib.parse
from collections.abc import AsyncIterator

from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "discovery"


def _gh_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "mytools-osint"}
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _wayback(target: str) -> AsyncIterator[Hit]:
    """Wayback CDX — first/last snapshot for any URL containing the target string."""
    # Use the wildcard CDX search to find any snapshotted page matching.
    cdx = (
        f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(target)}"
        f"&matchType=prefix&output=json&limit=20&fl=timestamp,original"
    )
    try:
        client = await get_client()
        r = await client.get(cdx, headers={"Accept": "application/json"}, timeout=20)
        if r.status_code != 200:
            yield Hit(module=NAME, source="Wayback", category="archive",
                      status=HitStatus.UNCERTAIN, detail=f"HTTP {r.status_code}")
            return
        rows = r.json() or []
        if len(rows) <= 1:
            yield Hit(module=NAME, source="Wayback", category="archive",
                      status=HitStatus.NOT_FOUND, detail="no archived snapshots")
            return
        for ts, original in rows[1:11]:
            snap = f"https://web.archive.org/web/{ts}/{original}"
            yield Hit(
                module=NAME, source="Wayback", category="archive",
                status=HitStatus.FOUND,
                title=original,
                detail=f"snapshot {ts}",
                url=snap, severity=Severity.LOW,
                extra={"timestamp": ts, "url": original},
            )
    except Exception as e:
        yield Hit(module=NAME, source="Wayback", category="archive",
                  status=HitStatus.ERROR, detail=str(e))


async def _github_search(value: str, kind: QueryKind) -> AsyncIterator[Hit]:
    """Public GitHub code search — finds mentions of the email or username in repos.

    Note: unauthenticated requests are throttled to ~10/min. Set GITHUB_TOKEN env
    for 30/min via a personal access token (free).
    """
    if kind == QueryKind.EMAIL:
        q = value
    else:
        q = f'"{value}"'
    url = f"https://api.github.com/search/code?q={urllib.parse.quote(q)}&per_page=10"
    try:
        client = await get_client()
        r = await client.get(url, headers=_gh_headers(), timeout=15)
        if r.status_code == 403 and "rate limit" in r.text.lower():
            yield Hit(module=NAME, source="GitHub:code", category="leak",
                      status=HitStatus.RATELIMITED,
                      detail="set GITHUB_TOKEN in .env for 30 req/min")
            return
        if r.status_code == 422 and not os.getenv("GITHUB_TOKEN"):
            yield Hit(module=NAME, source="GitHub:code", category="leak",
                      status=HitStatus.SKIPPED,
                      detail="GitHub code search requires GITHUB_TOKEN (free)")
            return
        if r.status_code != 200:
            yield Hit(module=NAME, source="GitHub:code", category="leak",
                      status=HitStatus.UNCERTAIN, detail=f"HTTP {r.status_code}")
            return
        data = r.json() or {}
        items = data.get("items") or []
        if not items:
            yield Hit(module=NAME, source="GitHub:code", category="leak",
                      status=HitStatus.NOT_FOUND,
                      detail=f"no public code matches (total={data.get('total_count', 0)})")
            return
        for it in items[:10]:
            repo = (it.get("repository") or {}).get("full_name", "?")
            path = it.get("path", "?")
            html = it.get("html_url", "")
            yield Hit(
                module=NAME, source=f"GitHub:{repo}", category="leak",
                status=HitStatus.FOUND,
                title=f"{repo}/{path}",
                detail="public code mention",
                url=html, severity=Severity.HIGH,
                extra={"repo": repo, "path": path},
            )
    except Exception as e:
        yield Hit(module=NAME, source="GitHub:code", category="leak",
                  status=HitStatus.ERROR, detail=str(e))


async def _gitlab_user(username: str) -> AsyncIterator[Hit]:
    """GitLab.com public user lookup. Mirrors the GitHub user probe.

    `https://gitlab.com/api/v4/users?username=<u>` returns 0 or 1 user matching
    that exact handle (case-insensitive). No auth needed, no key.
    """
    url = "https://gitlab.com/api/v4/users"
    try:
        client = await get_client()
        r = await client.get(
            url, params={"username": username},
            headers={"Accept": "application/json", "User-Agent": "mytools-osint"},
            timeout=10,
        )
        if r.status_code == 200:
            users = r.json() or []
            if not users:
                yield Hit(module=NAME, source="GitLab:user", category="profile",
                          status=HitStatus.NOT_FOUND,
                          detail="no public user with that handle")
                return
            u = users[0]
            yield Hit(
                module=NAME, source="GitLab:user", category="profile",
                status=HitStatus.FOUND,
                title=u.get("name") or u.get("username") or username,
                detail=(
                    f"id={u.get('id')} state={u.get('state','?')} "
                    f"created={u.get('created_at','?')[:10]} "
                    f"loc={u.get('location') or '-'} "
                    f"org={u.get('organization') or '-'} "
                    f"bio={(u.get('bio') or '')[:60]}"
                ),
                url=u.get("web_url") or f"https://gitlab.com/{username}",
                severity=Severity.HIGH,
                extra=u,
            )
        elif r.status_code in (429, 403):
            yield Hit(module=NAME, source="GitLab:user", category="profile",
                      status=HitStatus.RATELIMITED, detail=f"HTTP {r.status_code}")
        else:
            yield Hit(module=NAME, source="GitLab:user", category="profile",
                      status=HitStatus.UNCERTAIN, detail=f"HTTP {r.status_code}")
    except Exception as e:
        yield Hit(module=NAME, source="GitLab:user", category="profile",
                  status=HitStatus.ERROR, detail=str(e))


async def _github_user(username: str) -> AsyncIterator[Hit]:
    """GitHub user lookup — public-no-key endpoint, very useful profile detail."""
    url = f"https://api.github.com/users/{urllib.parse.quote(username)}"
    try:
        client = await get_client()
        r = await client.get(url, headers=_gh_headers(), timeout=10)
        if r.status_code == 200:
            data = r.json() or {}
            yield Hit(
                module=NAME, source="GitHub:user", category="profile",
                status=HitStatus.FOUND,
                title=data.get("name") or data.get("login"),
                detail=(
                    f"id={data.get('id')} repos={data.get('public_repos')} "
                    f"followers={data.get('followers')} "
                    f"loc={data.get('location') or '-'} "
                    f"co={data.get('company') or '-'} "
                    f"email={data.get('email') or '-'} "
                    f"blog={data.get('blog') or '-'}"
                ),
                url=data.get("html_url", ""),
                severity=Severity.HIGH,
                extra=data,
            )
        elif r.status_code == 404:
            yield Hit(module=NAME, source="GitHub:user", category="profile",
                      status=HitStatus.NOT_FOUND, detail="user not found")
        else:
            yield Hit(module=NAME, source="GitHub:user", category="profile",
                      status=HitStatus.UNCERTAIN, detail=f"HTTP {r.status_code}")
    except Exception as e:
        yield Hit(module=NAME, source="GitHub:user", category="profile",
                  status=HitStatus.ERROR, detail=str(e))


def _dorks(value: str, kind: QueryKind) -> list[tuple[str, str]]:
    """Return [(label, google-search-url), ...] — ready-to-click Google dorks."""
    q = urllib.parse.quote(value)
    dorks: list[tuple[str, str]] = []
    base = "https://www.google.com/search?q="
    if kind in (QueryKind.USERNAME, QueryKind.TELEGRAM):
        dorks += [
            ("exact-phrase",        f'{base}"{q}"'),
            ("with site:linkedin",  f'{base}"{q}"+site%3Alinkedin.com'),
            ("with site:fb",        f'{base}"{q}"+site%3Afacebook.com'),
            ("filetype:pdf",        f'{base}"{q}"+filetype%3Apdf'),
            ("paste sites",         f'{base}"{q}"+(site%3Apastebin.com+OR+site%3Aghostbin.com+OR+site%3Arentry.co)'),
        ]
    elif kind == QueryKind.EMAIL:
        dorks += [
            ("exact-email",         f'{base}"{q}"'),
            ("breach paste sites",  f'{base}"{q}"+(site%3Apastebin.com+OR+site%3Aanonfiles.com+OR+site%3Arentry.co)'),
            ("intext + filetype",   f'{base}intext%3A"{q}"+(filetype%3Apdf+OR+filetype%3Axls+OR+filetype%3Adoc)'),
            ("github gists",        f'{base}"{q}"+site%3Agist.github.com'),
        ]
    elif kind == QueryKind.PHONE:
        digits = "".join(ch for ch in value if ch.isdigit())
        d = urllib.parse.quote(digits)
        dorks += [
            ("exact-number",        f'{base}"{q}"'),
            ("digits-only",         f'{base}"{d}"'),
            ("contact-pages",       f'{base}"{q}"+(intitle%3Acontact+OR+intext%3A"contact+us")'),
        ]
    elif kind == QueryKind.DOMAIN:
        dorks += [
            ("inurl",               f'{base}site%3A{q}'),
            ("subdomain pivot",     f'{base}site%3A*.{q}+-www'),
            ("files",               f'{base}site%3A{q}+(filetype%3Apdf+OR+filetype%3Axls+OR+filetype%3Adoc+OR+filetype%3Atxt)'),
            ("admin/login",         f'{base}site%3A{q}+(inurl%3Aadmin+OR+inurl%3Alogin+OR+intitle%3Asignin)'),
            ("exposed configs",     f'{base}site%3A{q}+(ext%3Aenv+OR+ext%3Ayaml+OR+ext%3Aconfig+OR+ext%3Asql)'),
        ]
    return dorks


async def run(query: Query) -> AsyncIterator[Hit]:
    value = query.value.strip()
    if not value:
        return
    # 1) ready-to-click Google dorks (no network — purely synthetic, always emitted)
    for label, url in _dorks(value, query.kind):
        yield Hit(
            module=NAME, source=f"Dork:{label}", category="dork",
            status=HitStatus.FOUND, title=f"Google dork: {label}",
            detail="open in browser to pivot",
            url=url, severity=Severity.INFO,
        )

    # 2) Wayback Machine — works for any string
    async for h in _wayback(value):
        yield h

    # 3) GitHub code/user search where applicable
    if query.kind in (QueryKind.USERNAME, QueryKind.EMAIL, QueryKind.TELEGRAM):
        async for h in _github_search(value, query.kind):
            yield h
    if query.kind == QueryKind.USERNAME:
        # also fetch the GitHub / GitLab user profile if the username matches
        handle = value.lstrip("@")
        async for h in _github_user(handle):
            yield h
        async for h in _gitlab_user(handle):
            yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.USERNAME, QueryKind.EMAIL, QueryKind.PHONE,
                     QueryKind.DOMAIN, QueryKind.TELEGRAM], run)
