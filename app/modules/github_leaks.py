"""GitHub public-repo leak detection for a domain or email.

For a DOMAIN: search public GitHub code for mentions of `@<domain>` (emails),
`<domain>` (config files, error pages, internal URLs), and the wildcard
`<basename>` (e.g. "marsits" for "marsits.uz"). Each hit is a public repo
where someone wrote your domain — could be an honest mention, but is
often: a fork of a private repo, a leaked config, an employee's personal
project containing your endpoints.

For an EMAIL: search public commits for the email address — gives you
every public commit ever pushed by that author across all of GitHub.
This is the single best way to find an employee's personal projects /
side-gigs / hobby repos that may leak more than they realize.

Auth:
  - Without a GITHUB_PAT we get 10 requests / minute (search) — useful
    for one-off queries but rate-limits fast.
  - With a GITHUB_PAT (any scope, even 'public-only') we get 30/min.

  Set in env or via `osint config set GITHUB_PAT ghp_…`.

Caveats:
  - GitHub's code-search returns at most 100 results per query, capped at
    1,000 across all pages. We grab the first page (30 results) and stop.
  - Counts can be off-by-a-bit; GitHub's index lags by minutes.
"""
from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from typing import Any, cast
from urllib.parse import quote

from app.core.classify import classify_exception, classify_http
from app.core.http import get_client
from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "github_leaks"

_CODE_SEARCH = "https://api.github.com/search/code?q={q}&per_page=30"
_USER_SEARCH = "https://api.github.com/search/users?q={q}&per_page=10"
_COMMIT_SEARCH = "https://api.github.com/search/commits?q={q}&per_page=20"

_TIMEOUT = 12.0


def _token() -> str:
    """GitHub PAT from env. Accept GITHUB_PAT or the common GITHUB_TOKEN alias."""
    return (os.getenv("GITHUB_PAT", "") or os.getenv("GITHUB_TOKEN", "")).strip()


def _headers() -> dict[str, str]:
    pat = _token()
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "mytools-osint",
    }
    if pat:
        h["Authorization"] = f"Bearer {pat}"
    return h


async def _gh_get(url: str) -> tuple[int, dict[str, Any] | None, str]:
    try:
        client = await get_client()
        r = await client.get(url, headers=_headers(), timeout=_TIMEOUT)
    except Exception as e:
        return 0, None, f"{type(e).__name__}: {e}"
    if r.status_code == 422:
        # GitHub returns 422 for malformed queries — treat as NO_DATA so it's
        # less alarming than ERROR.
        return r.status_code, None, "invalid query"
    if r.status_code != 200:
        return r.status_code, None, f"HTTP {r.status_code}"
    try:
        return r.status_code, r.json(), ""
    except Exception as e:  # pragma: no cover
        return r.status_code, None, f"bad json: {e}"


async def _search_code_for_domain(domain: str) -> AsyncIterator[Hit]:
    """GitHub code search for the domain string."""
    q = quote(f'"{domain}"')
    url = _CODE_SEARCH.format(q=q)
    code, data, err = await _gh_get(url)
    if data is None:
        yield Hit(module=NAME, source="github code-search", category="leak",
                  url=f"https://github.com/search?q=%22{domain}%22&type=code",
                  status=classify_http(code) if code else classify_exception(Exception(err)),
                  title=domain, detail=err)
        return
    total = data.get("total_count", 0)
    items = data.get("items") or []
    if total == 0:
        yield Hit(module=NAME, source="github code-search", category="leak",
                  url=f"https://github.com/search?q=%22{domain}%22&type=code",
                  status=HitStatus.NO_DATA, title=domain,
                  detail="no public-code mentions")
        return
    # One summary hit + up to 5 sample-repo hits (high-signal repos go first
    # because GitHub sorts by relevance).
    yield Hit(
        module=NAME, source="github code-search", category="leak",
        url=f"https://github.com/search?q=%22{domain}%22&type=code",
        status=HitStatus.FOUND, title=domain,
        detail=f"{total:,} public-code mentions of {domain}",
        severity=Severity.HIGH if total > 50 else Severity.MEDIUM,
        extra={"total": total, "sampled": len(items)},
    )
    seen_repos: set[str] = set()
    for item in items[:8]:
        repo = (item.get("repository") or {}).get("full_name") or ""
        if not repo or repo in seen_repos:
            continue
        seen_repos.add(repo)
        path = item.get("path", "")
        yield Hit(
            module=NAME, source=f"github:{repo}", category="leak",
            url=item.get("html_url", ""),
            status=HitStatus.FOUND, title=f"{repo}/{path}",
            detail=f"{domain} mentioned in {path}",
            severity=Severity.MEDIUM,
            extra={"repo": repo, "path": path, "score": item.get("score")},
        )


async def _search_commits_for_email(email: str) -> AsyncIterator[Hit]:
    """GitHub commit search for the email — finds the author's public commits."""
    q = quote(f"author-email:{email}")
    url = _COMMIT_SEARCH.format(q=q)
    code, data, err = await _gh_get(url)
    if data is None:
        yield Hit(module=NAME, source="github commit-search", category="leak",
                  url=f"https://github.com/search?q=author-email%3A{email}&type=commits",
                  status=classify_http(code) if code else classify_exception(Exception(err)),
                  title=email, detail=err)
        return
    total = data.get("total_count", 0)
    items: list[dict[str, Any]] = data.get("items") or []
    if total == 0:
        yield Hit(module=NAME, source="github commit-search", category="leak",
                  url=f"https://github.com/search?q=author-email%3A{email}&type=commits",
                  status=HitStatus.NO_DATA, title=email,
                  detail="no public commits by this email")
        return
    # `.get("full_name")` is typed Any|None via the empty-dict fallback; the set
    # only ever holds present full_name strings in practice. Cast keeps runtime
    # behaviour identical while giving `sorted` a sortable element type.
    repo_names = cast(
        "set[str]",
        {(i.get("repository") or {}).get("full_name") for i in items if i.get("repository")},
    )
    repos = sorted(repo_names)
    yield Hit(
        module=NAME, source="github commit-search", category="leak",
        url=f"https://github.com/search?q=author-email%3A{email}&type=commits",
        status=HitStatus.FOUND, title=email,
        detail=(f"{total:,} public commits across {len(repos)} repo(s): "
                f"{', '.join(r for r in repos[:5] if r)}"
                + (" …" if len(repos) > 5 else "")),
        severity=Severity.HIGH,
        extra={"total_commits": total, "repos": repos[:30]},
    )


async def _search_users_for_email(email: str) -> AsyncIterator[Hit]:
    """User search by email."""
    q = quote(email)
    url = _USER_SEARCH.format(q=q)
    code, data, err = await _gh_get(url)
    if data is None or not isinstance(data, dict):
        return
    items = data.get("items") or []
    if not items:
        return
    for u in items[:5]:
        login = u.get("login", "")
        yield Hit(
            module=NAME, source="github user-search", category="leak",
            url=u.get("html_url", ""),
            status=HitStatus.FOUND, title=login,
            detail=f"user with public email {email}: @{login}",
            severity=Severity.HIGH,
            extra={"login": login, "id": u.get("id"), "type": u.get("type")},
        )


async def run(query: Query) -> AsyncIterator[Hit]:
    value = (query.value or "").strip().lower()
    if not value:
        return
    # GitHub's code/commit search API hard-requires authentication; without a
    # token every endpoint 401/403/422s. Emit ONE concise SKIPPED hit instead
    # of an error per endpoint.
    if not _token():
        yield Hit(module=NAME, source="github", category="leak",
                  status=HitStatus.SKIPPED, title=value,
                  detail="no GITHUB_TOKEN — skipped")
        return
    if query.kind == QueryKind.DOMAIN:
        async for h in _search_code_for_domain(value):
            yield h
    elif query.kind == QueryKind.EMAIL:
        # Run code+commit+user searches concurrently and stream as they finish.
        # User-search runs against the user index; commit-search against commit
        # index; code-search against the code index — three distinct rate buckets.
        async def collect(gen: AsyncIterator[Hit]) -> list[Hit]:
            return [h async for h in gen]

        tasks = [
            asyncio.create_task(collect(_search_commits_for_email(value))),
            asyncio.create_task(collect(_search_users_for_email(value))),
        ]
        # Also search code for the email (catches config files etc.)
        tasks.append(asyncio.create_task(collect(_search_code_for_domain(value))))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, BaseException):
                yield Hit(module=NAME, source="github", status=HitStatus.ERROR,
                          detail=f"{type(r).__name__}: {r}")
                continue
            for h in r:
                yield h


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN, QueryKind.EMAIL], run)
