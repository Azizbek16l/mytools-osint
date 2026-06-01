"""Passive subdomain brute-force via DNS A/AAAA lookups.

Tries a curated wordlist of common subdomain names against the target
domain. Pure DNS — no traffic to the target's webserver, no port scan,
nothing that an IDS would mark as 'active' recon. The DNS server (yours
or the target's NS) sees the queries; the target's web infra does not.

Wordlist: ~280 entries blending the top of SecLists' best-of-the-best
with high-signal infra names (vpn, mta, kibana, jenkins, gitlab, …).
Skipped if `--quick` profile is set (use `--profile deep` or
`--profile red-team` for this).
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import dns.asyncresolver

from app.core.runner import Runner
from app.core.types import Hit, HitStatus, Query, QueryKind, Severity

NAME = "subdomain_brute"

WORDLIST = [
    # admin / management
    "admin", "administrator", "manage", "management", "console", "dashboard",
    "panel", "cpanel", "webadmin", "siteadmin", "control", "controlpanel",
    # api / app
    "api", "api1", "api2", "api-staging", "api-prod", "api-dev", "graphql",
    "rest", "rpc", "webhook", "webhooks", "app", "apps", "application",
    # auth / identity
    "auth", "login", "signin", "sso", "saml", "oauth", "id", "identity",
    "accounts", "account", "secure", "vpn", "openvpn", "wireguard", "fortinet",
    "pulse", "anyconnect", "globalprotect", "citrix", "ssl",
    # mail / chat
    "mail", "smtp", "imap", "pop", "pop3", "webmail", "owa", "exchange",
    "mx", "mx1", "mx2", "mta", "relay", "chat", "rocketchat", "mattermost",
    "slack", "telegram", "matrix", "jabber",
    # dev / ci / vcs
    "git", "github", "gitlab", "bitbucket", "gitea", "gogs", "svn",
    "jenkins", "ci", "drone", "buildkite", "concourse", "travis", "circle",
    "argo", "argocd", "flux", "spinnaker",
    # data
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "elasticsearch", "kibana", "grafana", "prometheus", "alertmanager",
    "splunk", "datadog", "metabase", "looker", "tableau", "powerbi",
    "clickhouse", "snowflake", "bigquery", "athena", "presto", "trino",
    # ops / infra
    "ops", "devops", "sre", "monitoring", "monitor", "nagios", "zabbix",
    "icinga", "uptime", "uptime-kuma", "statuspage", "status", "health",
    "metrics", "logs", "log", "syslog", "sentry", "bugsnag", "newrelic",
    "rollbar", "opsgenie", "pagerduty",
    # files / storage
    "files", "file", "upload", "uploads", "downloads", "download", "ftp",
    "sftp", "rsync", "nfs", "smb", "s3", "minio", "ceph", "swift",
    "backup", "backups", "snapshot", "snapshots", "archive", "archives",
    # cloud / kube
    "cloud", "aws", "azure", "gcp", "k8s", "kubernetes", "kube", "rancher",
    "openshift", "harbor", "registry", "docker", "nexus", "artifactory",
    "vault", "consul", "nomad", "etcd",
    # network
    "router", "switch", "firewall", "fw", "ids", "ips", "waf", "proxy",
    "squid", "lb", "haproxy", "nginx", "apache", "tomcat", "varnish",
    "cdn", "cdn1", "cdn2", "edge", "origin",
    # collab / docs / wiki
    "wiki", "docs", "doc", "documentation", "confluence", "notion", "jira",
    "youtrack", "phabricator", "trac", "redmine", "kanban", "trello",
    "asana", "monday", "linear",
    # support / crm / hr
    "support", "helpdesk", "help", "tickets", "ticket", "freshdesk",
    "zendesk", "intercom", "drift", "crm", "hr", "humanresources",
    "payroll", "expenses", "expensify",
    # marketing / cms
    "cms", "wordpress", "wp", "drupal", "joomla", "ghost", "strapi",
    "contentful", "sanity", "shop", "store", "checkout", "cart", "ecommerce",
    "shopify", "magento", "woocommerce", "prestashop",
    # env / stage / test
    "dev", "develop", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "preview", "preprod", "beta", "alpha", "demo", "sandbox",
    # generic
    "old", "new", "internal", "intranet", "extranet", "private", "public",
    "main", "www2", "www3", "m", "mobile", "video", "stream", "rtmp",
    "voice", "voip", "sip", "pbx", "asterisk", "callcenter",
    # forgotten classics
    "blog", "news", "forum", "community", "events", "calendar", "training",
    "academy", "portal", "client", "clients", "partner", "partners",
]


async def _resolve(host: str) -> tuple[str, list[str]]:
    try:
        ans = await dns.asyncresolver.resolve(host, "A", lifetime=3.5)
        return host, [r.to_text() for r in ans]
    except Exception:
        return host, []


async def run(query: Query) -> AsyncIterator[Hit]:
    if query.kind != QueryKind.DOMAIN:
        return
    domain = (query.value or "").strip().lower().lstrip("*.").rstrip("/")
    if not domain or "." not in domain:
        return
    candidates = [f"{w}.{domain}" for w in WORDLIST]
    sem = asyncio.Semaphore(40)

    async def gated(h: str) -> tuple[str, list[str]]:
        async with sem:
            return await _resolve(h)

    tasks = [asyncio.create_task(gated(h)) for h in candidates]
    found = 0
    for fut in asyncio.as_completed(tasks):
        try:
            host, ips = await fut
        except Exception as e:
            yield Hit(module=NAME, source=NAME, status=HitStatus.ERROR,
                      detail=f"{type(e).__name__}: {e}")
            continue
        if not ips:
            continue
        found += 1
        yield Hit(
            module=NAME, source="dns-brute", category="subdomain",
            url=f"https://{host}/", status=HitStatus.FOUND,
            title=host, detail=f"resolves → {', '.join(ips[:3])}",
            severity=Severity.MEDIUM,
            extra={"host": host, "ips": ips},
        )
    yield Hit(module=NAME, source="summary", category="subdomain",
              status=HitStatus.FOUND if found else HitStatus.NO_DATA,
              title=domain,
              detail=f"DNS-brute {len(candidates)} candidates, {found} resolve",
              severity=Severity.INFO,
              extra={"checked": len(candidates), "found": found})


def register(r: Runner) -> None:
    r.register(NAME, [QueryKind.DOMAIN], run)
