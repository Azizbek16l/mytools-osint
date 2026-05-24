# Data sources used by `mytools-osint`

Every external source the tool talks to, with rate-limit notes and the
"do I need a key?" answer. All free or freemium — no paid-only sources.

## Identity / username

| Source | Endpoint | Auth | Rate limit | Cap. |
|---|---|---|---|---|
| Sherlock (curated) | per-site URL templates | none | site-specific | 517 sites |
| WhatsMyName (deduped) | per-site URL templates | none | site-specific | 491 sites |
| Maigret (optional sync) | per-site URL templates | none | site-specific | 3000+ sites |

## Email

| Source | Auth | Rate limit |
|---|---|---|
| XposedOrNot      | none | generous |
| HudsonRock Cavalier | none | generous |
| ProxyNova ComB   | none | generous |
| Holehe-style probes (11 sites) | none | site-specific |
| Gravatar md5     | none | none |
| EmailRep         | none | 50/day |
| HIBP breach catalog (public, NOT per-account) | none | generous |
| HIBP per-account | **HIBP_API_KEY** (paid) | per plan |
| keys.openpgp.org | none | generous |
| keyserver.ubuntu.com | none | generous |

## Phone

| Source | Auth | Notes |
|---|---|---|
| libphonenumber (offline) | n/a | carrier / region / line-type / timezone — no network |
| Telegram MTProto         | your own user session | via Telethon |
| WhatsApp wa.me probe     | none | best-effort, no public API |
| Numverify                | optional NUMVERIFY_API_KEY | 100/month free |

## Domain / subdomain

| Source | Auth | Rate limit |
|---|---|---|
| crt.sh Certificate Transparency | none | generous |
| HackerTarget hostsearch        | none | ~50/day soft limit |
| Certspotter                     | none | generous |
| AlienVault OTX (read)           | none | generous |
| subdomain.center                | none | generous |
| RapidDNS scrape                 | none | scrape-limited |
| Wayback CDX                     | none | generous |
| ThreatMiner v2                  | none | 10/min |
| DNS (A/AAAA/MX/TXT/NS/CAA/SOA) | none | n/a |
| urlscan.io recent scans        | none | generous |

## Web / app

| Source | Auth | Purpose |
|---|---|---|
| target homepage + same-origin JS | none | secret scan |
| Wayback CDX URL list             | none | `.env/.git/admin` discovery |
| favicon.ico mmh3 hash            | none | pivot via Shodan favicon hash |
| HTTPS + TLS handshake            | none | SSL/TLS grade |
| HTTP response headers            | none | header grade |

## Email security (domain-level)

| Source | Endpoint | Auth |
|---|---|---|
| DNS TXT  (SPF + DMARC + DKIM + MTA-STS) | n/a | none |
| `mta-sts.<domain>/.well-known/mta-sts.txt` | HTTPS | none |

## IP / network

| Source | Auth | Notes |
|---|---|---|
| Shodan InternetDB        | none | ports + CVEs + tags per IP — *no key needed* |
| GreyNoise community      | none | per-IP rate limit |
| Spamhaus DROP list       | none | downloaded text file, 1h in-memory cache |
| AbuseIPDB                | optional ABUSEIPDB_API_KEY | 1000/day free |
| IPinfo                   | optional IPINFO_API_TOKEN | 50k/month free |
| Team Cymru WHOIS         | none | ASN / BGP route |
| BGPView API              | none | generous |
| onionoo (Tor Project)    | none | generous |
| reverse DNS (PTR)        | n/a  | n/a |

## Threat-intel

| Source | Auth | Notes |
|---|---|---|
| URLhaus (abuse.ch)   | **ABUSE_CH_API_KEY** (free via auth.abuse.ch) | required as of 2024 |
| ThreatFox (abuse.ch) | **ABUSE_CH_API_KEY** (same) | required |
| PhishTank checkurl   | none | per-URL lookup; bulk feed deprecated |

## Subdomain takeover fingerprints

Built-in, 20 services curated from EdOverflow/can-i-take-over-xyz.
No network beyond the CNAME and the target HTTPS GET.

## Discovery

| Source | Auth |
|---|---|
| Wayback Machine snapshots | none |
| GitHub public user search | optional GITHUB_PAT (5k/h vs 60/h unauthenticated) |
| GitHub public code search | optional GITHUB_PAT |
| Google Dorks (link generator, no scraping) | n/a |

## Optional paid sources we deliberately do NOT use

- Dehashed (paid)
- Snusbase (paid)
- Hunter.io (paid)
- IntelX (paid)
- LeakCheck (paid)

If the user has a key, they can wire one in via the existing
`EmailExtras`-style pattern, but no module ships dependent on them.

## Rate-limit hygiene

The shared `httpx.AsyncClient` caps concurrency via
`HTTP_CONCURRENCY=40`. Each module also picks a local semaphore
appropriate for the source's tolerance (e.g. ThreatMiner gets 1
in-flight; Shodan InternetDB gets 4; the username probe pool gets 30).
In OPSEC mode we additionally jitter 200-800ms per request to defeat
naïve burst-detection.
