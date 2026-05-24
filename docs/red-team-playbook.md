# Red-team playbook — `mytools-osint`

A short playbook for using `mytools-osint` during an authorized engagement.
Every step here is **passive** (no exploitation, no auth attempts, no
unsolicited traffic to the target). Use this for the reconnaissance phase
of a sanctioned pentest only.

---

## 0 · OPSEC first

If you are recon'ing a sensitive target (one likely to alert on direct
hits from your home/office IP), turn on OPSEC mode before issuing any
query:

```bash
# 1. start Tor (any method — system service, Tor Browser, docker)
sudo systemctl start tor             # Linux
brew services start tor              # macOS

# 2. point the CLI at it (default port 9050)
export TOR_SOCKS=socks5://127.0.0.1:9050

# 3. run every command with --opsec
osint --opsec example.com --profile red-team
```

OPSEC mode forces `socks5h://` (DNS through Tor, no leaks), rotates
User-Agent per request, and adds 200-800ms jitter to defeat trivial
rate-pattern detection.

Verify your egress IP **before** the first real query:

```bash
osint --opsec --kind ip $(curl -s https://api64.ipify.org)
```

---

## 1 · External attack-surface map

Given just the target domain, build the full passive footprint:

```bash
osint example.com --profile domain-recon --html surface.html
```

You now have:
- subdomain list (crt.sh + 7 other passive sources, deduped)
- DNS posture (A/AAAA/MX/TXT/NS/CAA/SOA)
- SSL/TLS grade (cipher suites, protocols, cert chain, OCSP)
- HTTP security-header grade (HSTS, CSP, X-Frame-Options, …)
- tech fingerprint (Wappalyzer-lite, ~30 categories)
- Shodan InternetDB → every resolved IP's open ports + CVEs
- SPF / DMARC / DKIM / MTA-STS A-F grade
- subdomain-takeover candidates (Vercel / Netlify / S3 / Heroku / …)
- typosquat candidates that are **already registered**
- threat-intel matches (URLhaus / ThreatFox / PhishTank)
- Wayback "goldmine" → historical `.env`, `.git`, `/admin`, backup paths
- JS-source secret scan (AWS, GCP, Slack, Stripe, GitHub PAT, JWT, …)

Open `surface.html` in a browser — dark theme, SVG pivot graph showing
target → modules → top sources. Single file, no CDN.

## 2 · People

For each named employee found in step 1 (LinkedIn-derived, footer,
about page, GitHub commits):

```bash
osint alice@example.com --profile person --html alice.html
osint alice --profile person --jsonl >> people.jsonl
```

Covers: breach exposure (XposedOrNot · HudsonRock Cavalier · ProxyNova
ComB), Holehe-style account existence (~10 silent-signup sites), Gravatar,
MX validation, derived-username sweep, PGP key, 1,008-site username probe,
Telegram MTProto phone↔username lookup (your own session), pattern
expansion (alice → alicedev / alice.smith / …).

## 3 · Infra pivot

For each unique IP from step 1 (`jq -r '.extra.ports? as $p | select($p!=null) |
.extra' surface.jsonl | sort -u`):

```bash
osint 198.51.100.42 --profile ioc --jsonl
```

Gives you: Shodan InternetDB (ports + CVE list), GreyNoise classification
(scanner / benign / malicious), Spamhaus DROP, AbuseIPDB (with key),
Tor relay/exit status, ASN/BGP + neighbours via Team Cymru + BGPView.

## 4 · Bulk runs

Got a target list from scope? Run it all once:

```bash
# targets.txt — one per line, # comments OK
cat > targets.txt <<EOF
prod.example.com
staging.example.com
admin.example.com
EOF

osint --bulk targets.txt --profile red-team --bulk-format jsonl > bulk.jsonl

# Then triage with jq:
jq -r 'select(.severity=="critical") | "\(.target)\t\(.module)\t\(.detail)"' bulk.jsonl
```

## 5 · Watchlist + diff (monitor a target over weeks)

```bash
osint watch add domain example.com --label "engagement-X" --every 24
osint watch run                              # poll every hour from cron
osint diff domain example.com                # what changed since last scan?
```

New subdomains, opened ports, dropped TLS certs, popped takeover
candidates — all surface in the diff output.

## 6 · Hand-off

For deliverables:

```bash
# Executive HTML report:
osint example.com --profile red-team --html exec_report.html

# Engineer-friendly JSONL (one Hit per line, easy to feed into Splunk, ELK, …):
osint example.com --profile red-team --jsonl > raw.jsonl

# Raw export of everything (CSV):
osint example.com --profile red-team --format csv --all > full.csv
```

---

## What NOT to do

- **No active exploitation** with this tool. It is a *recon* tool, not
  an exploit framework.
- **No mass scanning** of arbitrary IP ranges. Stick to your scope.
- **No credential validation** against discovered admin panels. Hand
  the URL to your operator, document, move on.
- **No personal data harvesting** outside the engagement scope.

Stay in scope. The CLI's `--bulk` reads exactly the file you point it
at — that file is your audit trail.
