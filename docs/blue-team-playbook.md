# Blue-team playbook — `mytools-osint`

For SOC, IR, and CTI use: assessing your *own* surface, triaging
indicators, and watching for change. Same tool, different lens.

## 1 · Baseline your own surface

Run once on every owned domain:

```bash
osint mycorp.com --profile blue-team --html mycorp-baseline.html
```

The `blue-team` profile covers: SSL/TLS posture, HTTP-headers grade,
SPF/DMARC/DKIM/MTA-STS, subdomain-takeover candidates that you've
forgotten about, typosquat candidates someone *else* has registered,
threat-intel hits against your own IPs (in case you've been compromised
and your IP is now a known C2), Shodan InternetDB exposed surface.

Store the JSON output for later diffing:

```bash
osint mycorp.com --profile blue-team --format json --out baseline.json
```

## 2 · Schedule weekly drift monitoring

```bash
osint watch add domain mycorp.com --label "weekly-mycorp" --every 168
osint watch run                     # nightly cron
```

When `watch run` finds new positives (new subdomain, new CVE on your
public IP, new typosquat registration), it ships a Telegram notification
via the bot you've configured under `osint config`.

## 3 · IOC triage

You got an IP / URL / domain from an alert — is it known-bad?

```bash
osint 198.51.100.42 --profile ioc
osint badsite.example --profile ioc
```

Returns: GreyNoise (scanner / benign / malicious), URLhaus + ThreatFox
(malware C2 / payload), PhishTank (phishing URL), Tor relay/exit?,
Shodan InternetDB (exposed services + CVEs the attacker may be using),
ASN / BGP info (who actually owns the netblock).

Pipe to your SIEM:

```bash
osint 198.51.100.42 --profile ioc --jsonl >> /var/log/ioc-triage.jsonl
```

## 4 · Typosquat & impersonation watch

Run weekly — flags any domain that resembles yours and was registered
since the last run:

```bash
osint mycorp.com --enable typosquat --disable username \
                 --format json --out typosquat-$(date +%F).json
```

Diff this week vs last week for newly-registered impersonations.

## 5 · Email-security drift

```bash
osint mycorp.com --enable email_security --format json --out mail-posture.json
```

You'll catch SPF drift (someone added a `+all` and broke DMARC), missing
DKIM after a mail-relay migration, or DMARC silently downgraded from
`p=reject` to `p=none`.

## 6 · Continuous-monitoring crontab

```cron
# /etc/cron.d/osint-blue-team
# weekly attack-surface baseline + drift notification
0 3 * * 1  ops  osint watch run --all >> /var/log/osint-blue.log 2>&1
# nightly IOC re-check of last 7d alerts
0 4 * * *  ops  /usr/local/bin/ioc-recheck.sh >> /var/log/ioc-recheck.log 2>&1
```

## 7 · Hand-off & escalation

For ticketing / IR write-ups:

```bash
osint <indicator> --profile ioc --html ioc-$(date +%FT%H%M).html
```

Single HTML file you can drop in Jira / Notion / Zendesk — pivot graph
included, no external assets, opens offline.
