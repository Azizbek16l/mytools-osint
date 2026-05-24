# Security policy

## Supported versions

Only the latest minor release of `mytools-osint` receives security fixes.
At time of writing that is **v0.2.x**. Older releases are best-effort.

| Version  | Supported  |
|----------|------------|
| 0.2.x    | ✅          |
| 0.1.x    | ❌ (upgrade)|

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Email:  `azizbektopilboyev7@gmail.com`
PGP:    pull from `https://keys.openpgp.org/vks/v1/by-email/azizbektopilboyev7%40gmail.com`
Subject: `[security] mytools-osint — <short title>`

Include, if possible:
- the version (`osint --version`)
- the affected module or CLI flag
- a minimal reproducer
- the impact (e.g. "RCE via crafted target value", "credential leak in logs")
- your preferred name for the credit (or "anonymous")

I'll acknowledge within **72 hours** and aim to ship a patch within **14 days**
for high-severity issues. Coordinated disclosure timeline can be agreed
case-by-case.

## What counts as a vulnerability here

- RCE / arbitrary file write / SSRF in the tool itself
- Credential leak (any API key the user has configured, ending up in logs,
  reports, or outgoing requests it shouldn't)
- Bypass of the `--opsec` SOCKS proxy (i.e. a request that leaks the user's
  real IP/DNS while OPSEC mode is on)
- Crash via crafted input that wedges the long-running watchlist daemon

## What does NOT count

- A site upstream is rate-limiting you (that's their decision)
- False-positive / false-negative on a username probe (open a normal issue)
- "I can write a malicious .env into my own home directory" (not a vuln)
- "I gave the tool a target I have no authorization for" (out of scope —
  the tool is intended for authorized use)

## Threat model in one paragraph

`mytools-osint` is a *single-user desktop CLI* and a single-user GUI. It
runs with the user's privileges, talks to public OSINT sources, and stores
results in `%LOCALAPPDATA%\mytools-osint\` (Windows) or
`~/.local/share/mytools-osint/` (Linux/macOS). The user is trusted; the
network and remote sources are *not*. Anything coming back from an
upstream source is treated as untrusted bytes (we never `eval()`, never
shell out with concatenated source data, and we cap response sizes to
prevent memory blow-up).

Optional API keys (HIBP / Numverify / IPinfo / abuse.ch / AbuseIPDB) are
stored in `%LOCALAPPDATA%\mytools-osint\config.env` and read into the
Settings dataclass. They never get logged, never get attached to outgoing
requests for sources that didn't ask for them.
