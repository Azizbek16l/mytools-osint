# Bluetm Agent

A small autonomous daemon that maintains and promotes `mytools-osint` without
human intervention. Designed for **zero recurring cost** — runs on GitHub
Actions (free for public repos) plus optional self-hosted infra you already
own.

## Honest scope

What it **can** do autonomously:

- Pull upstream OSINT site datasets (Sherlock, WhatsMyName) daily and open a
  PR when new entries appear.
- Run a **canary probe** against a small set of known-good public profiles
  (`torvalds` on GitHub, `@durov` on Telegram, etc.) and file a GitHub issue
  when one starts failing — i.e. the site broke our signature.
- Update `CHANGELOG.md` automatically from `git log` between tags.
- Post a **Telegram channel announcement** when a new release tag is pushed.
- Refresh README badges (downloads, stars, last release).
- Triage incoming GitHub issues with deterministic labels.

What it **cannot** do, despite the hype around "AI agents":

- Sell a product. Sales requires human judgement and trust signals no agent
  can manufacture.
- Write meaningful code improvements without an LLM. There is no free LLM
  with the engineering quality of Claude/GPT-4. Optional Ollama integration
  exists (see below) but the output is rough and needs human review before
  merge — so it's still a PR-proposer, not a merger.
- Promote on platforms that require account login (LinkedIn, X, Reddit, HN)
  without violating ToS. Posting via the official APIs costs money, and
  scraped-login automation gets bans.

The agent is a **release engineer + canary watcher**, not a salesperson.

## Setup (one-time, ~10 minutes)

### 1. Create a dedicated Telegram bot

This bot is **separate from your personal `@8714884501` MTProto session**.
Nothing in the agent touches your real Telegram account.

1. Open <https://t.me/BotFather>
2. Send `/newbot`. Pick a name (e.g. `Bluetm OSINT Agent`) and username (e.g.
   `bluetm_osint_bot`).
3. Copy the bot token BotFather gives you. Looks like
   `1234567890:AAAAxxxx...`.
4. Create a public channel (e.g. `@bluetm_osint`). Add the bot as an admin
   with "Post messages" permission.
5. Save these as GitHub repo secrets:
   - `TELEGRAM_AGENT_BOT_TOKEN`
   - `TELEGRAM_AGENT_CHANNEL` (e.g. `@bluetm_osint`)

### 2. Enable the daily workflow

Already present at `.github/workflows/agent-daily.yml`. Runs at 03:00 UTC.
Trigger manually first via the GitHub Actions UI to confirm everything wires
up before relying on the cron.

### 3. (Optional) Local Ollama hook

If you want autonomous code-improvement proposals (small refactors, comment
cleanups, regex tuning), point the agent at your existing Ollama install on
`root2`:

```
export OLLAMA_HOST=http://192.168.30.4:11434
export OLLAMA_MODEL=qwen2.5-coder:32b
python -m agent.main --task ollama_improvements
```

Without `OLLAMA_HOST` set the LLM tasks are skipped silently — no failure,
no cost.

## Daily workflow

```
03:00 UTC  GH Actions cron fires
  → agent/main.py runs each task in this order:
      1. sync_datasets      (sherlock + whatsmyname)
      2. canary_probe        (verify 10 known profiles)
      3. changelog_update    (sync CHANGELOG with git log)
      4. telegram_announce   (post if a new tag was reached)
      5. badge_update        (refresh README badges)
      6. issue_triage        (label new issues)
  → On any task failure, the workflow opens a GitHub issue with the log.
```

Each task has a timeout. A single failing task does not stop the others —
the agent is best-effort by design.

## Files

```
agent/
├── __init__.py
├── main.py                  # task runner (cron entry point)
├── tasks/
│   ├── sync_datasets.py
│   ├── canary_probe.py
│   ├── changelog_update.py
│   ├── telegram_announce.py
│   ├── badge_update.py
│   ├── issue_triage.py
│   └── ollama_improvements.py  # optional, only runs if OLLAMA_HOST set
└── README.md
```

## Cost ledger

| Resource | Cost | Notes |
|---|---|---|
| GitHub Actions (public repo) | $0 | Unlimited free minutes for public repositories |
| Telegram Bot API | $0 | Free for any volume; we post ~once per release |
| Sherlock / WhatsMyName API | $0 | Public JSON files, no rate limit |
| Ollama (optional) | electricity only | Runs on your existing root2 GPU |

**No subscription. No card on file. No vendor lock-in.**
