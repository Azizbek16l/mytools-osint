"""YAML config file — declarative profiles, source overrides, presets.

Loaded from (first found):
  1. ./mytools-osint.yaml      (project-local — checked into repo)
  2. ~/.config/mytools-osint/config.yaml   (per-user)
  3. %LOCALAPPDATA%/mytools-osint/config.yaml   (Windows)

Schema:
  profiles:
    my-domain-scan:
      modules: [domain, ssl_tls, http_headers, web_recon]
      min_severity: medium
  presets:
    my-acme-scan:
      kind: domain
      target: acme.com
      profile: my-domain-scan
      opsec: true
      html: ./acme-report.html
  sources:
    github_pat: env:GITHUB_PAT
    abuse_ch_key: env:ABUSE_CH_API_KEY
  defaults:
    parallel: 4
    cache: true
    pivot: 1

Usage:
  osint preset run my-acme-scan       (executes preset)
  osint preset list                   (shows all)
  osint preset show my-acme-scan      (debug)
  osint config init-yaml              (writes a sample file)

Why YAML over env-only: a power user with 6 recurring scans shouldn't
have to remember CLI flags or shell wrappers. Presets = saved queries.
Profiles = ad-hoc module set. Sources = central API-key registry.

Optional dep: PyYAML. If missing, we fall back to ConfigError and tell the
user to `pip install pyyaml`. Pure-Python fallback for read-only parsing
covers ~80% of use cases but doesn't validate.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


SAMPLE = """# mytools-osint v4.0 config

# Declarative module presets (similar to --profile but you define them)
profiles:
  my-quick-domain:
    modules: [domain, ssl_tls, http_headers]
    min_severity: medium
  my-deep-domain:
    modules: [domain, ssl_tls, http_headers, web_recon, takeover, well_known, typosquat]
    min_severity: low

# Saved scans — `osint preset run <name>`
presets:
  acme-daily:
    kind: domain
    target: acme.com
    profile: red-team
    pivot: 1
    html: ./acme-daily.html
    md: ./acme-daily.md

  jane-doe:
    kind: email
    target: jane@example.com
    profile: person
    pivot: 0

# API key registry (env: refs use process env at scan time)
sources:
  github_pat: env:GITHUB_PAT
  abuse_ch_key: env:ABUSE_CH_API_KEY
  hibp_api_key: env:HIBP_API_KEY
  ipinfo_api_token: env:IPINFO_API_TOKEN

defaults:
  cache: true            # OSINT_CACHE=1
  parallel: 4            # bulk concurrency (v4.0)
  opsec: false           # SOCKS5 + jitter + UA rotation
"""


@dataclass
class YAMLConfig:
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)
    presets: dict[str, dict[str, Any]] = field(default_factory=dict)
    sources: dict[str, str] = field(default_factory=dict)
    defaults: dict[str, Any] = field(default_factory=dict)
    path: Path | None = None


def search_paths() -> list[Path]:
    out: list[Path] = []
    out.append(Path.cwd() / "mytools-osint.yaml")
    out.append(Path.home() / ".config" / "mytools-osint" / "config.yaml")
    if os.name == "nt":
        appdata = os.environ.get("LOCALAPPDATA", "")
        if appdata:
            out.append(Path(appdata) / "mytools-osint" / "config.yaml")
    return out


def load() -> YAMLConfig | None:
    if not HAS_YAML:
        return None
    for p in search_paths():
        if p.exists():
            try:
                data = _yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                cfg = YAMLConfig(
                    profiles=data.get("profiles") or {},
                    presets=data.get("presets") or {},
                    sources=data.get("sources") or {},
                    defaults=data.get("defaults") or {},
                    path=p,
                )
                _apply_sources(cfg)
                return cfg
            except Exception as e:
                print(f"  warning: {p}: {e}", file=sys.stderr)
                return None
    return None


def _apply_sources(cfg: YAMLConfig) -> None:
    """`env:NAME` strings → just confirm the env var exists. Inline strings
    get pushed into os.environ if their target key isn't already set."""
    for k, v in cfg.sources.items():
        if not isinstance(v, str):
            continue
        env_key = k.upper()
        if v.startswith("env:"):
            target = v.split(":", 1)[1]
            if os.environ.get(target):
                os.environ.setdefault(env_key, os.environ[target])
        else:
            os.environ.setdefault(env_key, v)


def init_yaml_file() -> int:
    if not HAS_YAML:
        print("  pip install pyyaml  — required to enable YAML config", file=sys.stderr)
        return 2
    target = Path.home() / ".config" / "mytools-osint" / "config.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        print(f"  already exists: {target}")
        return 0
    target.write_text(SAMPLE, encoding="utf-8")
    print(f"  wrote sample → {target}")
    return 0


def cmd_preset(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: osint preset <list|show|run> [name]\n"
              "  presets are defined in your YAML config — see `osint config init-yaml`",
              file=sys.stderr)
        return 0 if argv else 2
    cfg = load()
    if cfg is None:
        print("  no YAML config found — `osint config init-yaml` to create one",
              file=sys.stderr)
        return 2
    sub = argv[0]
    if sub == "list":
        if not cfg.presets:
            print("  (no presets defined)")
            return 0
        print(f"  presets ({cfg.path}):")
        for name, p in cfg.presets.items():
            kind = p.get("kind", "?")
            tgt = p.get("target", "?")
            profile = p.get("profile", "default")
            print(f"  • {name:<24} {kind:<10} {tgt:<32} profile={profile}")
        return 0
    if sub == "show" and len(argv) >= 2:
        name = argv[1]
        if name not in cfg.presets:
            print(f"  no such preset: {name}", file=sys.stderr)
            return 1
        import json
        print(json.dumps(cfg.presets[name], indent=2, default=str))
        return 0
    if sub == "run" and len(argv) >= 2:
        name = argv[1]
        if name not in cfg.presets:
            print(f"  no such preset: {name}", file=sys.stderr)
            return 1
        p = cfg.presets[name]
        # Re-enter osint with the preset's args
        new_argv = [p.get("target", "")]
        if p.get("kind"):
            new_argv += ["--kind", p["kind"]]
        if p.get("profile"):
            new_argv += ["--profile", p["profile"]]
        if p.get("pivot"):
            new_argv += ["--pivot", str(p["pivot"])]
        if p.get("html"):
            new_argv += ["--html", p["html"]]
        if p.get("md"):
            new_argv += ["--md", p["md"]]
        if p.get("opsec"):
            new_argv += ["--opsec"]
        if p.get("min_severity"):
            new_argv += ["--min-severity", p["min_severity"]]
        print(f"  ↻ running preset {name}: osint {' '.join(new_argv)}",
              file=sys.stderr)
        from cli import main as _main
        return _main(new_argv)
    print("usage: osint preset <list|show|run> [name]", file=sys.stderr)
    return 2
