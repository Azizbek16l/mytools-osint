"""Opt-in scheduler (Wave D4).

We do NOT run a daemon. Instead, on ``osint schedule install`` we hand the
OS a unit it understands — launchd plist (macOS), systemd-user timer
(Linux), Task Scheduler XML (Windows) — and let the OS invoke an
``osint`` command on schedule. On Linux without systemd-user we print a
crontab snippet rather than silently install one.

Goals:
  * Tolerant of weak machines — every rendered unit specifies low priority
    where the OS supports it.
  * Easy to disable — every install prints the exact removal command.
  * Auditable — renderers are pure (path/cmd in → text out). We only
    invoke launchctl/systemctl/schtasks behind a single ``apply`` call
    that's never run in tests.

Public API:
  * ``Schedule`` — dataclass describing one scheduled job.
  * ``render_launchd_plist(s)`` / ``render_systemd_unit(s)`` /
    ``render_cron_snippet(s)`` / ``render_windows_task_xml(s)`` —
    pure renderers (tested).
  * ``install`` / ``list_installed`` / ``remove`` — high-level CLI
    helpers.
"""
from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
import xml.sax.saxutils as xml_esc
from dataclasses import dataclass
from pathlib import Path

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{1,63}$")


@dataclass(slots=True)
class Schedule:
    """One scheduled job.

    Either ``every_hours`` or ``cron_expr`` must be set. ``cron_expr`` is
    used verbatim — we don't try to translate cron to launchd's calendar
    intervals (too lossy).
    """

    name: str               # filesystem-safe identifier
    osint_bin: str          # absolute path to the osint binary
    command_args: list[str] # e.g. ["case", "resume", "myslug"]
    every_hours: int | None = None
    cron_expr: str | None = None
    description: str = ""

    def __post_init__(self) -> None:
        if not _NAME_RE.match(self.name or ""):
            raise ValueError(
                f"schedule name {self.name!r} must match [a-z0-9][a-z0-9_-]{{1,63}}"
            )
        if not self.osint_bin:
            raise ValueError("osint_bin must be set")
        if not self.command_args:
            raise ValueError("command_args must be non-empty")
        if self.every_hours is None and not self.cron_expr:
            raise ValueError("must set either every_hours or cron_expr")
        if self.every_hours is not None and self.every_hours < 1:
            raise ValueError("every_hours must be >= 1")

    # ---- canonical label/id helpers ---------------------------------------

    @property
    def launchd_label(self) -> str:
        return f"uz.bluetm.osint.{self.name}"

    @property
    def systemd_unit_name(self) -> str:
        return f"osint-{self.name}"

    @property
    def windows_task_path(self) -> str:
        return f"\\\\BlueTM\\\\osint-{self.name}"


# ---------------------------------------------------------------------------
# Renderers — pure text. No filesystem / subprocess.
# ---------------------------------------------------------------------------


def _xml(s: str) -> str:
    return xml_esc.escape(s)


def render_launchd_plist(s: Schedule) -> str:
    """LaunchAgents plist. Lives in ``~/Library/LaunchAgents/<label>.plist``.

    Uses ``StartInterval`` (seconds) for ``every_hours``. ``cron_expr`` is
    rejected here — launchd doesn't speak cron. We emit a comment about it
    so the user knows to use cron on Linux or schtasks on Windows for
    cron-style expressions.
    """
    if s.cron_expr and s.every_hours is None:
        raise ValueError(
            "launchd does not parse cron expressions; pass every_hours "
            "(or use systemd / cron / schtasks)."
        )
    interval_s = (s.every_hours or 1) * 3600
    args_xml = "\n".join(f"    <string>{_xml(a)}</string>"
                          for a in [s.osint_bin, *s.command_args])
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '<dict>\n'
        f'  <key>Label</key>\n  <string>{_xml(s.launchd_label)}</string>\n'
        '  <key>ProgramArguments</key>\n'
        '  <array>\n'
        f'{args_xml}\n'
        '  </array>\n'
        f'  <key>StartInterval</key>\n  <integer>{interval_s}</integer>\n'
        '  <key>RunAtLoad</key>\n  <false/>\n'
        '  <key>ProcessType</key>\n  <string>Background</string>\n'
        '  <key>LowPriorityIO</key>\n  <true/>\n'
        '  <key>Nice</key>\n  <integer>10</integer>\n'
        f'  <key>StandardOutPath</key>\n  <string>/tmp/{_xml(s.systemd_unit_name)}.log</string>\n'
        f'  <key>StandardErrorPath</key>\n  <string>/tmp/{_xml(s.systemd_unit_name)}.err</string>\n'
        '</dict>\n'
        '</plist>\n'
    )


def render_systemd_unit(s: Schedule) -> tuple[str, str]:
    """Return (service_unit, timer_unit). One systemd timer + a service
    pair, both per-user.

    Timer keys: ``OnCalendar=`` if a cron-ish expression is provided
    (translated via simple rules), else ``OnUnitActiveSec=`` for the
    hourly interval. We err on the side of keeping the user's cron string
    as ``OnCalendar=<expr>`` — systemd accepts a subset and rejects the
    rest at unit-load time (not our problem to translate the full
    grammar).
    """
    cmd = " ".join([s.osint_bin, *s.command_args])
    service = (
        f"[Unit]\nDescription=osint schedule: {s.name}\n\n"
        "[Service]\nType=oneshot\n"
        "Nice=10\nIOSchedulingClass=idle\n"
        f"ExecStart={cmd}\n"
    )
    if s.every_hours is not None:
        ts = f"OnUnitActiveSec={s.every_hours}h\nOnBootSec=5min\n"
    else:
        # systemd OnCalendar — pass user expression through verbatim.
        ts = f"OnCalendar={s.cron_expr}\n"
    timer = (
        f"[Unit]\nDescription=osint timer: {s.name}\n\n"
        "[Timer]\n"
        f"{ts}"
        f"Unit={s.systemd_unit_name}.service\n"
        "Persistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )
    return service, timer


def render_cron_snippet(s: Schedule) -> str:
    """Crontab-line for users without systemd. ``cron_expr`` wins;
    ``every_hours`` becomes ``0 */N * * *``.

    We do NOT actually install this — print it and let the user paste it
    into ``crontab -e``. Stealth-installing user cron entries is exactly
    the kind of surprise this tool should never spring.
    """
    if s.cron_expr:
        sched = s.cron_expr
    else:
        h = s.every_hours or 1
        if h == 1:
            sched = "0 * * * *"
        elif h <= 24:
            sched = f"0 */{h} * * *"
        else:
            # > 24h: spread across multiple days at midnight
            sched = f"0 0 */{max(1, h // 24)} * *"
    cmd = " ".join([s.osint_bin, *s.command_args])
    return f"# osint schedule: {s.name}\n{sched} {cmd}\n"


def render_windows_task_xml(s: Schedule) -> str:
    """Windows Task Scheduler XML — registered with
    ``schtasks /create /xml ...``.

    For hourly intervals we use a TimeTrigger with Repetition; for
    cron-style we let the user know cron doesn't translate (caller must
    construct their own trigger XML).
    """
    if s.cron_expr and s.every_hours is None:
        raise ValueError(
            "Windows Task Scheduler does not parse cron expressions; "
            "pass every_hours or hand-roll the XML."
        )
    interval = f"PT{s.every_hours or 1}H"
    args = " ".join(s.command_args)
    return (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        '  <RegistrationInfo>\n'
        f'    <Description>{_xml(s.description or "osint scheduled scan")}</Description>\n'
        '    <Author>BlueTM osint</Author>\n'
        '  </RegistrationInfo>\n'
        '  <Triggers>\n'
        '    <TimeTrigger>\n'
        '      <Repetition>\n'
        f'        <Interval>{interval}</Interval>\n'
        '        <StopAtDurationEnd>false</StopAtDurationEnd>\n'
        '      </Repetition>\n'
        '      <StartBoundary>2026-01-01T03:00:00</StartBoundary>\n'
        '      <Enabled>true</Enabled>\n'
        '    </TimeTrigger>\n'
        '  </Triggers>\n'
        '  <Settings>\n'
        '    <Priority>7</Priority>\n'
        '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n'
        '    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>\n'
        '    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>\n'
        '  </Settings>\n'
        '  <Actions Context="Author">\n'
        '    <Exec>\n'
        f'      <Command>{_xml(s.osint_bin)}</Command>\n'
        f'      <Arguments>{_xml(args)}</Arguments>\n'
        '    </Exec>\n'
        '  </Actions>\n'
        '</Task>\n'
    )


# ---------------------------------------------------------------------------
# Filesystem helpers — paths only; no install side effects in tests.
# ---------------------------------------------------------------------------


def _launchd_plist_path(s: Schedule) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{s.launchd_label}.plist"


def _systemd_unit_dir() -> Path:
    return Path.home() / ".config" / "systemd" / "user"


def _systemd_unit_paths(s: Schedule) -> tuple[Path, Path]:
    base = _systemd_unit_dir()
    return base / f"{s.systemd_unit_name}.service", base / f"{s.systemd_unit_name}.timer"


def _windows_task_xml_path(s: Schedule) -> Path:
    return Path.home() / "AppData" / "Local" / "BlueTM" / f"osint-{s.name}.xml"


# ---------------------------------------------------------------------------
# install / remove / list — best-effort wrappers
# ---------------------------------------------------------------------------


def _detect_platform() -> str:
    sys_name = platform.system()
    if sys_name == "Darwin":
        return "macos"
    if sys_name == "Windows":
        return "windows"
    if sys_name == "Linux":
        # Distinguish systemd-user vs cron fallback.
        if shutil.which("systemctl") and (Path.home() / ".config" / "systemd" / "user").exists():
            return "systemd-user"
        # Heuristic: if systemctl --user works, we'll prefer systemd.
        if shutil.which("systemctl"):
            return "systemd-user"
        return "cron"
    return "cron"


def install_schedule(s: Schedule, *, dry_run: bool = False) -> dict[str, object]:
    """Render the right unit for the current OS and (unless dry_run) load it.

    Returns a dict describing what happened (always — even on dry_run).
    Keys:
      * ``platform``: detected target
      * ``unit_paths``: list of files written (or would be written)
      * ``activate_cmd`` / ``deactivate_cmd``: shell strings the user can run
      * ``executed``: True if we actually attempted to bootstrap/enable
    """
    plat = _detect_platform()
    info: dict[str, object] = {"platform": plat, "unit_paths": [], "executed": False}
    if plat == "macos":
        path = _launchd_plist_path(s)
        text = render_launchd_plist(s)
        info["unit_paths"] = [str(path)]
        info["activate_cmd"] = (
            f"launchctl bootstrap gui/$(id -u) {path}"
        )
        info["deactivate_cmd"] = (
            f"launchctl bootout gui/$(id -u) {path} && rm {path}"
        )
        if not dry_run:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            info["executed"] = _safe_subprocess([
                "launchctl", "bootstrap", f"gui/{_uid()}", str(path),
            ])
        return info
    if plat == "systemd-user":
        srv_path, tmr_path = _systemd_unit_paths(s)
        srv, tmr = render_systemd_unit(s)
        info["unit_paths"] = [str(srv_path), str(tmr_path)]
        info["activate_cmd"] = (
            f"systemctl --user daemon-reload && systemctl --user enable --now {s.systemd_unit_name}.timer"
        )
        info["deactivate_cmd"] = (
            f"systemctl --user disable --now {s.systemd_unit_name}.timer && "
            f"rm {srv_path} {tmr_path}"
        )
        if not dry_run:
            srv_path.parent.mkdir(parents=True, exist_ok=True)
            srv_path.write_text(srv, encoding="utf-8")
            tmr_path.write_text(tmr, encoding="utf-8")
            info["executed"] = (
                _safe_subprocess(["systemctl", "--user", "daemon-reload"]) and
                _safe_subprocess([
                    "systemctl", "--user", "enable", "--now", f"{s.systemd_unit_name}.timer",
                ])
            )
        return info
    if plat == "windows":
        path = _windows_task_xml_path(s)
        text = render_windows_task_xml(s)
        info["unit_paths"] = [str(path)]
        info["activate_cmd"] = (
            f"schtasks /create /tn osint-{s.name} /xml {path}"
        )
        info["deactivate_cmd"] = f"schtasks /delete /tn osint-{s.name} /f"
        if not dry_run:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-16")
            info["executed"] = _safe_subprocess([
                "schtasks", "/create", "/tn", f"osint-{s.name}", "/xml", str(path),
            ])
        return info
    # cron fallback
    snippet = render_cron_snippet(s)
    info["unit_paths"] = []
    info["activate_cmd"] = "crontab -e   # then paste the snippet below"
    info["deactivate_cmd"] = "crontab -e   # then remove the snippet"
    info["cron_snippet"] = snippet
    return info


def _safe_subprocess(cmd: list[str]) -> bool:
    """Run the command and return True iff exit code 0. Never raises.

    Marked ``pragma: no cover`` because tests must NOT actually call this.
    """
    try:
        r = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, timeout=20, check=False,
        )
        return r.returncode == 0
    except Exception:
        return False


def _uid() -> str:
    try:
        import os
        return str(os.getuid())
    except AttributeError:
        return "1000"


def list_installed() -> list[dict[str, object]]:
    """Best-effort discovery of currently-installed osint schedules.

    Walks the known target directories. We do not contact launchctl /
    systemctl / schtasks for state (slow + flaky); the on-disk presence
    of a unit file is good enough.
    """
    found: list[dict[str, object]] = []
    # macOS
    la = Path.home() / "Library" / "LaunchAgents"
    if la.exists():
        for p in la.glob("uz.bluetm.osint.*.plist"):
            found.append({
                "platform": "macos",
                "name": p.stem.split(".")[-1],
                "path": str(p),
            })
    # systemd-user
    sd = _systemd_unit_dir()
    if sd.exists():
        for p in sd.glob("osint-*.timer"):
            found.append({
                "platform": "systemd-user",
                "name": p.stem.removeprefix("osint-"),
                "path": str(p),
            })
    # Windows
    win = Path.home() / "AppData" / "Local" / "BlueTM"
    if win.exists():
        for p in win.glob("osint-*.xml"):
            found.append({
                "platform": "windows",
                "name": p.stem.removeprefix("osint-"),
                "path": str(p),
            })
    return found


def remove_schedule(name: str) -> dict[str, object]:
    """Remove a schedule by name. Returns a summary dict; never raises."""
    # macOS
    la = Path.home() / "Library" / "LaunchAgents" / f"uz.bluetm.osint.{name}.plist"
    if la.exists():
        _safe_subprocess(["launchctl", "bootout", f"gui/{_uid()}", str(la)])
        la.unlink(missing_ok=True)
        return {"platform": "macos", "removed": str(la)}
    # systemd-user
    srv = _systemd_unit_dir() / f"osint-{name}.service"
    tmr = _systemd_unit_dir() / f"osint-{name}.timer"
    if tmr.exists() or srv.exists():
        _safe_subprocess([
            "systemctl", "--user", "disable", "--now", f"osint-{name}.timer",
        ])
        srv.unlink(missing_ok=True)
        tmr.unlink(missing_ok=True)
        return {"platform": "systemd-user", "removed": [str(srv), str(tmr)]}
    # Windows
    win = Path.home() / "AppData" / "Local" / "BlueTM" / f"osint-{name}.xml"
    if win.exists():
        _safe_subprocess(["schtasks", "/delete", "/tn", f"osint-{name}", "/f"])
        win.unlink(missing_ok=True)
        return {"platform": "windows", "removed": str(win)}
    return {"platform": "unknown", "removed": None,
            "note": f"no schedule named {name!r} found"}


# ---------------------------------------------------------------------------
# CLI dispatch — `osint schedule ...`
# ---------------------------------------------------------------------------


def _parse_every(token: str) -> tuple[int | None, str | None]:
    """Parse '6h' / '24h' / cron expr into (every_hours | None, cron | None).

    Anything containing whitespace or non-suffix-h alphabetics is treated
    as a cron expression. Plain ``Nh`` becomes ``every_hours``.
    """
    t = (token or "").strip()
    if not t:
        return None, None
    if re.match(r"^\d+h$", t):
        return int(t[:-1]), None
    if re.match(r"^\d+$", t):
        return int(t), None
    return None, t


def cmd_schedule(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(
            "usage:\n"
            "  osint schedule install <slug-or-target> --every <Nh|cron> "
            "[--profile NAME] [--dry-run]\n"
            "  osint schedule list\n"
            "  osint schedule remove <name>\n\n"
            "  install: emits a launchd plist / systemd unit / Task Scheduler XML\n"
            "  on the host OS. The actual command run is `osint case resume <slug>`\n"
            "  if <slug> is a known case, otherwise `osint <target> --profile <p>`.\n"
            "  On Linux without systemd-user, we print a crontab snippet for you to paste.\n",
            file=sys.stderr,
        )
        return 0 if argv else 2

    sub = argv[0]

    if sub == "list":
        rows = list_installed()
        if not rows:
            print("  (no installed osint schedules found)")
            return 0
        for r in rows:
            print(f"  {r['platform']:<14} {r['name']:<20} {r['path']}")
        return 0

    if sub == "remove":
        if len(argv) < 2:
            print("usage: osint schedule remove <name>", file=sys.stderr)
            return 2
        info = remove_schedule(argv[1])
        if info.get("removed"):
            print(f"  removed: {info}")
            return 0
        print(f"  no schedule found for {argv[1]!r}")
        return 1

    if sub == "install":
        if len(argv) < 2:
            print("usage: osint schedule install <slug-or-target> --every Nh [--profile NAME]",
                  file=sys.stderr)
            return 2
        ident = argv[1]
        rest = argv[2:]
        every: str | None = None
        profile: str | None = None
        dry = False
        i = 0
        while i < len(rest):
            if rest[i] == "--every" and i + 1 < len(rest):
                every = rest[i + 1]; i += 2; continue
            if rest[i] == "--profile" and i + 1 < len(rest):
                profile = rest[i + 1]; i += 2; continue
            if rest[i] == "--dry-run":
                dry = True; i += 1; continue
            i += 1
        if not every:
            print("--every <Nh|cron> is required", file=sys.stderr)
            return 2
        hours, cron = _parse_every(every)

        osint_bin = shutil.which("osint") or sys.argv[0]
        # Build the command. If `ident` looks like a slug (no dot / @ / +),
        # use `case resume`; otherwise treat as a scan target.
        if _looks_like_slug(ident):
            cmd_args = ["case", "resume", ident]
        else:
            cmd_args = [ident]
            if profile:
                cmd_args.extend(["--profile", profile])

        try:
            s = Schedule(
                name=ident if _looks_like_slug(ident) else _sanitise(ident),
                osint_bin=osint_bin,
                command_args=cmd_args,
                every_hours=hours,
                cron_expr=cron,
                description=f"osint scheduled run: {ident}",
            )
        except ValueError as exc:
            print(f"  bad schedule: {exc}", file=sys.stderr)
            return 2

        info = install_schedule(s, dry_run=dry)
        print(f"  platform:        {info['platform']}")
        for p in info.get("unit_paths") or []:
            print(f"  unit:            {p}")
        if "cron_snippet" in info:
            print()
            print("  cron snippet (paste into `crontab -e`):")
            for line in str(info["cron_snippet"]).splitlines():
                print(f"    {line}")
        print()
        print(f"  activate:        {info['activate_cmd']}")
        print(f"  deactivate:      {info['deactivate_cmd']}")
        print()
        if dry:
            print("  (dry-run; nothing written)")
        elif info.get("executed"):
            print("  installed + enabled.")
        elif info["platform"] != "cron":
            print("  unit written but auto-enable did not succeed; run the activate command above.")
        return 0

    print(f"unknown schedule subcommand: {sub!r}", file=sys.stderr)
    return 2


def _looks_like_slug(s: str) -> bool:
    return bool(_NAME_RE.match(s))


def _sanitise(s: str) -> str:
    out = re.sub(r"[^a-z0-9_\-]", "-", s.lower())[:60].strip("-_") or "scan"
    if not out[0].isalnum():
        out = "s" + out
    return out
