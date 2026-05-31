"""Wave D4 — scheduler renderers.

We only test the rendering paths — never actually invoke launchctl /
systemctl / schtasks (those depend on the test machine and would fight
the real user installation).
"""
from __future__ import annotations

import pytest

from app.features.scheduler import (
    Schedule,
    _parse_every,
    render_cron_snippet,
    render_launchd_plist,
    render_systemd_unit,
    render_windows_task_xml,
)

# ---- Schedule validation ---------------------------------------------------


def test_schedule_rejects_bad_name():
    with pytest.raises(ValueError):
        Schedule(name="bad name", osint_bin="/usr/bin/osint",
                 command_args=["x"], every_hours=6)


def test_schedule_rejects_no_schedule_setting():
    with pytest.raises(ValueError):
        Schedule(name="ok", osint_bin="/usr/bin/osint",
                 command_args=["x"])


def test_schedule_rejects_empty_command_args():
    with pytest.raises(ValueError):
        Schedule(name="ok", osint_bin="/usr/bin/osint",
                 command_args=[], every_hours=6)


def test_schedule_rejects_zero_interval():
    with pytest.raises(ValueError):
        Schedule(name="ok", osint_bin="/usr/bin/osint",
                 command_args=["x"], every_hours=0)


# ---- _parse_every ----------------------------------------------------------


def test_parse_every_hours_form():
    assert _parse_every("6h") == (6, None)
    assert _parse_every("1h") == (1, None)
    assert _parse_every("24") == (24, None)


def test_parse_every_cron_form():
    h, cron = _parse_every("0 3 * * *")
    assert h is None
    assert cron == "0 3 * * *"


def test_parse_every_empty():
    assert _parse_every("") == (None, None)


# ---- launchd ---------------------------------------------------------------


def test_render_launchd_plist_for_case_resume():
    s = Schedule(
        name="acme",
        osint_bin="/Users/me/.osint-venv/bin/osint",
        command_args=["case", "resume", "acme"],
        every_hours=6,
    )
    out = render_launchd_plist(s)
    assert "<?xml version" in out
    assert "<key>Label</key>" in out
    assert "uz.bluetm.osint.acme" in out
    # interval is hours * 3600
    assert "<integer>21600</integer>" in out
    assert "<string>/Users/me/.osint-venv/bin/osint</string>" in out
    assert "<string>case</string>" in out
    assert "<string>resume</string>" in out
    assert "<string>acme</string>" in out
    assert "<key>LowPriorityIO</key>" in out
    assert "<key>Nice</key>" in out
    assert "<key>RunAtLoad</key>" in out


def test_render_launchd_plist_rejects_cron():
    s = Schedule(
        name="acme", osint_bin="/usr/bin/osint",
        command_args=["x"], cron_expr="0 3 * * *",
    )
    with pytest.raises(ValueError):
        render_launchd_plist(s)


def test_render_launchd_plist_rejects_unsafe_args():
    # WP-C: a command arg with shell/XML metacharacters is now rejected at
    # construction time (allowlist), not merely XML-escaped at render time.
    with pytest.raises(ValueError):
        Schedule(
            name="esc",
            osint_bin="/usr/bin/osint",
            command_args=["case", "resume", "<bad&slug>"],
            every_hours=1,
        )


def test_render_launchd_plist_renders_safe_args():
    s = Schedule(
        name="esc",
        osint_bin="/usr/bin/osint",
        command_args=["case", "resume", "good-slug_1"],
        every_hours=1,
    )
    out = render_launchd_plist(s)
    assert "<string>good-slug_1</string>" in out


# ---- systemd ---------------------------------------------------------------


def test_render_systemd_unit_with_hours():
    s = Schedule(
        name="acme",
        osint_bin="/opt/osint/bin/osint",
        command_args=["case", "resume", "acme"],
        every_hours=4,
    )
    svc, tmr = render_systemd_unit(s)
    assert "[Service]" in svc
    assert "Type=oneshot" in svc
    assert "ExecStart=/opt/osint/bin/osint case resume acme" in svc
    assert "Nice=10" in svc
    assert "IOSchedulingClass=idle" in svc

    assert "[Timer]" in tmr
    assert "OnUnitActiveSec=4h" in tmr
    assert "Unit=osint-acme.service" in tmr
    assert "Persistent=true" in tmr
    assert "WantedBy=timers.target" in tmr


def test_render_systemd_unit_with_cron():
    s = Schedule(
        name="acme",
        osint_bin="/opt/osint/bin/osint",
        command_args=["acme.example", "--profile", "domain-recon"],
        cron_expr="0 3 * * *",
    )
    _, tmr = render_systemd_unit(s)
    # WP-C: a raw cron string is NOT valid systemd OnCalendar syntax, so it is
    # translated to calendar form (never emitted verbatim).
    assert "OnCalendar=*-*-* 03:00:00" in tmr
    assert "OnCalendar=0 3 * * *" not in tmr
    assert "OnUnitActiveSec" not in tmr


# ---- cron snippet ----------------------------------------------------------


def test_render_cron_snippet_hourly():
    s = Schedule(
        name="acme", osint_bin="/usr/local/bin/osint",
        command_args=["case", "resume", "acme"],
        every_hours=1,
    )
    out = render_cron_snippet(s)
    assert out.startswith("# osint schedule: acme")
    assert "0 * * * * /usr/local/bin/osint case resume acme" in out


def test_render_cron_snippet_every_6h():
    s = Schedule(
        name="acme", osint_bin="/usr/local/bin/osint",
        command_args=["case", "resume", "acme"],
        every_hours=6,
    )
    assert "0 */6 * * *" in render_cron_snippet(s)


def test_render_cron_snippet_passes_through_cron():
    s = Schedule(
        name="acme", osint_bin="/usr/local/bin/osint",
        command_args=["x"], cron_expr="15 2 * * 1",
    )
    out = render_cron_snippet(s)
    assert "15 2 * * 1 /usr/local/bin/osint x" in out


# ---- Windows ---------------------------------------------------------------


def test_render_windows_task_xml():
    s = Schedule(
        name="acme",
        osint_bin=r"C:\Tools\osint.exe",
        command_args=["case", "resume", "acme"],
        every_hours=12,
    )
    out = render_windows_task_xml(s)
    assert "<Task" in out
    assert "<Interval>PT12H</Interval>" in out
    assert "<Command>C:\\Tools\\osint.exe</Command>" in out
    assert "<Arguments>case resume acme</Arguments>" in out
    assert "<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>" in out


def test_render_windows_task_xml_rejects_cron():
    s = Schedule(
        name="xy", osint_bin="C:\\osint.exe",
        command_args=["a"], cron_expr="0 3 * * *",
    )
    with pytest.raises(ValueError):
        render_windows_task_xml(s)
