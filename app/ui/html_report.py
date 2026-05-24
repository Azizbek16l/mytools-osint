"""Self-contained HTML report — single file, no CDN, no external assets.

Layout: dark-grade neutrals, single accent (azure) per the brand tokens.
Grid: header KPIs, severity stripe, modules-grouped findings table with
expand-on-click extras, and a lightweight inline SVG pivot graph
(target → modules → sources) instead of pulling in vis-network — keeps
the file under ~100 KB regardless of how many hits.

Use:
    from app.ui.html_report import render_report
    html = render_report(query, query_result, elapsed_ms)
    Path("report.html").write_text(html, encoding="utf-8")
"""
from __future__ import annotations

import html
import json
import math
from collections import defaultdict
from datetime import UTC, datetime

from app.core.types import HitStatus, Query, QueryResult  # noqa: I001

_SEV_COLOR = {
    "info":     ("#8fa1b3", "#1b2a36"),
    "low":      ("#83c5ff", "#0e2a40"),
    "medium":   ("#f6c177", "#3a2a10"),
    "high":     ("#f47c7c", "#3a1414"),
    "critical": ("#ff5c5c", "#451010"),
}
_STATUS_DOT = {
    "found": "●", "not_found": "○", "uncertain": "?", "error": "✕",
    "ratelimited": "▲", "unavailable": "~", "no_data": "·", "skipped": "·",
}


def _esc(s: object) -> str:
    return html.escape(str(s) if s is not None else "")


def render_report(query: Query, result: QueryResult, elapsed_ms: int) -> str:
    hits = result.hits
    by_module: dict[str, list] = defaultdict(list)
    for h in hits:
        by_module[h.module].append(h)
    n_total = len(hits)
    n_found = sum(1 for h in hits if h.status == HitStatus.FOUND)
    n_crit = sum(1 for h in hits if h.severity.value == "critical")
    n_high = sum(1 for h in hits if h.severity.value == "high")
    n_med = sum(1 for h in hits if h.severity.value == "medium")
    sev_counts = defaultdict(int)
    for h in hits:
        sev_counts[h.severity.value] += 1

    # --- header KPIs
    kpi_rows = []
    for label, value, color in [
        ("FOUND", n_found, "#7be67b"),
        ("CRITICAL", n_crit, "#ff5c5c"),
        ("HIGH", n_high, "#f47c7c"),
        ("MEDIUM", n_med, "#f6c177"),
        ("TOTAL HITS", n_total, "#8fa1b3"),
        ("DURATION", f"{elapsed_ms} ms", "#83c5ff"),
    ]:
        kpi_rows.append(
            f'<div class="kpi"><div class="kpi-label">{_esc(label)}</div>'
            f'<div class="kpi-value" style="color:{color}">{_esc(value)}</div></div>'
        )

    # --- severity stripe
    total_sev = sum(sev_counts.values()) or 1
    stripe = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = sev_counts.get(sev, 0)
        if n == 0:
            continue
        pct = n / total_sev * 100
        c, _ = _SEV_COLOR[sev]
        stripe.append(f'<div class="stripe-seg" style="width:{pct:.1f}%;background:{c}" '
                      f'title="{n} {sev}"></div>')
    stripe_html = "".join(stripe) or '<div class="stripe-seg" style="width:100%;background:#2a3441"></div>'

    # --- findings table grouped by module
    sections = []
    for mod, items in sorted(by_module.items(), key=lambda kv: -sum(1 for h in kv[1] if h.status == HitStatus.FOUND)):
        n_pos = sum(1 for h in items if h.status == HitStatus.FOUND)
        rows = []
        for h in items:
            sev = h.severity.value
            c, bg = _SEV_COLOR.get(sev, ("#8fa1b3", "#1b2a36"))
            extra_pre = ""
            if h.extra:
                extra_pre = (
                    f'<pre class="extra">{_esc(json.dumps(h.extra, indent=2, default=str)[:4000])}</pre>'
                )
            url_html = (f'<a href="{_esc(h.url)}" target="_blank" rel="noreferrer">'
                        f'{_esc(h.url)[:70]}</a>') if h.url else ""
            rows.append(
                f'<tr class="status-{_esc(h.status.value)}">'
                f'<td class="sev-cell" style="border-left:3px solid {c}">'
                f'  <span class="sev-pill" style="color:{c};background:{bg}">{_esc(sev)}</span></td>'
                f'<td class="status">{_esc(_STATUS_DOT.get(h.status.value, "?"))} {_esc(h.status.value)}</td>'
                f'<td class="source"><b>{_esc(h.source)}</b><br>'
                f'  <span class="cat">{_esc(h.category or "-")}</span></td>'
                f'<td class="detail">{_esc(h.detail)[:300]}<br>{url_html}{extra_pre}</td>'
                f'<td class="latency">{_esc(h.latency_ms)} ms</td>'
                f'</tr>'
            )
        sections.append(
            f'<section class="module">'
            f'  <h2><span class="mod-name">{_esc(mod)}</span> '
            f'  <span class="mod-stats">{n_pos} found / {len(items)} probed</span></h2>'
            f'  <table><thead><tr><th>SEV</th><th>STATUS</th>'
            f'    <th>SOURCE</th><th>FINDING</th><th>LAT</th></tr></thead>'
            f'  <tbody>{"".join(rows)}</tbody></table>'
            f'</section>'
        )

    # --- pivot SVG graph: target (center) → modules (ring) → top sources (outer)
    svg_w, svg_h = 880, 540
    cx, cy = svg_w // 2, svg_h // 2
    mod_list = [m for m in by_module if any(h.status == HitStatus.FOUND for h in by_module[m])]
    mod_list = mod_list[:14]
    nodes = [f'<circle cx="{cx}" cy="{cy}" r="32" fill="#0c1a26" stroke="#83c5ff" stroke-width="2"/>',
             f'<text x="{cx}" y="{cy+4}" text-anchor="middle" fill="#e6edf3" '
             f'font-size="12" font-family="ui-monospace,monospace">{_esc(query.value[:18])}</text>']
    for i, mod in enumerate(mod_list):
        ang = 2 * math.pi * i / max(1, len(mod_list)) - math.pi / 2
        mx = cx + int(math.cos(ang) * 170)
        my = cy + int(math.sin(ang) * 170)
        nodes.append(f'<line x1="{cx}" y1="{cy}" x2="{mx}" y2="{my}" stroke="#2a3441" stroke-width="1"/>')
        nodes.append(f'<circle cx="{mx}" cy="{my}" r="22" fill="#1b2a36" stroke="#83c5ff" stroke-width="1.5"/>')
        label = mod[:9]
        nodes.append(f'<text x="{mx}" y="{my+4}" text-anchor="middle" fill="#e6edf3" '
                     f'font-size="10" font-family="ui-monospace,monospace">{_esc(label)}</text>')
        # outer ring: up to 3 sources per module
        positives = [h for h in by_module[mod] if h.status == HitStatus.FOUND][:3]
        for j, h in enumerate(positives):
            sang = ang + (j - 1) * 0.14
            sx = cx + int(math.cos(sang) * 250)
            sy = cy + int(math.sin(sang) * 250)
            nodes.append(f'<line x1="{mx}" y1="{my}" x2="{sx}" y2="{sy}" '
                         f'stroke="#2a3441" stroke-width="1"/>')
            sev_c, _ = _SEV_COLOR.get(h.severity.value, ("#8fa1b3", "#1b2a36"))
            nodes.append(f'<circle cx="{sx}" cy="{sy}" r="6" fill="{sev_c}"/>')
            nodes.append(f'<text x="{sx}" y="{sy+18}" text-anchor="middle" fill="#9ba9b8" '
                         f'font-size="9" font-family="ui-monospace,monospace">'
                         f'{_esc((h.source or "")[:14])}</text>')
    svg = (f'<svg viewBox="0 0 {svg_w} {svg_h}" width="100%" height="540" '
           f'xmlns="http://www.w3.org/2000/svg">{"".join(nodes)}</svg>')

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>mytools-osint report · {_esc(query.value)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {{
    --bg:#0a1219; --panel:#0e1822; --panel-2:#142231; --border:#1f2c3a;
    --fg:#e6edf3; --fg-dim:#9ba9b8; --accent:#83c5ff;
  }}
  * {{ box-sizing:border-box; }}
  html,body {{ margin:0; background:var(--bg); color:var(--fg);
    font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, monospace; }}
  .wrap {{ max-width:1200px; margin:0 auto; padding:32px 24px 80px; }}
  header.hero {{ border:1px solid var(--border); border-radius:14px;
    background:linear-gradient(180deg,#0e1d2c 0%, var(--panel) 100%);
    padding:24px 28px; margin-bottom:18px; }}
  h1 {{ margin:0 0 4px; font-size:20px; font-weight:600; letter-spacing:.2px; }}
  h1 .brand {{ color:var(--accent); }}
  .target {{ color:var(--fg); font-size:28px; font-weight:600;
    word-break:break-all; margin:6px 0 18px; }}
  .meta {{ color:var(--fg-dim); font-size:12px; }}
  .kpi-row {{ display:grid; grid-template-columns:repeat(6,1fr); gap:10px;
    margin-top:16px; }}
  .kpi {{ background:var(--panel-2); border:1px solid var(--border);
    border-radius:10px; padding:10px 12px; }}
  .kpi-label {{ color:var(--fg-dim); font-size:10.5px; letter-spacing:.12em; }}
  .kpi-value {{ font-size:22px; font-weight:600; margin-top:4px; }}
  .stripe {{ display:flex; height:10px; border-radius:6px; overflow:hidden;
    margin-top:16px; background:#101a25; }}
  .stripe-seg {{ height:100%; transition: filter .2s; }}
  .stripe-seg:hover {{ filter:brightness(1.4); }}

  section.module {{ background:var(--panel); border:1px solid var(--border);
    border-radius:12px; margin:16px 0; overflow:hidden; }}
  section.module h2 {{ margin:0; padding:12px 18px; font-size:13.5px;
    background:var(--panel-2); border-bottom:1px solid var(--border);
    display:flex; justify-content:space-between; align-items:baseline; }}
  .mod-name {{ color:var(--accent); font-weight:600; letter-spacing:.06em; }}
  .mod-stats {{ color:var(--fg-dim); font-size:11px; font-weight:400; }}
  table {{ width:100%; border-collapse:collapse; }}
  th, td {{ padding:8px 12px; text-align:left; vertical-align:top;
    border-top:1px solid var(--border); font-size:12.5px; }}
  th {{ color:var(--fg-dim); font-weight:500; font-size:10.5px;
    letter-spacing:.12em; background:var(--panel-2); border-top:0; }}
  td.sev-cell {{ width:90px; padding-left:14px; }}
  .sev-pill {{ display:inline-block; padding:2px 8px; border-radius:10px;
    font-size:10.5px; letter-spacing:.1em; font-weight:600; text-transform:uppercase; }}
  td.status {{ width:110px; color:var(--fg-dim); white-space:nowrap; }}
  td.source {{ width:200px; }}
  td.source .cat {{ color:var(--fg-dim); font-size:10.5px; }}
  td.detail {{ word-break:break-word; }}
  td.detail a {{ color:var(--accent); text-decoration:none; }}
  td.detail a:hover {{ text-decoration:underline; }}
  td.latency {{ width:70px; text-align:right; color:var(--fg-dim); }}
  pre.extra {{ margin:8px 0 0; padding:8px 10px; background:#091420;
    border:1px solid var(--border); border-radius:6px; font-size:11.5px;
    color:var(--fg-dim); max-height:220px; overflow:auto; }}
  tr.status-found td.detail {{ color:var(--fg); }}
  tr.status-not_found td, tr.status-no_data td, tr.status-skipped td {{ color:#5e6b78; }}

  section.graph {{ margin:16px 0; background:var(--panel); border:1px solid var(--border);
    border-radius:12px; padding:8px 12px 12px; }}
  section.graph h2 {{ font-size:13.5px; color:var(--accent); margin:6px 4px 4px; letter-spacing:.06em; }}
  footer {{ color:var(--fg-dim); text-align:center; margin-top:36px; font-size:11px; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="hero">
    <h1><span class="brand">▎</span> mytools-osint report  <span class="meta">— generated {_esc(now)}</span></h1>
    <div class="target">{_esc(query.value)} <span class="meta">({_esc(query.kind.value)})</span></div>
    <div class="stripe">{stripe_html}</div>
    <div class="kpi-row">{"".join(kpi_rows)}</div>
  </header>

  <section class="graph">
    <h2>pivot graph — target → modules → top sources</h2>
    {svg}
  </section>

  {"".join(sections)}

  <footer>
    mytools-osint · BLUETM·UZ ·
    {_esc(len(by_module))} modules · {_esc(n_total)} hits · {_esc(elapsed_ms)} ms
  </footer>
</div>
</body>
</html>
"""
