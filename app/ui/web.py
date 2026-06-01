"""`osint serve` — minimal local web dashboard.

Stdlib only — no FastAPI, no uvicorn, no extra deps. Uses asyncio + a
hand-rolled HTTP/1.1 + SSE (Server-Sent Events) endpoint.

Endpoints:
  GET /                → dark single-page UI (inline CSS/JS, no CDN)
  GET /api/scan?q=…&kind=…&profile=…
                       → text/event-stream of Hit JSON lines

Listen: localhost only by default. The web UI is intended for the user
themselves — not as a public-facing service.
"""
from __future__ import annotations

import asyncio
import html as _html
import json
import secrets
import urllib.parse
from datetime import UTC, datetime

from app.core.config import load_settings
from app.core.profiles import PROFILES, apply_profile
from app.core.runner import runner
from app.core.types import Hit, Query, QueryKind, QueryResult

_BIND = "127.0.0.1"
# Per-run secret embedded in the page and required on /api/scan. Stops other
# local web pages (or DNS-rebinding) from silently driving scans.
_TOKEN = ""
_PORT = 8765

# Wave C kinds that have no auto-detect branch in cli.infer_kind — surfaced
# in their own optgroup so the user can reach them from the dashboard.
_WAVE_C_KINDS = frozenset({QueryKind.WALLET, QueryKind.IMAGE, QueryKind.COMPANY})
# Profile aliases never offered in the picker (they duplicate "deep"/everything).
_PROFILE_HIDDEN = frozenset({"default", "all"})

# Per-run cooperative-cancel registry: scan-id -> asyncio.Task running r.run().
# A client hitting /api/stop (or whose SSE writer breaks) cancels the Task so
# the runner's TaskGroup tears the in-flight modules down server-side, rather
# than letting the scan run to completion after the browser has navigated away.
_SCANS: dict[str, asyncio.Task[QueryResult]] = {}


def _kind_options() -> str:
    """Build the kind <select> body from QueryKind, never hand-drifted.

    Auto-detectable kinds go in the default group; Wave C kinds (wallet/image/
    company — company has no infer_kind branch) get their own optgroup so they
    are reachable from the UI.
    """
    core = [k for k in QueryKind if k not in _WAVE_C_KINDS]
    wave_c = [k for k in QueryKind if k in _WAVE_C_KINDS]
    parts = ['<option value="">auto</option>']
    for k in core:
        parts.append(f"<option>{_html.escape(k.value)}</option>")
    if wave_c:
        parts.append('<optgroup label="Wave C">')
        parts.extend(f"<option>{_html.escape(k.value)}</option>" for k in wave_c)
        parts.append("</optgroup>")
    return "".join(parts)


def _profile_options() -> str:
    """Build the profile <select> body from PROFILES (incl. dossier + active-recon).

    Generated from the live registry so new profiles appear automatically and
    can never drift from the CLI's notion of what exists.
    """
    names = [p for p in PROFILES if p not in _PROFILE_HIDDEN]
    parts = ['<option value="">— profile —</option>']
    parts.extend(f"<option>{_html.escape(p)}</option>" for p in names)
    return "".join(parts)


_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>mytools-osint · web dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {
    --bg:#0a1219; --panel:#0e1822; --panel-2:#142231; --border:#1f2c3a;
    --fg:#e6edf3; --fg-dim:#9ba9b8; --accent:#83c5ff;
    --ok:#7be67b; --warn:#f6c177; --bad:#ff5c5c;
    /* single critical token shared with the HTML report (#ff5c5c on #451010) */
    --crit:#ff5c5c; --crit-bg:#451010;
    /* dimmed rows: lifted to #7e8a98 for >=4.5:1 contrast on --bg */
    --dim:#7e8a98;
  }
  * { box-sizing:border-box; }
  html,body { margin:0; background:var(--bg); color:var(--fg);
    font: 13.5px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; }
  header { padding:18px 24px; background:var(--panel); border-bottom:1px solid var(--border); }
  header h1 { margin:0; font-size:16px; font-weight:600; }
  header h1 .brand { color:var(--accent); }
  form { padding:14px 24px; background:var(--panel-2); border-bottom:1px solid var(--border);
    display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  input, select, button {
    background:var(--bg); color:var(--fg); border:1px solid var(--border);
    border-radius:6px; padding:7px 10px; font: inherit;
  }
  input[type=text] { flex:1; min-width:260px; }
  button { background:var(--accent); color:var(--bg); font-weight:600; cursor:pointer; }
  button:hover { filter:brightness(1.15); }
  button:disabled { background:#345; color:var(--fg-dim); cursor:not-allowed; }
  #stats { padding:8px 24px; color:var(--fg-dim); font-size:12px;
    background:var(--panel); border-bottom:1px solid var(--border);
    display:flex; gap:18px; flex-wrap:wrap; align-items:center; }
  #stats b { color:var(--fg); }
  /* indeterminate progress bar shown only while scanning */
  #progress { height:3px; background:transparent; overflow:hidden; }
  #progress.on { background:#10202e; }
  #progress.on::after { content:""; display:block; height:100%; width:35%;
    background:var(--accent); animation:slide 1.1s ease-in-out infinite; }
  @keyframes slide { 0%{transform:translateX(-100%);} 100%{transform:translateX(385%);} }
  /* filter chips */
  #filters { padding:8px 24px; background:var(--panel); border-bottom:1px solid var(--border);
    display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  #filters .lbl { color:var(--fg-dim); font-size:11px; letter-spacing:.08em; }
  .chip { background:var(--bg); color:var(--fg-dim); border:1px solid var(--border);
    border-radius:14px; padding:3px 11px; font-size:11px; cursor:pointer; }
  .chip[aria-pressed=true] { background:var(--accent); color:var(--bg); border-color:var(--accent); }
  main { padding:0 24px 60px; }
  table { width:100%; border-collapse:collapse; margin-top:8px; }
  th { text-align:left; color:var(--fg-dim); font-weight:500; font-size:10.5px;
    letter-spacing:.12em; padding:10px 8px; border-bottom:1px solid var(--border); }
  th.sortable { cursor:pointer; user-select:none; }
  th.sortable:hover { color:var(--fg); }
  th .arrow { opacity:.6; font-size:9px; }
  td { padding:8px; vertical-align:top; border-bottom:1px solid var(--border); }
  td.sev { width:104px; }
  .pill { display:inline-block; padding:2px 8px; border-radius:10px;
    font-size:10.5px; font-weight:600; text-transform:uppercase; letter-spacing:.05em; }
  /* leading glyph so severity is never conveyed by colour alone (a11y) */
  .pill .g { font-style:normal; margin-right:4px; }
  .pill.info { color:#8fa1b3; background:#1b2a36; }
  .pill.low  { color:#9cd0ff; background:#0e2a40; }
  .pill.medium { color:#f6c177; background:#3a2a10; }
  .pill.high { color:#f9a7a7; background:#3a1414; }
  .pill.critical { color:#fff; background:var(--crit); }
  .status { width:96px; color:var(--fg-dim); }
  .src { width:200px; }
  .src b { color:var(--fg); }
  .cat { color:var(--fg-dim); font-size:11px; }
  .url { word-break:break-all; }
  .url a { color:var(--accent); text-decoration:none; }
  .url a:hover { text-decoration:underline; }
  .conf { width:100px; }
  .conf .bar { height:5px; border-radius:3px; background:#10202e; overflow:hidden; }
  .conf .fill { display:block; height:100%; background:var(--accent); }
  .conf .pct { font-size:10.5px; color:var(--fg-dim); }
  .evidence { margin:6px 0 0; padding:6px 9px; background:#091420;
    border:1px solid var(--border); border-radius:6px; font-size:11px;
    color:var(--fg-dim); white-space:pre-wrap; word-break:break-word; }
  .lat { text-align:right; color:var(--fg-dim); width:60px; }
  tr.status-found td .det { color:var(--fg); }
  tr.status-not_found td, tr.status-no_data td, tr.status-skipped td { color:var(--dim); }
  tr.hidden { display:none; }
  /* empty-state / skeleton overlay */
  #empty { padding:48px 24px; text-align:center; color:var(--fg-dim); }
  #empty h2 { color:var(--fg); font-size:15px; font-weight:600; margin:0 0 6px; }
  #empty .examples { display:flex; gap:10px; flex-wrap:wrap; justify-content:center; margin-top:16px; }
  #empty .ex { background:var(--panel-2); border:1px solid var(--border); color:var(--accent);
    border-radius:8px; padding:8px 14px; cursor:pointer; font: inherit; font-size:12.5px; }
  #empty .ex:hover { border-color:var(--accent); }
  .skel-row td { border-bottom:1px solid var(--border); }
  .skel { display:block; height:11px; border-radius:5px;
    background:linear-gradient(90deg,#142231 25%,#1c2c3d 37%,#142231 63%);
    background-size:400% 100%; animation:shimmer 1.3s ease infinite; }
  @keyframes shimmer { 0%{background-position:100% 0;} 100%{background-position:-100% 0;} }
  @media (max-width:680px) {
    header, form, #stats, #filters, main { padding-left:14px; padding-right:14px; }
    td.sev, .status, .src, .conf, .lat { width:auto; }
    thead { display:none; }
    table, tbody, tr, td { display:block; width:100%; }
    tr { border-bottom:1px solid var(--border); padding:6px 0; }
    td { border:0; padding:4px 0; }
  }
  @media (prefers-reduced-motion: reduce) {
    #progress.on::after, .skel { animation:none; }
    .skel { background:#142231; }
  }
</style>
</head><body>
<header>
  <h1><span class="brand">▎</span> mytools-osint  <span style="color:var(--fg-dim);font-weight:400">· local web dashboard</span></h1>
</header>
<form id="f">
  <input type="text" id="q" placeholder="target — username · email · +phone · @tg · domain · IP · hash" autofocus>
  <select id="kind" aria-label="query kind">__KIND_OPTIONS__</select>
  <select id="profile" aria-label="scan profile">__PROFILE_OPTIONS__</select>
  <button type="submit" id="go">scan</button>
  <button type="button" id="stop" disabled>stop</button>
</form>
<div id="stats">
  <span>hits: <b id="n">0</b></span>
  <span>found: <b id="p">0</b></span>
  <span>critical: <b id="c">0</b></span>
  <span>elapsed: <b id="e">0.0s</b></span>
  <span id="state" style="color:var(--accent)"></span>
</div>
<div id="progress" aria-hidden="true"></div>
<div id="filters">
  <span class="lbl">FILTER</span>
  <button type="button" class="chip" id="flt-pos" aria-pressed="false">found only</button>
  <button type="button" class="chip" id="flt-crit" aria-pressed="false">critical + high</button>
</div>
<main>
  <table>
    <thead><tr>
      <th class="sortable" data-sort="sev">SEV <span class="arrow"></span></th>
      <th class="sortable" data-sort="status">STATUS <span class="arrow"></span></th>
      <th>SOURCE</th>
      <th class="sortable" data-sort="conf">CONF <span class="arrow"></span></th>
      <th>FINDING</th>
      <th class="sortable" data-sort="lat">LAT <span class="arrow"></span></th>
    </tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <div id="empty"></div>
</main>
<script>
const $ = (id) => document.getElementById(id);
let evt = null, scanId = null, n = 0, p = 0, c = 0, t0 = 0, timer = null;
const SEV_RANK = { critical:5, high:4, medium:3, low:2, info:1, '':0 };
const SEV_GLYPH = { critical:'◆', high:'▲', medium:'●', low:'◇', info:'·' };
let sortKey = null, sortDir = -1, filterPos = false, filterCrit = false;
function fmt(d){ return (d ?? '').toString().slice(0, 240); }
// Only allow http(s) links; reject javascript:/data: etc. (anti-XSS).
function safeUrl(u){ try { const x = new URL(u); return (x.protocol === 'http:' || x.protocol === 'https:') ? x.href : null; } catch { return null; } }
function cell(cls, text){ const td = document.createElement('td'); if (cls) td.className = cls; td.textContent = fmt(text); return td; }
const EXAMPLES = ['octocat', 'jane@example.com', 'example.com', '8.8.8.8'];
function showEmpty(){
  const e = $('empty'); e.innerHTML = '';
  if ($('rows').children.length > 0) { e.style.display = 'none'; return; }
  e.style.display = 'block';
  const h = document.createElement('h2'); h.textContent = 'No scan yet';
  const p2 = document.createElement('div'); p2.textContent = 'Enter a target above, or try an example:';
  const ex = document.createElement('div'); ex.className = 'examples';
  EXAMPLES.forEach(v => {
    const b = document.createElement('button'); b.type = 'button'; b.className = 'ex'; b.textContent = v;
    b.addEventListener('click', () => { $('q').value = v; $('f').requestSubmit(); });
    ex.appendChild(b);
  });
  e.appendChild(h); e.appendChild(p2); e.appendChild(ex);
}
function showNoResults(target){
  const e = $('empty'); e.style.display = 'block'; e.innerHTML = '';
  const h = document.createElement('h2'); h.textContent = 'No findings';
  const p2 = document.createElement('div'); p2.textContent = 'Nothing surfaced for ' + fmt(target) + '.';
  e.appendChild(h); e.appendChild(p2);
}
function addSkeletons(){
  const tb = $('rows');
  for (let i = 0; i < 5; i++) {
    const tr = document.createElement('tr'); tr.className = 'skel-row';
    for (let j = 0; j < 6; j++) {
      const td = document.createElement('td'); const s = document.createElement('span');
      s.className = 'skel'; s.style.width = (45 + (j*9)%50) + '%'; td.appendChild(s); tr.appendChild(td);
    }
    tb.appendChild(tr);
  }
}
function clearSkeletons(){ $('rows').querySelectorAll('.skel-row').forEach(r => r.remove()); }
function applyFilters(tr){
  let hide = false;
  if (filterPos && tr.dataset.status !== 'found') hide = true;
  if (filterCrit && !['critical','high'].includes(tr.dataset.sev)) hide = true;
  tr.classList.toggle('hidden', hide);
}
function row(h){
  clearSkeletons();
  n++;
  if (h.status === 'found') p++;
  if (h.severity === 'critical') c++;
  $('n').textContent = n; $('p').textContent = p; $('c').textContent = c;
  const tr = document.createElement('tr');
  tr.className = 'status-' + (h.status || '');
  tr.dataset.sev = h.severity || '';
  tr.dataset.status = h.status || '';
  tr.dataset.sevrank = SEV_RANK[h.severity] || 0;
  tr.dataset.conf = (h.confidence ?? 0);
  tr.dataset.lat = (h.latency_ms ?? 0);
  // SEV — glyph + label so severity is never colour-only.
  const sevTd = document.createElement('td'); sevTd.className = 'sev';
  const pill = document.createElement('span'); pill.className = 'pill ' + (h.severity || '');
  const g = document.createElement('i'); g.className = 'g'; g.textContent = SEV_GLYPH[h.severity] || '·';
  pill.appendChild(g); pill.appendChild(document.createTextNode(h.severity || ''));
  sevTd.appendChild(pill); tr.appendChild(sevTd);
  tr.appendChild(cell('status', h.status));
  const srcTd = document.createElement('td'); srcTd.className = 'src';
  const b = document.createElement('b'); b.textContent = fmt(h.source); srcTd.appendChild(b);
  srcTd.appendChild(document.createElement('br'));
  const cat = document.createElement('span'); cat.className = 'cat'; cat.textContent = fmt(h.category) || '-'; srcTd.appendChild(cat);
  tr.appendChild(srcTd);
  // CONFIDENCE — bar + percent
  const confTd = document.createElement('td'); confTd.className = 'conf';
  if (h.confidence != null) {
    const pct = Math.round(Math.max(0, Math.min(1, h.confidence)) * 100);
    const bar = document.createElement('div'); bar.className = 'bar';
    bar.setAttribute('role', 'meter'); bar.setAttribute('aria-valuenow', String(pct));
    bar.setAttribute('aria-label', 'confidence ' + pct + '%');
    const fill = document.createElement('span'); fill.className = 'fill'; fill.style.width = pct + '%';
    bar.appendChild(fill); confTd.appendChild(bar);
    const ptxt = document.createElement('span'); ptxt.className = 'pct'; ptxt.textContent = pct + '%';
    confTd.appendChild(ptxt);
  }
  tr.appendChild(confTd);
  const findTd = document.createElement('td');
  const det = document.createElement('span'); det.className = 'det'; det.textContent = fmt(h.detail); findTd.appendChild(det);
  const su = safeUrl(h.url);
  if (su) {
    findTd.appendChild(document.createElement('br'));
    const sp = document.createElement('span'); sp.className = 'url';
    const a = document.createElement('a'); a.href = su; a.target = '_blank'; a.rel = 'noreferrer'; a.textContent = fmt(su);
    sp.appendChild(a); findTd.appendChild(sp);
  }
  // EVIDENCE — producer signals, safe-DOM (textContent only, no innerHTML).
  if (h.evidence && typeof h.evidence === 'object') {
    const keys = Object.keys(h.evidence);
    if (keys.length) {
      const ev = document.createElement('div'); ev.className = 'evidence';
      ev.textContent = keys.map(k => k + ': ' + h.evidence[k]).join('\n');
      findTd.appendChild(ev);
    }
  }
  tr.appendChild(findTd);
  tr.appendChild(cell('lat', (h.latency_ms ?? '') + 'ms'));
  applyFilters(tr);
  $('rows').prepend(tr);
}
function sortRows(){
  if (!sortKey) return;
  const tb = $('rows');
  const rows = [...tb.querySelectorAll('tr:not(.skel-row)')];
  const key = sortKey === 'sev' ? 'sevrank' : sortKey;
  rows.sort((a, b) => (Number(a.dataset[key]) - Number(b.dataset[key])) * sortDir);
  rows.forEach(r => tb.appendChild(r));
}
function stop(){
  if (evt) { evt.close(); evt = null; }
  if (timer) { clearInterval(timer); timer = null; }
  clearSkeletons();
  $('progress').className = '';
  $('go').disabled = false; $('stop').disabled = true;
  $('state').textContent = 'done';
  // Best-effort server-side cooperative cancel (does not wait for the response).
  if (scanId) { try { fetch('/api/stop?id=' + encodeURIComponent(scanId) + '&token=__TOKEN__', {keepalive:true}); } catch {} }
  if (n === 0) showNoResults($('q').value); else $('empty').style.display = 'none';
}
$('f').addEventListener('submit', (e) => {
  e.preventDefault();
  if (!$('q').value.trim()) { $('q').focus(); return; }
  if (evt) evt.close();
  $('rows').innerHTML = ''; $('empty').style.display = 'none';
  n = p = c = 0; t0 = Date.now();
  $('n').textContent = 0; $('p').textContent = 0; $('c').textContent = 0; $('e').textContent = '0.0s';
  $('state').textContent = 'scanning…';
  $('progress').className = 'on';
  $('go').disabled = true; $('stop').disabled = false;
  addSkeletons();
  timer = setInterval(() => $('e').textContent = ((Date.now()-t0)/1000).toFixed(1)+'s', 100);
  scanId = (crypto && crypto.randomUUID) ? crypto.randomUUID() : String(Date.now()) + Math.random();
  const q = encodeURIComponent($('q').value);
  const k = encodeURIComponent($('kind').value);
  const pf = encodeURIComponent($('profile').value);
  evt = new EventSource(`/api/scan?q=${q}&kind=${k}&profile=${pf}&id=${scanId}&token=__TOKEN__`);
  evt.addEventListener('hit', (e) => { try { row(JSON.parse(e.data)); } catch {} });
  evt.addEventListener('done', stop);
  evt.onerror = stop;
});
$('stop').addEventListener('click', stop);
document.querySelectorAll('th.sortable').forEach(th => th.addEventListener('click', () => {
  const k = th.dataset.sort;
  if (sortKey === k) sortDir = -sortDir; else { sortKey = k; sortDir = -1; }
  document.querySelectorAll('th .arrow').forEach(a => a.textContent = '');
  th.querySelector('.arrow').textContent = sortDir < 0 ? '▼' : '▲';
  sortRows();
}));
$('flt-pos').addEventListener('click', () => {
  filterPos = !filterPos; $('flt-pos').setAttribute('aria-pressed', String(filterPos));
  $('rows').querySelectorAll('tr:not(.skel-row)').forEach(applyFilters);
});
$('flt-crit').addEventListener('click', () => {
  filterCrit = !filterCrit; $('flt-crit').setAttribute('aria-pressed', String(filterCrit));
  $('rows').querySelectorAll('tr:not(.skel-row)').forEach(applyFilters);
});
showEmpty();
</script>
</body></html>
"""


def _hit_event(h: Hit, q: Query) -> bytes:
    body = json.dumps({
        "ts": (h.found_at or datetime.now(UTC)).isoformat(),
        "kind": q.kind.value,
        "target": q.value,
        "module": h.module,
        "source": h.source,
        "category": h.category,
        "status": h.status.value,
        "severity": h.severity.value,
        "title": h.title,
        "detail": h.detail,
        "url": h.url,
        "latency_ms": h.latency_ms,
        # v1.1 — provenance so the dashboard can render a confidence bar +
        # the producer's evidence signals (the report already had the data).
        "confidence": h.confidence,
        "evidence": h.evidence,
    }, default=str, ensure_ascii=False).encode("utf-8")
    return b"event: hit\ndata: " + body + b"\n\n"


async def _handle_scan(qs: dict[str, str], writer: asyncio.StreamWriter) -> None:
    from cli import infer_kind  # local import — cli.py adds repo root to sys.path
    if not secrets.compare_digest(qs.get("token", ""), _TOKEN):
        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 13\r\n\r\nbad token")
        await writer.drain(); return
    q_value = qs.get("q", "").strip()
    if not q_value:
        writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 17\r\n\r\nmissing ?q=")
        await writer.drain(); return
    kind_str = qs.get("kind", "")
    kind = QueryKind(kind_str) if kind_str else infer_kind(q_value)
    query = Query(kind=kind, value=q_value)
    r = runner()
    if qs.get("profile"):
        try:
            apply_profile(r, qs["profile"])
        except ValueError:
            pass

    headers = (b"HTTP/1.1 200 OK\r\n"
               b"Content-Type: text/event-stream\r\n"
               b"Cache-Control: no-cache\r\n"
               b"Connection: keep-alive\r\n"
               b"X-Accel-Buffering: no\r\n"
               b"\r\n")
    writer.write(headers)
    await writer.drain()

    scan_id = qs.get("id", "")
    scan_task: asyncio.Task[QueryResult] | None = None

    async def on_hit(h: Hit) -> None:
        # If the client has gone away the write/drain raises — cancel the
        # in-flight runner Task so its TaskGroup tears the modules down
        # server-side instead of running the whole scan to completion.
        try:
            writer.write(_hit_event(h, query))
            await writer.drain()
        except Exception:
            if scan_task is not None:
                scan_task.cancel()

    try:
        scan_task = asyncio.create_task(r.run(query, on_hit=on_hit))
        if scan_id:
            _SCANS[scan_id] = scan_task
        await scan_task
    except asyncio.CancelledError:
        # /api/stop or a dead client cancelled us — swallow; the runner's
        # TaskGroup already cancelled its child module tasks cooperatively.
        pass
    finally:
        if scan_id:
            _SCANS.pop(scan_id, None)
        try:
            writer.write(b"event: done\ndata: {}\n\n")
            await writer.drain()
        except Exception:
            pass


async def _handle_stop(qs: dict[str, str], writer: asyncio.StreamWriter) -> None:
    """Cooperatively cancel an in-flight scan by id (sent on client 'stop')."""
    if not secrets.compare_digest(qs.get("token", ""), _TOKEN):
        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nbad token")
        await writer.drain(); return
    task = _SCANS.get(qs.get("id", ""))
    if task is not None and not task.done():
        task.cancel()
    writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    await writer.drain()


async def _handle_index(writer: asyncio.StreamWriter) -> None:
    body = (
        _HTML.replace("__KIND_OPTIONS__", _kind_options())
        .replace("__PROFILE_OPTIONS__", _profile_options())
        .replace("__TOKEN__", _TOKEN)
    ).encode("utf-8")
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    writer.write(body)
    await writer.drain()


async def _handle_404(writer: asyncio.StreamWriter) -> None:
    writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nnot found")
    await writer.drain()


async def _serve_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        req_line = await asyncio.wait_for(reader.readline(), timeout=10)
        # Read headers, capturing Host for an anti-DNS-rebinding check.
        host_hdr = ""
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            if line in (b"\r\n", b"\n", b""):
                break
            name, _, value = line.decode("latin-1").partition(":")
            if name.strip().lower() == "host":
                host_hdr = value.strip().lower()
        method, _, rest = req_line.decode("latin-1").strip().partition(" ")
        path, _, _ = rest.partition(" ")
        if method != "GET":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return
        # Only accept loopback Host values — a rebinding/foreign Host is rejected.
        # An ABSENT Host (HTTP/1.0 / hand-rolled client) is also rejected: skipping
        # the check on a missing header was the anti-rebind bypass.
        allowed_hosts = {f"127.0.0.1:{_PORT}", f"localhost:{_PORT}", "127.0.0.1", "localhost"}
        if host_hdr not in allowed_hosts:
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nbad host")
            await writer.drain()
            return
        url = urllib.parse.urlparse(path)
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
        if url.path == "/":
            await _handle_index(writer)
        elif url.path == "/api/scan":
            await _handle_scan(qs, writer)
        elif url.path == "/api/stop":
            await _handle_stop(qs, writer)
        else:
            await _handle_404(writer)
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _run_server(port: int) -> None:
    server = await asyncio.start_server(_serve_client, _BIND, port)
    addr = server.sockets[0].getsockname()
    url = f"http://{addr[0]}:{addr[1]}/"
    print(f"  mytools-osint web dashboard → {url}")
    print("  press Ctrl-C to stop\n")
    async with server:
        await server.serve_forever()


def serve(port: int = 8765) -> int:
    global _TOKEN, _PORT
    _TOKEN = secrets.token_urlsafe(24)
    _PORT = port
    load_settings()
    runner()  # warm registry
    try:
        asyncio.run(_run_server(port))
    except KeyboardInterrupt:
        print("\n  stopped.")
    return 0
