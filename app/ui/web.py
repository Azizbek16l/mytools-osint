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
import json
import urllib.parse
from datetime import UTC, datetime

from app.core.config import load_settings
from app.core.profiles import apply_profile
from app.core.runner import runner
from app.core.types import Hit, Query, QueryKind

_BIND = "127.0.0.1"


_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>mytools-osint · web dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {
    --bg:#0a1219; --panel:#0e1822; --panel-2:#142231; --border:#1f2c3a;
    --fg:#e6edf3; --fg-dim:#9ba9b8; --accent:#83c5ff;
    --ok:#7be67b; --warn:#f6c177; --bad:#ff5c5c; --crit:#ff3030;
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
    background:var(--panel); border-bottom:1px solid var(--border); display:flex; gap:18px; }
  #stats b { color:var(--fg); }
  main { padding:0 24px 60px; }
  table { width:100%; border-collapse:collapse; margin-top:8px; }
  th { text-align:left; color:var(--fg-dim); font-weight:500; font-size:10.5px;
    letter-spacing:.12em; padding:10px 8px; border-bottom:1px solid var(--border); }
  td { padding:8px; vertical-align:top; border-bottom:1px solid var(--border); }
  td.sev { width:90px; }
  .pill { display:inline-block; padding:2px 8px; border-radius:10px;
    font-size:10.5px; font-weight:600; text-transform:uppercase; letter-spacing:.05em; }
  .pill.info { color:#8fa1b3; background:#1b2a36; }
  .pill.low  { color:#83c5ff; background:#0e2a40; }
  .pill.medium { color:#f6c177; background:#3a2a10; }
  .pill.high { color:#f47c7c; background:#3a1414; }
  .pill.critical { color:#fff; background:var(--crit); }
  .status { width:90px; color:var(--fg-dim); }
  .src { width:200px; }
  .src b { color:var(--fg); }
  .cat { color:var(--fg-dim); font-size:11px; }
  .url { word-break:break-all; }
  .url a { color:var(--accent); text-decoration:none; }
  .url a:hover { text-decoration:underline; }
  .lat { text-align:right; color:var(--fg-dim); width:60px; }
  tr.status-found td .det { color:var(--fg); }
  tr.status-not_found td, tr.status-no_data td, tr.status-skipped td { color:#5e6b78; }
</style>
</head><body>
<header>
  <h1><span class="brand">▎</span> mytools-osint  <span style="color:var(--fg-dim);font-weight:400">· local web dashboard</span></h1>
</header>
<form id="f">
  <input type="text" id="q" placeholder="target — username · email · +phone · @tg · domain · IP · hash" autofocus>
  <select id="kind">
    <option value="">auto</option>
    <option>username</option><option>email</option><option>phone</option>
    <option>telegram</option><option>whatsapp</option><option>ip</option>
    <option>domain</option><option>password</option><option>hash</option>
  </select>
  <select id="profile">
    <option value="">— profile —</option>
    <option>quick</option><option>deep</option><option>person</option>
    <option>domain-recon</option><option>red-team</option><option>blue-team</option>
    <option>ioc</option><option>creds</option><option>leak-hunt</option>
  </select>
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
<main>
  <table>
    <thead><tr><th>SEV</th><th>STATUS</th><th>SOURCE</th><th>FINDING</th><th>LAT</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
</main>
<script>
const $ = (id) => document.getElementById(id);
let evt = null, n = 0, p = 0, c = 0, t0 = 0, timer = null;
function fmt(d){ return (d ?? '').toString().slice(0, 240); }
function row(h){
  n++;
  if (h.status === 'found') p++;
  if (h.severity === 'critical') c++;
  $('n').textContent = n; $('p').textContent = p; $('c').textContent = c;
  const tr = document.createElement('tr');
  tr.className = 'status-' + h.status;
  tr.innerHTML = `
    <td class="sev"><span class="pill ${h.severity}">${h.severity}</span></td>
    <td class="status">${h.status}</td>
    <td class="src"><b>${fmt(h.source)}</b><br><span class="cat">${fmt(h.category) || '-'}</span></td>
    <td><span class="det">${fmt(h.detail)}</span><br>${h.url ? `<span class="url"><a href="${h.url}" target="_blank" rel="noreferrer">${fmt(h.url)}</a></span>` : ''}</td>
    <td class="lat">${h.latency_ms}ms</td>`;
  $('rows').prepend(tr);
}
function stop(){
  if (evt) { evt.close(); evt = null; }
  if (timer) { clearInterval(timer); timer = null; }
  $('go').disabled = false; $('stop').disabled = true;
  $('state').textContent = 'done';
}
$('f').addEventListener('submit', (e) => {
  e.preventDefault();
  if (evt) evt.close();
  $('rows').innerHTML = '';
  n = p = c = 0; t0 = Date.now();
  $('n').textContent = 0; $('p').textContent = 0; $('c').textContent = 0; $('e').textContent = '0.0s';
  $('state').textContent = 'scanning…';
  $('go').disabled = true; $('stop').disabled = false;
  timer = setInterval(() => $('e').textContent = ((Date.now()-t0)/1000).toFixed(1)+'s', 100);
  const q = encodeURIComponent($('q').value);
  const k = encodeURIComponent($('kind').value);
  const pf = encodeURIComponent($('profile').value);
  evt = new EventSource(`/api/scan?q=${q}&kind=${k}&profile=${pf}`);
  evt.addEventListener('hit', (e) => { try { row(JSON.parse(e.data)); } catch {} });
  evt.addEventListener('done', stop);
  evt.onerror = stop;
});
$('stop').addEventListener('click', stop);
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
    }, default=str, ensure_ascii=False).encode("utf-8")
    return b"event: hit\ndata: " + body + b"\n\n"


async def _handle_scan(qs: dict[str, str], writer: asyncio.StreamWriter) -> None:
    from cli import infer_kind  # local import — cli.py adds repo root to sys.path
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

    async def on_hit(h: Hit) -> None:
        try:
            writer.write(_hit_event(h, query))
            await writer.drain()
        except Exception:
            pass

    try:
        await r.run(query, on_hit=on_hit)
    finally:
        try:
            writer.write(b"event: done\ndata: {}\n\n")
            await writer.drain()
        except Exception:
            pass


async def _handle_index(writer: asyncio.StreamWriter) -> None:
    body = _HTML.encode("utf-8")
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
        # Drain headers
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            if line in (b"\r\n", b"\n", b""):
                break
        method, _, rest = req_line.decode("latin-1").strip().partition(" ")
        path, _, _ = rest.partition(" ")
        if method != "GET":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return
        url = urllib.parse.urlparse(path)
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
        if url.path == "/":
            await _handle_index(writer)
        elif url.path == "/api/scan":
            await _handle_scan(qs, writer)
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
    print(f"  press Ctrl-C to stop\n")
    async with server:
        await server.serve_forever()


def serve(port: int = 8765) -> int:
    load_settings()
    runner()  # warm registry
    try:
        asyncio.run(_run_server(port))
    except KeyboardInterrupt:
        print("\n  stopped.")
    return 0
