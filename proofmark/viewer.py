"""Local web viewer: browse your scan runs in the browser, straight off disk.

`proofmark view` starts a tiny local server (127.0.0.1, random port) and opens a
private, token-gated dashboard. Nothing leaves the machine — it reads the run
records the scanner already wrote. No cloud, no account, no JS build step.
"""
from __future__ import annotations

import json
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from proofmark.audit import RUNS_DIR

_SEVS = ("critical", "high", "medium", "low", "info")


def _sev(f: dict) -> str:
    s = f.get("severity", "info")
    if isinstance(s, dict):
        s = s.get("value", "info")
    return str(s).lower().replace("severity.", "")


def _list_runs(runs_dir: str) -> list[dict]:
    """Summarize every run under runs_dir (newest first)."""
    base = Path(runs_dir)
    out: list[dict] = []
    if not base.is_dir():
        return out
    for d in base.iterdir():
        manifest = d / "run.json"
        if not (d.is_dir() and manifest.exists()):
            continue
        try:
            m = json.loads(manifest.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        findings = m.get("findings") or []
        counts = {s: sum(1 for f in findings if _sev(f) == s) for s in _SEVS}
        out.append({
            "name": d.name,
            "target": m.get("target", ""),
            "model": m.get("model", ""),
            "operator": m.get("operator", ""),
            "started_at": m.get("started_at", ""),
            "finished_at": m.get("finished_at", ""),
            "stopped_reason": m.get("stopped_reason", ""),
            "signed": bool(m.get("signature")),
            "finding_count": len(findings),
            "severity": counts,
        })
    out.sort(key=lambda r: r.get("started_at", ""), reverse=True)
    return out


def _run_manifest(runs_dir: str, name: str) -> dict:
    if not name or "/" in name or ".." in name:
        raise ValueError("bad run name")
    manifest = Path(runs_dir) / name / "run.json"
    return json.loads(manifest.read_text(encoding="utf-8"))


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep the console quiet
        pass

    def _send(self, code: int, ctype: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def _json(self, obj, code=200):
        self._send(code, "application/json", json.dumps(obj, default=str).encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path == "/favicon.ico":
            self._send(204, "image/x-icon", b"")
            return
        if (qs.get("t") or [""])[0] != self.server.token:  # type: ignore[attr-defined]
            self._send(403, "text/plain; charset=utf-8",
                       b"Forbidden: this dashboard needs the token from the printed URL.")
            return
        if parsed.path == "/":
            self._send(200, "text/html; charset=utf-8", _HTML.encode())
        elif parsed.path == "/api/runs":
            self._json(_list_runs(self.server.runs_dir))  # type: ignore[attr-defined]
        elif parsed.path == "/api/run":
            try:
                self._json(_run_manifest(self.server.runs_dir,  # type: ignore[attr-defined]
                                         (qs.get("name") or [""])[0]))
            except (OSError, ValueError) as exc:
                self._json({"error": str(exc)}, code=404)
        else:
            self._send(404, "text/plain; charset=utf-8", b"Not found")


def serve(runs_dir: str = RUNS_DIR, run_name: str | None = None,
          host: str = "127.0.0.1", port: int = 0, open_browser: bool = True) -> None:
    token = secrets.token_urlsafe(24)
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.token = token          # type: ignore[attr-defined]
    httpd.runs_dir = runs_dir    # type: ignore[attr-defined]
    real_port = httpd.server_address[1]
    shown_host = "127.0.0.1" if host in ("127.0.0.1", "localhost") else host
    url = f"http://{shown_host}:{real_port}/?t={token}"
    if run_name:
        url += f"&run={run_name}"

    print(f"Proofmark viewer → {url}")
    if host in ("0.0.0.0", "::"):
        print("  Reachable from other machines. The token in that URL grants read access to your "
              "run data — share it only with trusted users, and firewall the port.")
    if open_browser and host in ("127.0.0.1", "localhost"):
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - a headless box has no browser; the URL still works
            pass
    print("  Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()


_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Proofmark — runs</title>
<style>
:root{--bg:#0b0f14;--panel:#111a22;--panel2:#0e151d;--bd:#20303f;--tx:#e7eef4;--mut:#93a6b6;--faint:#6d8091;--accent:#3ad0be;
--critical:#ff5c62;--high:#ff9f43;--medium:#ffcf5a;--low:#5db4ff;--info:#8fa3b4;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.55 system-ui,-apple-system,sans-serif;display:flex;height:100vh;overflow:hidden}
a{color:var(--accent)}
#side{width:320px;flex:none;border-right:1px solid var(--bd);background:var(--panel2);display:flex;flex-direction:column;overflow:hidden}
#brand{padding:16px 18px;border-bottom:1px solid var(--bd);font-weight:800;letter-spacing:-.02em;font-size:1.05rem;display:flex;align-items:center;gap:8px}
#brand .m{color:var(--accent)}
#runs{overflow-y:auto;flex:1}
.run{padding:12px 16px;border-bottom:1px solid var(--bd);cursor:pointer}
.run:hover{background:var(--panel)}.run.on{background:var(--panel);box-shadow:inset 3px 0 0 var(--accent)}
.run .t{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.run .s{color:var(--mut);font-size:.8rem;margin-top:2px;display:flex;gap:8px;flex-wrap:wrap}
.dots{display:flex;gap:3px;margin-top:6px}.dot{width:9px;height:9px;border-radius:2px}
#main{flex:1;overflow-y:auto;padding:26px 30px}
h1{font-size:1.4rem;margin:0 0 4px;letter-spacing:-.02em}
.meta{color:var(--mut);font-size:.86rem;margin-bottom:18px;display:flex;gap:14px;flex-wrap:wrap}
.sev-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:22px}
.pill{padding:8px 14px;border:1px solid var(--bd);border-radius:10px;background:var(--panel);min-width:84px}
.pill .n{font-size:1.4rem;font-weight:700}.pill .l{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}
.find{border:1px solid var(--bd);border-radius:12px;background:var(--panel);margin-bottom:14px;overflow:hidden}
.fh{padding:14px 16px;display:flex;gap:12px;align-items:flex-start;cursor:pointer}
.badge{font-size:.68rem;font-weight:700;text-transform:uppercase;padding:3px 8px;border-radius:6px;color:#08121a;white-space:nowrap}
.fh .ti{font-weight:600}.fh .lo{color:var(--faint);font-size:.82rem;margin-top:3px}
.fb{padding:0 16px 16px;border-top:1px solid var(--bd);display:none}
.find.open .fb{display:block}
.fb h4{margin:14px 0 5px;font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}
pre{background:#070b0f;border:1px solid var(--bd);border-radius:8px;padding:11px 13px;overflow-x:auto;font:12px/1.5 ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-word}
.tag{display:inline-block;font-size:.72rem;color:var(--mut);border:1px solid var(--bd);border-radius:6px;padding:2px 7px;margin:2px 4px 0 0}
.empty{color:var(--mut);padding:40px;text-align:center}
</style></head><body>
<div id="side"><div id="brand"><span class="m">◈</span> Proofmark <span style="color:var(--mut);font-weight:400">runs</span></div><div id="runs"></div></div>
<div id="main"><div class="empty">Select a run on the left.</div></div>
<script>
const T=new URLSearchParams(location.search).get('t');
const SEV=['critical','high','medium','low','info'];
const col=s=>getComputedStyle(document.documentElement).getPropertyValue('--'+s)||'#888';
const esc=s=>(s==null?'':String(s)).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function j(p){const r=await fetch(p+(p.includes('?')?'&':'?')+'t='+encodeURIComponent(T));return r.json();}
function sevOf(f){let s=f.severity;if(s&&typeof s==='object')s=s.value;return String(s||'info').toLowerCase().replace('severity.','');}
async function loadRuns(){
  const runs=await j('/api/runs');const box=document.getElementById('runs');
  if(!runs.length){box.innerHTML='<div class="empty">No runs yet. Run <code>proofmark scan …</code> first.</div>';return;}
  box.innerHTML=runs.map(r=>{
    const dots=SEV.map(s=>r.severity[s]?`<span class="dot" title="${r.severity[s]} ${s}" style="background:${col(s)}"></span>`:'').join('');
    return `<div class="run" data-n="${esc(r.name)}"><div class="t">${esc(r.target||r.name)}</div>
      <div class="s"><span>${r.finding_count} finding${r.finding_count===1?'':'s'}</span><span>${esc((r.started_at||'').slice(0,16).replace('T',' '))}</span></div>
      <div class="dots">${dots||'<span style="color:var(--faint);font-size:.75rem">clean</span>'}</div></div>`;
  }).join('');
  box.querySelectorAll('.run').forEach(el=>el.onclick=()=>select(el.dataset.n));
  const want=new URLSearchParams(location.search).get('run')||runs[0].name;
  select(want);
}
async function select(name){
  document.querySelectorAll('.run').forEach(e=>e.classList.toggle('on',e.dataset.n===name));
  const m=await j('/api/run?name='+encodeURIComponent(name));const main=document.getElementById('main');
  if(m.error){main.innerHTML='<div class="empty">'+esc(m.error)+'</div>';return;}
  const fs=(m.findings||[]).slice().sort((a,b)=>SEV.indexOf(sevOf(a))-SEV.indexOf(sevOf(b)));
  const counts=SEV.map(s=>({s,n:fs.filter(f=>sevOf(f)===s).length}));
  main.innerHTML=`<h1>${esc(m.target||name)}</h1>
    <div class="meta"><span>engine ${esc(m.model||'?')}</span><span>by ${esc(m.operator||'?')}</span>
      <span>${esc((m.started_at||'').slice(0,19).replace('T',' '))}</span>
      ${m.stopped_reason?'<span>stopped: '+esc(m.stopped_reason)+'</span>':''}${m.signature?'<span>✓ signed</span>':''}</div>
    <div class="sev-row">${counts.map(c=>`<div class="pill"><div class="n" style="color:${c.n?col(c.s):'var(--faint)'}">${c.n}</div><div class="l">${c.s}</div></div>`).join('')}</div>
    ${fs.length?fs.map(findCard).join(''):'<div class="empty">No findings were proven in this run.</div>'}`;
  main.querySelectorAll('.fh').forEach(h=>h.onclick=()=>h.parentElement.classList.toggle('open'));
}
function findCard(f){
  const s=sevOf(f);const ev=(f.evidence||[]).map(e=>typeof e==='string'?e:(e.curl||JSON.stringify(e,null,2))).join('\n\n');
  return `<div class="find"><div class="fh"><span class="badge" style="background:${col(s)}">${s}</span>
    <div style="flex:1"><div class="ti">${esc(f.title)}</div>${f.location?`<div class="lo">${esc(f.location)}</div>`:''}
      <div>${[f.owasp_category,f.cwe,f.confidence?('confidence: '+f.confidence):''].filter(Boolean).map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</div></div></div>
    <div class="fb">${f.description?`<h4>Description</h4><div>${esc(f.description)}</div>`:''}
      ${f.proof_of_concept?`<h4>Proof of concept</h4><pre>${esc(f.proof_of_concept)}</pre>`:''}
      ${ev?`<h4>Evidence</h4><pre>${esc(ev)}</pre>`:''}
      ${f.remediation?`<h4>Remediation</h4><div>${esc(f.remediation)}</div>`:''}</div></div>`;
}
loadRuns();
</script></body></html>"""
