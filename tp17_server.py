"""
TP17 — Security ReAct Agent · Web Server
Run:  python tp17_server.py
Open: http://localhost:8000
"""

import asyncio
import json
import os
import queue
import sys
import threading

# ── .env loader ──────────────────────────────────────────────
def _load_dotenv():
    try:
        from dotenv import load_dotenv; load_dotenv(); return
    except ImportError:
        pass
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_dotenv()

if not os.getenv("ANTHROPIC_API_KEY"):
    print("\n[ERROR] ANTHROPIC_API_KEY not set.")
    print("  Add to .env:  ANTHROPIC_API_KEY=sk-ant-...\n")
    sys.exit(1)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse

from tp17_react_security_agent import react_agent_stream, SCENARIOS, check_tools

app = FastAPI(title="Security ReAct Agent")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ============================================================
# API
# ============================================================

@app.get("/tools-status")
async def tools_status():
    return check_tools()

@app.get("/scenario/{key}")
async def get_scenario(key: str):
    task = SCENARIOS.get(key)
    if not task:
        return {"error": f"Unknown scenario '{key}'", "available": list(SCENARIOS)}
    return {"key": key, "task": task}

@app.get("/stream")
async def stream_agent(task: str):
    q: queue.Queue = queue.Queue()

    def run():
        try:
            for event in react_agent_stream(task):
                q.put(event)
        except Exception as exc:
            q.put({"type": "error", "text": str(exc)})
        finally:
            q.put(None)

    threading.Thread(target=run, daemon=True).start()

    async def generate():
        loop = asyncio.get_event_loop()
        while True:
            event = await loop.run_in_executor(None, q.get)
            if event is None:
                yield "data: " + json.dumps({"type": "done"}) + "\n\n"
                break
            yield "data: " + json.dumps(event) + "\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTML


# ============================================================
# EMBEDDED UI
# ============================================================

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security ReAct Agent</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}

:root{
  --bg:#0a0e1a; --sb:#0d1117; --card:#161b22; --border:#30363d;
  --accent:#58a6ff; --muted:#8b949e; --text:#e6edf3;
  --thought:#f0883e; --tool:#58a6ff; --result:#3fb950;
  --final:#a5d6ff; --err:#f85149; --warn:#d29922;
  --mono:'JetBrains Mono','Fira Code','Cascadia Code','Courier New',monospace;
  --ui:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
}

body{font-family:var(--ui);background:var(--bg);color:var(--text);
     height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* ── topbar ── */
.topbar{
  display:flex;align-items:center;gap:14px;padding:0 18px;
  height:50px;background:var(--sb);border-bottom:1px solid var(--border);
  flex-shrink:0;
}
.logo{font-size:15px;font-weight:700;color:var(--accent);letter-spacing:.3px}
.sub{font-size:11px;color:var(--muted);font-family:var(--mono)}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:10px}

.status-wrap{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted);transition:background .3s}
.dot.running{background:var(--result);animation:pulse 1.2s ease-in-out infinite}
.dot.done{background:var(--accent)}
.dot.error{background:var(--err)}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.75)}}

.clear-btn{
  padding:5px 12px;background:transparent;border:1px solid var(--border);
  border-radius:6px;color:var(--muted);font-size:12px;cursor:pointer;
  transition:all .15s
}
.clear-btn:hover{border-color:var(--err);color:var(--err)}

/* ── layout ── */
.body{display:flex;flex:1;overflow:hidden}

/* ── sidebar ── */
.sidebar{
  width:262px;flex-shrink:0;background:var(--sb);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;overflow-y:auto;
  padding:14px 10px;gap:16px
}
.sidebar::-webkit-scrollbar{width:4px}
.sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px}

.sec{font-size:10px;font-weight:700;letter-spacing:1.2px;
     text-transform:uppercase;color:var(--muted);margin-bottom:6px;padding:0 4px}

/* scenario buttons */
.scn{
  display:flex;align-items:flex-start;gap:9px;
  width:100%;padding:9px 10px;border:1px solid transparent;
  border-radius:8px;background:transparent;color:var(--text);
  font-size:12px;font-family:var(--ui);cursor:pointer;text-align:left;
  transition:all .15s;margin-bottom:3px
}
.scn:hover{background:var(--card);border-color:var(--border)}
.scn.active{background:rgba(88,166,255,.08);border-color:rgba(88,166,255,.3);color:var(--accent)}
.scn .ico{font-size:16px;flex-shrink:0;margin-top:1px}
.scn .nm{font-weight:600;display:block}
.scn .ht{font-size:10px;color:var(--muted);display:block;margin-top:2px;line-height:1.3}
.scn.active .ht{color:rgba(88,166,255,.55)}

.div{height:1px;background:var(--border);margin:2px 0}

/* custom query */
.qwrap{display:flex;flex-direction:column;gap:7px}
textarea.qbox{
  width:100%;min-height:82px;padding:9px 11px;
  background:#0a0e1a;border:1px solid var(--border);border-radius:8px;
  color:var(--text);font-size:12px;font-family:var(--ui);
  resize:vertical;outline:none;line-height:1.6
}
textarea.qbox:focus{border-color:var(--accent)}
textarea.qbox::placeholder{color:var(--muted)}

.run-btn{
  width:100%;padding:9px;background:var(--accent);border:none;
  border-radius:8px;color:#0a0e1a;font-size:13px;font-weight:700;
  cursor:pointer;letter-spacing:.2px;transition:opacity .15s,transform .1s
}
.run-btn:hover{opacity:.85}
.run-btn:active{transform:scale(.98)}
.run-btn:disabled{opacity:.3;cursor:not-allowed}

/* tool status */
.ts-row{display:flex;align-items:center;gap:7px;padding:3px 4px;font-size:11px}
.ts-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.ts-dot.ok{background:var(--result)}
.ts-dot.miss{background:var(--border)}
.ts-name{color:var(--text);flex:1;font-family:var(--mono)}
.ts-miss{font-size:10px;color:var(--muted)}

/* ── console ── */
.console{flex:1;display:flex;flex-direction:column;overflow:hidden}
.console-bar{
  padding:7px 18px;border-bottom:1px solid var(--border);
  font-size:11px;font-family:var(--mono);color:var(--muted);
  flex-shrink:0;display:flex;align-items:center;gap:8px;background:#0d1117
}
.prompt{color:var(--result)}
.cmdline{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.feed{
  flex:1;overflow-y:auto;padding:18px 20px;
  display:flex;flex-direction:column;gap:10px
}
.feed::-webkit-scrollbar{width:6px}
.feed::-webkit-scrollbar-thumb{background:#30363d;border-radius:3px}

/* ── welcome ── */
.welcome{
  display:flex;flex-direction:column;align-items:center;
  justify-content:center;height:100%;gap:8px;color:var(--muted);text-align:center
}
.welcome .big{font-size:50px;margin-bottom:4px}
.welcome h2{font-size:19px;color:var(--text);font-weight:600}
.welcome p{font-size:13px}
.welcome .kbd{
  margin-top:14px;padding:8px 18px;background:var(--card);
  border:1px solid var(--border);border-radius:8px;
  font-size:12px;font-family:var(--mono);color:var(--muted)
}

/* ── run header ── */
.run-hdr{
  display:flex;align-items:center;gap:10px;
  padding:8px 12px;background:rgba(88,166,255,.05);
  border:1px solid rgba(88,166,255,.15);border-radius:8px;
  font-size:12px;font-family:var(--mono)
}
.run-hdr .ts{color:var(--muted);flex-shrink:0}
.run-hdr .task-txt{color:var(--accent);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.run-hdr .badge-run{
  margin-left:auto;flex-shrink:0;padding:2px 8px;
  background:rgba(88,166,255,.12);border:1px solid rgba(88,166,255,.25);
  border-radius:4px;font-size:10px;color:var(--accent)
}

/* ── event cards ── */
.card{
  border-radius:9px;border:1px solid var(--border);
  background:var(--card);overflow:hidden;
  animation:fadeUp .2s ease-out
}
@keyframes fadeUp{
  from{opacity:0;transform:translateY(8px)}
  to{opacity:1;transform:translateY(0)}
}

.ch{
  display:flex;align-items:center;gap:8px;padding:8px 13px;
  border-bottom:1px solid var(--border);
  font-size:10px;font-weight:700;letter-spacing:.7px;text-transform:uppercase
}
.ch .ico{font-size:13px}
.cb{padding:11px 13px;font-size:13px;line-height:1.65}

/* thought */
.thought .ch{color:var(--thought)}
.thought{border-color:rgba(240,136,62,.2)}

/* tool call */
.tcall .ch{color:var(--tool)}
.tcall{border-color:rgba(88,166,255,.2)}

.badge{
  background:rgba(88,166,255,.1);border:1px solid rgba(88,166,255,.25);
  border-radius:4px;padding:1px 7px;font-family:var(--mono);font-size:11px;color:var(--tool)
}

.pblock{
  background:#0a0e1a;border:1px solid var(--border);border-radius:6px;
  padding:9px 11px;font-family:var(--mono);font-size:11px;
  margin-top:7px;overflow-x:auto
}
.prow{display:flex;gap:12px;margin-bottom:3px}
.pk{color:var(--muted);flex-shrink:0;min-width:80px}
.pv{color:var(--accent);word-break:break-all;white-space:pre-wrap}

/* result */
.tresult .ch{color:var(--result)}
.tresult{border-color:rgba(63,185,80,.2)}

.rpre{
  background:#0a0e1a;border:1px solid var(--border);border-radius:6px;
  padding:9px 11px;font-family:var(--mono);font-size:11px;
  color:var(--result);overflow:auto;max-height:240px;
  white-space:pre-wrap;word-break:break-word;margin-top:7px
}

.rpre.raw-err{color:var(--err)}

.result-footer{
  display:flex;align-items:center;gap:10px;margin-top:5px
}
.more-btn{
  font-size:10px;color:var(--muted);background:none;
  border:none;cursor:pointer;text-decoration:underline;padding:0
}
.more-btn:hover{color:var(--text)}
.copy-btn{
  font-size:10px;padding:2px 8px;background:transparent;
  border:1px solid var(--border);border-radius:4px;
  color:var(--muted);cursor:pointer;transition:all .15s;margin-left:auto
}
.copy-btn:hover{border-color:var(--accent);color:var(--accent)}

/* final */
.final{border-color:rgba(165,214,255,.2);background:rgba(165,214,255,.03)}
.final .ch{color:var(--final)}
.final .cb{font-size:14px;line-height:1.75}

/* error */
.errc{border-color:rgba(248,81,73,.2)}
.errc .ch{color:var(--err)}

/* step separator */
.step-sep{
  display:flex;align-items:center;gap:10px;
  font-size:10px;font-family:var(--mono);color:var(--muted);margin:2px 0
}
.step-sep::before,.step-sep::after{content:'';flex:1;height:1px;background:var(--border)}
</style>
</head>
<body>

<!-- topbar -->
<div class="topbar">
  <span class="logo">🛡️ Security ReAct Agent</span>
  <span class="sub">ReAct · nmap · osquery · splunk · metasploit</span>
  <div class="topbar-right">
    <button class="clear-btn" onclick="clearHistory()">⌫ Clear</button>
    <div class="status-wrap">
      <div class="dot" id="dot"></div>
      <span id="stxt">Ready</span>
    </div>
  </div>
</div>

<div class="body">

  <!-- sidebar -->
  <aside class="sidebar">
    <div>
      <div class="sec">Scenarios</div>
      <button class="scn" data-key="recon" onclick="runScenario(this)">
        <span class="ico">🔍</span>
        <span><span class="nm">Recon Scan</span>
              <span class="ht">nmap + DNS + osquery surface map</span></span>
      </button>
      <button class="scn" data-key="web_audit" onclick="runScenario(this)">
        <span class="ico">🌐</span>
        <span><span class="nm">Web Audit</span>
              <span class="ht">nmap + HTTP probe, headers, tech stack</span></span>
      </button>
      <button class="scn" data-key="brute_force_hunt" onclick="runScenario(this)">
        <span class="ico">🔐</span>
        <span><span class="nm">Brute Force Hunt</span>
              <span class="ht">Splunk: failed auth, top attacking IPs</span></span>
      </button>
      <button class="scn" data-key="vuln_scan" onclick="runScenario(this)">
        <span class="ico">⚡</span>
        <span><span class="nm">Vuln Scan</span>
              <span class="ht">nmap vuln scripts + Metasploit MS17-010</span></span>
      </button>
      <button class="scn" data-key="host_audit" onclick="runScenario(this)">
        <span class="ico">🖥️</span>
        <span><span class="nm">Host Audit</span>
              <span class="ht">osquery: ports, processes, users, tasks</span></span>
      </button>
    </div>

    <div class="div"></div>

    <div class="qwrap">
      <div class="sec">Custom Query</div>
      <textarea id="qbox" class="qbox"
        placeholder="Investigate 10.0.0.1 for open services…&#10;&#10;Ctrl+Enter to run"></textarea>
      <button id="runBtn" class="run-btn" onclick="runCustom()">▶&nbsp; Run Agent</button>
    </div>

    <div class="div"></div>

    <div>
      <div class="sec">Tool Status</div>
      <div id="toolStatus"><div style="font-size:11px;color:var(--muted);padding:4px">Loading…</div></div>
    </div>
  </aside>

  <!-- console -->
  <main class="console">
    <div class="console-bar">
      <span class="prompt">pentest@agent:~$</span>
      <span class="cmdline" id="cmdline">waiting for input…</span>
    </div>
    <div class="feed" id="feed">
      <div class="welcome" id="welcome">
        <div class="big">🛡️</div>
        <h2>Security ReAct Agent</h2>
        <p>Pick a scenario or enter a custom query.</p>
        <div class="kbd">Reason → Act → Observe → repeat</div>
      </div>
    </div>
  </main>
</div>

<script>
/* ── globals ── */
let evSrc = null;
let runCount = 0;

/* ── status ── */
function setDot(cls){ document.getElementById('dot').className = 'dot' + (cls ? ' '+cls : ''); }
function setStatus(cls, txt){
  setDot(cls);
  document.getElementById('stxt').textContent = txt;
  document.getElementById('runBtn').disabled = (cls === 'running');
}

/* ── feed helpers ── */
function hideWelcome(){
  const w = document.getElementById('welcome');
  if(w) w.remove();
}
function push(html){
  const f = document.getElementById('feed');
  f.insertAdjacentHTML('beforeend', html);
  f.scrollTop = f.scrollHeight;
}
function esc(s){
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function clearHistory(){
  document.getElementById('feed').innerHTML =
    '<div class="welcome" id="welcome">' +
    '<div class="big">🛡️</div><h2>Security ReAct Agent</h2>' +
    '<p>Pick a scenario or enter a custom query.</p>' +
    '<div class="kbd">Reason → Act → Observe → repeat</div></div>';
  document.getElementById('cmdline').textContent = 'waiting for input…';
  document.querySelectorAll('.scn').forEach(b => b.classList.remove('active'));
  setStatus('','Ready');
  runCount = 0;
}

/* ── run header ── */
function addRunHeader(task){
  runCount++;
  const ts = new Date().toLocaleTimeString();
  push(`<div class="run-hdr">
    <span class="ts">${ts}</span>
    <span class="task-txt">${esc(task)}</span>
    <span class="badge-run">Run #${runCount}</span>
  </div>`);
}

/* ── event renderers ── */
function renderStep(n){ push(`<div class="step-sep">Step ${n}</div>`); }

function renderThought(txt){
  push(`<div class="card thought">
    <div class="ch"><span class="ico">💭</span> Thinking</div>
    <div class="cb">${esc(txt)}</div>
  </div>`);
}

function renderToolCall(name, input){
  const rows = Object.entries(input).map(([k,v]) => {
    const val = typeof v === 'object' ? JSON.stringify(v,null,2) : String(v);
    return `<div class="prow"><span class="pk">${esc(k)}</span><span class="pv">${esc(val)}</span></div>`;
  }).join('');
  push(`<div class="card tcall">
    <div class="ch"><span class="ico">🔧</span> Tool Call <span class="badge">${esc(name)}</span></div>
    <div class="cb"><div class="pblock">${rows}</div></div>
  </div>`);
}

function renderToolResult(name, output){
  const id   = 'r' + Date.now() + Math.random().toString(36).slice(2);
  const sid  = id + 's';
  const trunc = output.length > 800;
  const preview = trunc ? output.slice(0,800)+'\n…' : output;
  const isErr = output.startsWith('[TOOL NOT FOUND]') || output.startsWith('[ERROR]') ||
                output.startsWith('[CONFIG MISSING]') || output.startsWith('[TIMEOUT]');
  push(`<div class="card tresult">
    <div class="ch"><span class="ico">📤</span> Result <span class="badge">${esc(name)}</span></div>
    <div class="cb">
      <pre class="rpre${isErr?' raw-err':''}" id="${id}">${esc(preview)}</pre>
      <span id="${sid}" style="display:none">${esc(output)}</span>
      <div class="result-footer">
        ${trunc ? `<button class="more-btn" onclick="expand('${id}','${sid}',this)">↓ Show full output</button>` : '<span></span>'}
        <button class="copy-btn" onclick="copyResult('${id}')">Copy</button>
      </div>
    </div>
  </div>`);
}

function expand(preId, spanId, btn){
  document.getElementById(preId).textContent = document.getElementById(spanId).textContent;
  btn.remove();
}
function copyResult(preId){
  const txt = document.getElementById(preId)?.textContent || '';
  navigator.clipboard.writeText(txt).catch(() => {});
}

function renderFinal(txt){
  push(`<div class="card final">
    <div class="ch"><span class="ico">✅</span> Final Answer</div>
    <div class="cb">${esc(txt)}</div>
  </div>`);
}
function renderError(txt){
  push(`<div class="card errc">
    <div class="ch"><span class="ico">❌</span> Error</div>
    <div class="cb">${esc(txt)}</div>
  </div>`);
}

/* ── core runner ── */
function runAgent(task){
  if(evSrc){ evSrc.close(); }
  hideWelcome();
  addRunHeader(task);
  setStatus('running','Running…');
  document.getElementById('cmdline').textContent = task.length>72 ? task.slice(0,72)+'…' : task;

  evSrc = new EventSource('/stream?task=' + encodeURIComponent(task));
  evSrc.onmessage = (e) => {
    const d = JSON.parse(e.data);
    switch(d.type){
      case 'step':        renderStep(d.step);                  break;
      case 'thought':     renderThought(d.text);               break;
      case 'tool_call':   renderToolCall(d.name, d.input);     break;
      case 'tool_result': renderToolResult(d.name, d.output);  break;
      case 'final':       renderFinal(d.text); setStatus('done','Done'); break;
      case 'error':       renderError(d.text); setStatus('error','Error'); break;
      case 'done':        evSrc.close(); if(document.getElementById('dot').classList.contains('running')) setStatus('done','Done'); break;
    }
  };
  evSrc.onerror = () => {
    renderError('Stream connection lost.');
    evSrc.close();
    setStatus('error','Error');
  };
}

function runScenario(btn){
  document.querySelectorAll('.scn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  fetch('/scenario/' + btn.dataset.key)
    .then(r => r.json())
    .then(d => d.task ? runAgent(d.task) : renderError(d.error || 'Unknown scenario'));
}

function runCustom(){
  const q = document.getElementById('qbox').value.trim();
  if(!q) return;
  document.querySelectorAll('.scn').forEach(b => b.classList.remove('active'));
  runAgent(q);
}

document.getElementById('qbox').addEventListener('keydown', e => {
  if(e.key === 'Enter' && e.ctrlKey){ e.preventDefault(); runCustom(); }
});

/* ── tool status ── */
fetch('/tools-status')
  .then(r => r.json())
  .then(data => {
    const el = document.getElementById('toolStatus');
    el.innerHTML = Object.entries(data).map(([k,v]) =>
      `<div class="ts-row">
        <span class="ts-dot ${v?'ok':'miss'}"></span>
        <span class="ts-name">${k}</span>
        ${!v ? '<span class="ts-miss">not found</span>' : ''}
      </div>`
    ).join('');
  })
  .catch(() => {});
</script>
</body>
</html>
"""


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    import uvicorn
    print("Security ReAct Agent → http://localhost:8000")
    uvicorn.run("tp17_server:app", host="0.0.0.0", port=8000, reload=True)
