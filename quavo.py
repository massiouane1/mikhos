"""
Butcher — Security ReAct Agent · Web Server  (The Boys edition)
Run:  python quavo.py
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

from takeoff import react_agent_stream, SCENARIOS, check_tools

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
<title>Butcher — Security Agent</title>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f1114;--sb:#14171a;--card:#1a1d21;--border:#2a2d32;
  --accent:#00b389;--muted:#6b7280;--text:#e4e6ea;
  --thought:#f59e0b;--tool:#60a5fa;--result:#00b389;
  --final:#e4e6ea;--err:#ef4444;--warn:#f59e0b;
  --crit:#ef4444;--high:#f97316;--med:#eab308;--low:#22c55e;--info:#3b82f6;
  --mono:'JetBrains Mono','Fira Code','Cascadia Code',monospace;
  --ui:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
}
body{font-family:var(--ui);background:var(--bg);color:var(--text);height:100vh;display:flex;flex-direction:column;overflow:hidden}

/* topbar */
.topbar{height:52px;display:flex;align-items:center;gap:12px;padding:0 20px;
  background:var(--sb);border-bottom:1px solid var(--border);flex-shrink:0}
.logo{display:flex;align-items:center;gap:8px}
.logo-mark{width:28px;height:28px;background:var(--accent);border-radius:7px;
  display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.logo-text{font-size:15px;font-weight:700;color:var(--text);letter-spacing:-.3px}
.logo-sub{font-size:10px;color:var(--muted);letter-spacing:.3px;margin-top:1px}
.topbar-mid{flex:1;display:flex;align-items:center;justify-content:center;gap:10px}
.status-pill{display:flex;align-items:center;gap:7px;padding:4px 12px;
  background:var(--card);border:1px solid var(--border);border-radius:20px;
  font-size:12px;color:var(--muted)}
.dot{width:7px;height:7px;border-radius:50%;background:var(--muted);flex-shrink:0}
.dot.running{background:var(--accent);animation:pulse 1.2s ease-in-out infinite}
.dot.done{background:#22c55e}.dot.error{background:var(--err)}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.75)}}
.topbar-right{display:flex;gap:6px}
.tb-btn{height:30px;padding:0 12px;background:transparent;
  border:1px solid var(--border);border-radius:6px;
  color:var(--muted);font-size:12px;cursor:pointer;transition:all .15s}
.tb-btn:hover{border-color:var(--accent);color:var(--accent)}
.tb-btn.danger:hover{border-color:var(--err);color:var(--err)}
.tb-btn.primary{background:var(--accent);border-color:var(--accent);color:#0f1114;font-weight:600}
.tb-btn.primary:hover{opacity:.85}

/* layout */
.body{display:flex;flex:1;overflow:hidden;min-height:0}

/* sidebar */
.sidebar{width:260px;flex-shrink:0;background:var(--sb);
  border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;min-height:0}
.tab-bar{display:flex;border-bottom:1px solid var(--border);flex-shrink:0;padding:0 10px}
.tab{flex:1;padding:11px 4px;font-size:12px;font-weight:500;text-align:center;
  cursor:pointer;color:var(--muted);border:none;background:transparent;
  border-bottom:2px solid transparent;transition:all .15s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-panel{flex:1;min-height:0;overflow-y:auto;padding:12px 10px;
  display:none;flex-direction:column;gap:8px}
.tab-panel.active{display:flex}
.tab-panel::-webkit-scrollbar{width:5px}
.tab-panel::-webkit-scrollbar-track{background:transparent}
.tab-panel::-webkit-scrollbar-thumb{background:#374151;border-radius:4px}
.tab-panel::-webkit-scrollbar-thumb:hover{background:#4b5563}

/* scenario cards */
.scn{display:flex;align-items:center;gap:10px;width:100%;padding:10px 10px;
  border:1px solid transparent;border-radius:8px;background:transparent;
  color:var(--text);font-size:12px;font-family:var(--ui);cursor:pointer;
  text-align:left;transition:all .15s}
.scn:hover{background:var(--card);border-color:var(--border)}
.scn.active{background:rgba(0,179,137,.07);border-color:rgba(0,179,137,.35);color:var(--accent)}
.scn .ico{font-size:18px;flex-shrink:0}
.scn .nm{font-weight:600;font-size:12px;display:block}
.scn .ht{font-size:10px;color:var(--muted);display:block;margin-top:2px;line-height:1.4}
.scn.active .ht{color:rgba(0,179,137,.55)}

/* history */
.hist-empty{font-size:11px;color:var(--muted);font-style:italic;padding:4px 2px}
.hist-item{display:flex;align-items:flex-start;gap:8px;padding:9px 10px;
  border-radius:8px;border:1px solid transparent;cursor:pointer;
  transition:all .15s;width:100%;background:transparent;
  color:var(--text);font-family:var(--ui);text-align:left}
.hist-item:hover{background:var(--card);border-color:var(--border)}
.hist-body{flex:1;min-width:0}
.hist-task{font-size:11px;font-weight:500;color:var(--text);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block;margin-bottom:3px}
.hist-meta{font-size:10px;color:var(--muted);display:flex;gap:8px}
.hist-del{flex-shrink:0;background:none;border:none;color:var(--muted);
  cursor:pointer;font-size:12px;padding:1px 2px;transition:color .15s}
.hist-del:hover{color:var(--err)}
.hist-section-hdr{display:flex;align-items:center;justify-content:space-between;padding:0 2px}
.hist-clear{font-size:10px;color:var(--muted);background:none;border:none;
  cursor:pointer;text-decoration:underline;transition:color .15s}
.hist-clear:hover{color:var(--err)}
.sec-label{font-size:10px;font-weight:600;letter-spacing:.8px;
  text-transform:uppercase;color:var(--muted)}

/* tools panel */
.ts-item{border-radius:8px;background:var(--card);border:1px solid var(--border);overflow:hidden}
.ts-main{display:flex;align-items:center;gap:10px;padding:9px 10px}
.ts-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.ts-dot.ok{background:#22c55e}.ts-dot.miss{background:#374151}
.ts-name{font-size:12px;font-family:var(--mono);flex:1;color:var(--text)}
.ts-badge{font-size:10px;padding:1px 8px;border-radius:10px;flex-shrink:0;font-weight:500}
.ts-badge.ok{background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2)}
.ts-badge.miss{background:rgba(107,114,128,.1);color:var(--muted);border:1px solid var(--border)}
.ts-install{font-size:10px;color:var(--muted);font-family:var(--mono);
  padding:6px 10px 8px 28px;background:rgba(0,0,0,.2);border-top:1px solid var(--border);
  cursor:pointer;word-break:break-all;line-height:1.5}
.ts-install:hover{color:var(--text)}

/* main console */
.console{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}

/* search bar */
.search-bar{flex-shrink:0;padding:8px 16px;border-bottom:1px solid var(--border);
  background:var(--sb);display:none;align-items:center;gap:8px}
.search-bar.visible{display:flex}
.search-input{flex:1;padding:5px 10px;background:var(--card);border:1px solid var(--border);
  border-radius:6px;color:var(--text);font-size:12px;font-family:var(--mono);outline:none}
.search-input:focus{border-color:var(--accent)}
.search-count{font-size:11px;color:var(--muted);white-space:nowrap;font-family:var(--mono)}
.search-close{background:none;border:none;color:var(--muted);cursor:pointer;font-size:14px}
.search-close:hover{color:var(--err)}
.highlighted{background:rgba(0,179,137,.2);border-radius:2px}

/* feed area wrapper — absolute-fill gives reliable scroll in every browser */
.feed-area{flex:1;position:relative;overflow:hidden}

/* feed */
.feed{position:absolute;top:0;left:0;right:0;bottom:0;overflow-y:auto;
  padding:20px 24px;display:flex;flex-direction:column;gap:10px}
.feed::-webkit-scrollbar{width:7px}
.feed::-webkit-scrollbar-track{background:rgba(0,0,0,.25);border-radius:4px}
.feed::-webkit-scrollbar-thumb{background:#4b5563;border-radius:4px;border:1px solid rgba(255,255,255,.05)}
.feed::-webkit-scrollbar-thumb:hover{background:#6b7280}

/* welcome */
.welcome{display:flex;flex-direction:column;align-items:center;
  justify-content:center;height:100%;gap:8px;text-align:center;padding-bottom:40px}
.welcome-icon{width:64px;height:64px;background:rgba(0,179,137,.1);
  border:1px solid rgba(0,179,137,.2);border-radius:16px;
  display:flex;align-items:center;justify-content:center;font-size:30px;margin-bottom:12px}
.welcome h2{font-size:20px;color:var(--text);font-weight:700;margin-bottom:6px}
.welcome p{font-size:13px;color:var(--muted);max-width:320px;line-height:1.6}
.welcome .hint{margin-top:20px;padding:10px 20px;background:var(--card);
  border:1px solid var(--border);border-radius:8px;
  font-size:12px;font-family:var(--mono);color:var(--muted)}
.quick-row{display:flex;gap:8px;flex-wrap:wrap;justify-content:center;margin-top:16px;max-width:440px}
.qs-btn{padding:6px 14px;background:var(--card);border:1px solid var(--border);
  border-radius:20px;color:var(--text);font-size:12px;cursor:pointer;
  transition:all .15s;font-family:var(--ui)}
.qs-btn:hover{border-color:var(--accent);color:var(--accent)}

/* run header */
.run-hdr{display:flex;align-items:center;gap:10px;padding:10px 14px;
  background:rgba(0,179,137,.04);border:1px solid rgba(0,179,137,.15);
  border-radius:8px;font-size:12px}
.run-badge{font-family:var(--mono);font-size:10px;font-weight:600;color:var(--accent);
  padding:2px 8px;background:rgba(0,179,137,.1);
  border:1px solid rgba(0,179,137,.25);border-radius:4px;flex-shrink:0}
.run-ts{color:var(--muted);font-size:11px;flex-shrink:0;font-family:var(--mono)}
.run-task{color:var(--text);flex:1;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;font-size:12px}

/* step separator */
.step-sep{display:flex;align-items:center;gap:10px;
  font-size:10px;font-family:var(--mono);color:var(--muted);margin:2px 0}
.step-sep::before,.step-sep::after{content:'';flex:1;height:1px;background:var(--border)}
.stopped-sep{display:flex;align-items:center;gap:10px;
  font-size:10px;font-family:var(--mono);color:var(--warn);margin:2px 0}
.stopped-sep::before,.stopped-sep::after{content:'';flex:1;height:1px;background:rgba(245,158,11,.25)}

/* cards */
.card{border-radius:8px;border:1px solid var(--border);background:var(--card);
  overflow:hidden;animation:fadeUp .18s ease-out}
@keyframes fadeUp{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.ch{display:flex;align-items:center;gap:8px;padding:10px 14px;
  font-size:11px;font-weight:600;letter-spacing:.4px;cursor:pointer;
  user-select:none;transition:background .12s;border-bottom:1px solid transparent}
.ch:hover{background:rgba(255,255,255,.025)}
.ch .ico{font-size:14px;flex-shrink:0}
.ch .lbl{min-width:70px}
.ch .preview{font-size:10px;font-weight:400;color:var(--muted);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;letter-spacing:0}
.ch .toggle{font-size:10px;color:var(--muted);transition:transform .18s;flex-shrink:0;margin-left:4px}
.cb{padding:12px 14px;font-size:13px;line-height:1.65}

/* card type colors */
.thought{border-color:rgba(245,158,11,.15)}
.thought .ch{color:var(--thought);border-bottom-color:rgba(245,158,11,.1)}
.tcall{border-color:rgba(96,165,250,.15)}
.tcall .ch{color:var(--tool);border-bottom-color:rgba(96,165,250,.1)}
.tresult{border-color:rgba(0,179,137,.15)}
.tresult .ch{color:var(--result);border-bottom-color:rgba(0,179,137,.1)}
.final{border-color:rgba(0,179,137,.25);background:rgba(0,179,137,.03)}
.final .ch{color:var(--accent);border-bottom-color:rgba(0,179,137,.15)}
.errc{border-color:rgba(239,68,68,.2)}.errc .ch{color:var(--err)}

/* severity badges (HackerOne-style) */
.sev{display:inline-flex;align-items:center;font-size:10px;font-weight:700;
  letter-spacing:.4px;text-transform:uppercase;padding:1px 7px;
  border-radius:4px;flex-shrink:0}
.sev.crit{background:rgba(239,68,68,.15);color:var(--crit);border:1px solid rgba(239,68,68,.25)}
.sev.high{background:rgba(249,115,22,.15);color:var(--high);border:1px solid rgba(249,115,22,.25)}
.sev.med{background:rgba(234,179,8,.15);color:var(--med);border:1px solid rgba(234,179,8,.25)}
.sev.low{background:rgba(34,197,94,.15);color:var(--low);border:1px solid rgba(34,197,94,.25)}
.sev.info{background:rgba(59,130,246,.15);color:var(--info);border:1px solid rgba(59,130,246,.25)}

/* code blocks */
.badge{background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.2);
  border-radius:4px;padding:1px 7px;font-family:var(--mono);font-size:11px;color:var(--tool)}
.pblock{background:#0f1114;border:1px solid var(--border);border-radius:6px;
  padding:10px 12px;font-family:var(--mono);font-size:11px;margin-top:8px}
.prow{display:flex;gap:10px;margin-bottom:4px;align-items:flex-start}
.pk{color:var(--muted);flex-shrink:0;min-width:80px;font-size:10px}
.pv{color:var(--tool);word-break:break-all;white-space:pre-wrap}
.rpre{background:#0f1114;border:1px solid var(--border);border-radius:6px;
  padding:10px 12px;font-family:var(--mono);font-size:11px;
  color:var(--accent);overflow:auto;max-height:260px;
  white-space:pre-wrap;word-break:break-word;margin-top:8px}
.rpre.raw-err{color:var(--err)}

/* final markdown */
.final .cb{font-size:14px;line-height:1.8}
.final .cb h1,.final .cb h2{color:var(--accent);font-size:15px;margin:14px 0 6px;font-weight:700}
.final .cb h3{color:var(--accent);font-size:13px;margin:10px 0 5px;font-weight:600}
.final .cb ul,.final .cb ol{margin:6px 0 6px 18px}
.final .cb li{margin:4px 0}
.final .cb code{background:#0f1114;border:1px solid var(--border);
  border-radius:3px;padding:1px 5px;font-family:var(--mono);font-size:11px;color:var(--accent)}
.final .cb pre code{display:block;padding:12px;margin:8px 0;overflow-x:auto;border-radius:6px}
.final .cb strong{color:var(--text);font-weight:600}
.final .cb a{color:var(--accent);text-decoration:none}
.final .cb a:hover{text-decoration:underline}
.final .cb table{width:100%;border-collapse:collapse;margin:10px 0;font-size:12px}
.final .cb th{padding:6px 10px;background:rgba(0,179,137,.08);border:1px solid var(--border);
  text-align:left;font-weight:600;color:var(--accent)}
.final .cb td{padding:6px 10px;border:1px solid var(--border);color:var(--text)}
.final .cb tr:nth-child(even) td{background:rgba(255,255,255,.02)}

/* result footer */
.result-footer{display:flex;align-items:center;gap:8px;margin-top:8px}
.more-btn{font-size:10px;color:var(--muted);background:none;border:none;
  cursor:pointer;text-decoration:underline;padding:0}
.more-btn:hover{color:var(--text)}
.copy-btn{font-size:10px;padding:2px 9px;background:transparent;
  border:1px solid var(--border);border-radius:4px;
  color:var(--muted);cursor:pointer;transition:all .15s;margin-left:auto}
.copy-btn:hover{border-color:var(--accent);color:var(--accent)}

/* bottom input bar */
.input-bar{flex-shrink:0;border-top:1px solid var(--border);
  padding:12px 16px;background:var(--sb);display:flex;flex-direction:column;gap:8px}
.bar-meta{display:flex;align-items:center;gap:6px}
.fp{padding:3px 10px;background:transparent;border:1px solid var(--border);
  border-radius:10px;color:var(--muted);font-size:11px;cursor:pointer;transition:all .15s}
.fp:hover{border-color:var(--accent);color:var(--accent)}
.fp.active{background:rgba(0,179,137,.1);border-color:rgba(0,179,137,.35);color:var(--accent)}
.bar-counters{margin-left:auto;font-size:10px;color:var(--muted);font-family:var(--mono)}
.bar-counters b{color:var(--text)}
.input-row{display:flex;gap:8px;align-items:flex-end}
.input-wrap{flex:1;background:var(--card);border:1px solid var(--border);
  border-radius:10px;padding:10px 12px;transition:border-color .15s;display:flex;gap:8px;align-items:flex-end}
.input-wrap:focus-within{border-color:var(--accent)}
textarea.main-input{flex:1;background:transparent;border:none;outline:none;
  color:var(--text);font-size:13px;font-family:var(--ui);
  resize:none;line-height:1.5;min-height:20px;max-height:120px;padding:0}
textarea.main-input::placeholder{color:var(--muted)}
.run-btn{flex-shrink:0;height:38px;padding:0 20px;background:var(--accent);
  border:none;border-radius:8px;color:#0f1114;font-size:13px;
  font-weight:700;cursor:pointer;transition:all .15s;white-space:nowrap}
.run-btn:hover{opacity:.85}.run-btn:active{transform:scale(.97)}
.run-btn.stopping{background:var(--err);color:#fff}

/* thinking indicator */
.thinking-ind{display:none;align-items:center;gap:10px;padding:10px 14px;
  color:var(--muted);font-size:12px;font-family:var(--mono)}
.thi-dots{display:flex;gap:5px}
.thi-dot{width:5px;height:5px;border-radius:50%;background:var(--accent);
  animation:thi-b .9s ease-in-out infinite}
.thi-dot:nth-child(2){animation-delay:.18s}
.thi-dot:nth-child(3){animation-delay:.36s}
@keyframes thi-b{0%,60%,100%{transform:translateY(0);opacity:.35}30%{transform:translateY(-5px);opacity:1}}

/* scroll paused pill */
.scroll-paused{position:absolute;bottom:16px;right:20px;z-index:10;
  padding:6px 14px;background:var(--card);border:1px solid var(--border);
  border-radius:20px;font-size:11px;color:var(--muted);cursor:pointer;
  display:none;align-items:center;gap:6px;box-shadow:0 4px 20px rgba(0,0,0,.5)}
.scroll-paused.visible{display:flex}
.scroll-paused:hover{border-color:var(--accent);color:var(--accent)}
</style>
</head>
<body>

<div class="topbar">
  <div class="logo">
    <div class="logo-mark">🔪</div>
    <div>
      <div class="logo-text">Butcher</div>
      <div class="logo-sub">Security Agent</div>
    </div>
  </div>
  <div class="topbar-mid">
    <div class="status-pill">
      <div class="dot" id="dot"></div>
      <span id="stxt">Ready</span>
    </div>
  </div>
  <div class="topbar-right">
    <button class="tb-btn primary" onclick="newChat()">＋ New</button>
    <button class="tb-btn" onclick="toggleSearch()">🔍 Search</button>
    <button class="tb-btn" onclick="exportSession()">↓ Export</button>
    <button class="tb-btn danger" onclick="clearSession()">⌫</button>
  </div>
</div>

<div class="body">
  <aside class="sidebar">
    <div class="tab-bar">
      <button class="tab active" id="tab-ops"     onclick="switchTab('ops')">OPS</button>
      <button class="tab"        id="tab-logs"    onclick="switchTab('logs')">LOGS</button>
      <button class="tab"        id="tab-arsenal" onclick="switchTab('arsenal')">ARSENAL</button>
    </div>

    <div class="tab-panel active" id="panel-ops">
      <button class="scn" data-key="recon" onclick="runScenario(this)">
        <span class="ico">🔍</span>
        <span><span class="nm">Recon Scan</span><span class="ht">nmap · DNS · surface mapping</span></span>
      </button>
      <button class="scn" data-key="web_audit" onclick="runScenario(this)">
        <span class="ico">🌐</span>
        <span><span class="nm">Web Audit</span><span class="ht">HTTP headers · tech stack · ports</span></span>
      </button>
      <button class="scn" data-key="brute_force_hunt" onclick="runScenario(this)">
        <span class="ico">🔐</span>
        <span><span class="nm">Brute Force Hunt</span><span class="ht">Splunk · failed auth · attacker IPs</span></span>
      </button>
      <button class="scn" data-key="vuln_scan" onclick="runScenario(this)">
        <span class="ico">⚡</span>
        <span><span class="nm">Vuln Scan</span><span class="ht">nmap scripts · MS17-010 check</span></span>
      </button>
      <button class="scn" data-key="host_audit" onclick="runScenario(this)">
        <span class="ico">🖥️</span>
        <span><span class="nm">Host Audit</span><span class="ht">ports · processes · users · tasks</span></span>
      </button>
    </div>

    <div class="tab-panel" id="panel-logs">
      <div class="hist-section-hdr">
        <span class="sec-label">Recent</span>
        <button class="hist-clear" onclick="clearHistory()">clear all</button>
      </div>
      <div id="histList"><div class="hist-empty">No runs yet</div></div>
    </div>

    <div class="tab-panel" id="panel-arsenal">
      <span class="sec-label" style="padding:0 2px">Installed Tools</span>
      <div id="toolStatus"><div style="font-size:11px;color:var(--muted);padding:4px">Loading…</div></div>
    </div>
  </aside>

  <main class="console">
    <div class="search-bar" id="searchBar">
      <input class="search-input" id="searchInput" placeholder="Search in session…" oninput="doSearch(this.value)">
      <span class="search-count" id="searchCount"></span>
      <button class="search-close" onclick="closeSearch()">✕</button>
    </div>

    <div class="feed-area">
      <div class="feed" id="feed">
        <div class="welcome" id="welcome">
          <div class="welcome-icon">🔪</div>
          <h2>Butcher</h2>
          <p>We don't need to be the good guys. We just need to find the weaknesses first.</p>
          <div class="quick-row">
            <button class="qs-btn" onclick="quickRun('recon')">🔍 Recon</button>
            <button class="qs-btn" onclick="quickRun('web_audit')">🌐 Web Audit</button>
            <button class="qs-btn" onclick="quickRun('vuln_scan')">⚡ Vuln Scan</button>
            <button class="qs-btn" onclick="quickRun('host_audit')">🖥️ Host Audit</button>
          </div>
          <div class="hint">Ctrl+Enter to run · Ctrl+K to search</div>
        </div>
        <div class="thinking-ind" id="thinkingInd">
          <div class="thi-dots">
            <div class="thi-dot"></div><div class="thi-dot"></div><div class="thi-dot"></div>
          </div>
          <span id="thinkingTxt">Butcher is thinking…</span>
        </div>
      </div>

      <div class="scroll-paused" id="scrollPaused" onclick="resumeScroll()">
        ↓ New output — click to follow
      </div>
    </div>

    <div class="input-bar">
      <div class="bar-meta">
        <button class="fp active" id="fp-all"   onclick="setFilter('all')">All</button>
        <button class="fp"        id="fp-final" onclick="setFilter('final')">Finals</button>
        <button class="fp"        id="fp-tool"  onclick="setFilter('tool')">Tools</button>
        <button class="fp"        id="fp-think" onclick="setFilter('think')">Thinking</button>
        <div class="bar-counters">
          Steps <b id="stepCount">0</b> · Tools <b id="toolCount">0</b>
        </div>
      </div>
      <div class="input-row">
        <div class="input-wrap">
          <textarea id="mainInput" class="main-input" rows="1"
            placeholder="Scan a target, run a scenario, or ask anything security-related… (Ctrl+Enter to run)"
            oninput="autoResize(this)"
            onkeydown="if(event.key==='Enter'&&event.ctrlKey){event.preventDefault();runOrStop()}"></textarea>
        </div>
        <button id="runBtn" class="run-btn" onclick="runOrStop()">▶ Run</button>
      </div>
    </div>
  </main>
</div>

<script>
/* safe marked init — CDN may be slow */
function _initMarked(){ try{ marked.setOptions({breaks:true,gfm:true}); }catch(e){} }

let evSrc=null, runCount=0, lastFinalText='', lastTask='';
let autoScroll=true, stepCount=0, toolCount=0, currentFilter='all';
let history=JSON.parse(localStorage.getItem('butcher_history')||'[]');

/* textarea auto-resize */
function autoResize(ta){
  ta.style.height='auto';
  ta.style.height=Math.min(ta.scrollHeight,120)+'px';
}

/* tabs */
function switchTab(name){
  ['ops','logs','arsenal'].forEach(t=>{
    document.getElementById('tab-'+t).classList.toggle('active',t===name);
    document.getElementById('panel-'+t).classList.toggle('active',t===name);
  });
}

/* autoscroll */
const feed=document.getElementById('feed');
feed.addEventListener('scroll',()=>{
  const atBottom=feed.scrollHeight-feed.scrollTop-feed.clientHeight<40;
  autoScroll=atBottom;
  document.getElementById('scrollPaused').classList.toggle('visible',!atBottom&&evSrc);
});
function resumeScroll(){
  autoScroll=true; feed.scrollTop=feed.scrollHeight;
  document.getElementById('scrollPaused').classList.remove('visible');
}

/* counters */
function incStep(){stepCount++;document.getElementById('stepCount').textContent=stepCount;}
function incTool(){toolCount++;document.getElementById('toolCount').textContent=toolCount;}
function resetCounters(){
  stepCount=0;toolCount=0;
  document.getElementById('stepCount').textContent='0';
  document.getElementById('toolCount').textContent='0';
}

/* filter — persisted */
function setFilter(f){
  currentFilter=f;
  localStorage.setItem('butcher_filter',f);
  ['all','final','tool','think'].forEach(k=>{
    document.getElementById('fp-'+k).classList.toggle('active',k===f);
  });
  feed.querySelectorAll('.card').forEach(c=>{
    if(f==='all') c.style.display='';
    else if(f==='final')  c.style.display=c.classList.contains('final')?'':'none';
    else if(f==='tool')   c.style.display=c.classList.contains('tresult')?'':'none';
    else if(f==='think')  c.style.display=c.classList.contains('thought')?'':'none';
  });
}
setFilter(localStorage.getItem('butcher_filter')||'all');

/* status */
function setStatus(cls,txt){
  document.getElementById('dot').className='dot'+(cls?' '+cls:'');
  document.getElementById('stxt').textContent=txt;
  const btn=document.getElementById('runBtn');
  if(cls==='running'){btn.textContent='⏹ Stop';btn.classList.add('stopping');}
  else{btn.textContent='▶ Run';btn.classList.remove('stopping');}
}

/* feed */
function hideWelcome(){const w=document.getElementById('welcome');if(w)w.remove();}
function push(html){
  feed.insertAdjacentHTML('beforeend',html);
  if(autoScroll) feed.scrollTop=feed.scrollHeight;
  if(currentFilter!=='all'){
    const last=feed.lastElementChild;
    if(last&&last.classList.contains('card')){
      if(currentFilter==='final'&&!last.classList.contains('final')) last.style.display='none';
      if(currentFilter==='tool'&&!last.classList.contains('tresult')) last.style.display='none';
      if(currentFilter==='think'&&!last.classList.contains('thought')) last.style.display='none';
    }
  }
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function copyText(txt){navigator.clipboard.writeText(txt).catch(()=>{});}

/* thinking indicator */
const _tInd=document.getElementById('thinkingInd');
const _tTxt=document.getElementById('thinkingTxt');
function showThinking(msg='Butcher is thinking…'){
  _tTxt.textContent=msg; _tInd.style.display='flex';
  feed.appendChild(_tInd); // keep at bottom
  if(autoScroll) feed.scrollTop=feed.scrollHeight;
}
function hideThinking(){ _tInd.style.display='none'; }

/* session */
const WELCOME_HTML=`<div class="welcome" id="welcome">
  <div class="welcome-icon">🔪</div><h2>Butcher</h2>
  <p>We don't need to be the good guys. We just need to find the weaknesses first.</p>
  <div class="quick-row">
    <button class="qs-btn" onclick="quickRun('recon')">🔍 Recon</button>
    <button class="qs-btn" onclick="quickRun('web_audit')">🌐 Web Audit</button>
    <button class="qs-btn" onclick="quickRun('vuln_scan')">⚡ Vuln Scan</button>
    <button class="qs-btn" onclick="quickRun('host_audit')">🖥️ Host Audit</button>
  </div>
  <div class="hint">Ctrl+Enter to run · Ctrl+K to search</div>
</div>`;

function clearSession(){
  if(evSrc){evSrc.close();evSrc=null;}
  feed.innerHTML=WELCOME_HTML;
  document.querySelectorAll('.scn').forEach(b=>b.classList.remove('active'));
  setStatus('','Ready'); resetCounters();
  runCount=0;lastFinalText='';lastTask='';
}
function newChat(){clearSession();document.getElementById('mainInput').focus();}

function exportSession(){
  const ts=new Date().toLocaleString();
  const cards=[...feed.querySelectorAll('.card,.run-hdr')].map(el=>{
    const ch=el.querySelector('.ch');
    const cb=el.querySelector('.cb');
    if(!ch) return `<div class="rh">${esc(el.textContent.trim())}</div>`;
    const lbl=ch.querySelector('.lbl');
    const badge=ch.querySelector('.badge');
    const sev=ch.querySelector('.sev');
    const title=(lbl?lbl.textContent:'')+' '+(badge?'['+badge.textContent+']':'');
    const sevHtml=sev?`<span class="sev ${sev.className.replace('sev','').trim()}">${sev.textContent}</span>`:'';
    return `<details open><summary>${esc(title.trim())} ${sevHtml}</summary><pre>${cb?esc(cb.textContent.trim()):''}</pre></details>`;
  }).join('\n');
  const html=`<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Butcher Report — ${ts}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1114;color:#e4e6ea;padding:32px;line-height:1.6}
h1{font-size:22px;color:#00b389;margin-bottom:4px}
.meta{font-size:12px;color:#6b7280;margin-bottom:28px;font-family:monospace}
details{background:#1a1d21;border:1px solid #2a2d32;border-radius:8px;margin-bottom:10px;overflow:hidden}
summary{padding:10px 14px;font-size:12px;font-weight:600;cursor:pointer;color:#60a5fa;list-style:none;display:flex;align-items:center;gap:8px}
summary::-webkit-details-marker{display:none}
summary:hover{background:rgba(255,255,255,.03)}
pre{padding:12px 14px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:11px;color:#00b389;white-space:pre-wrap;word-break:break-word;border-top:1px solid #2a2d32}
.rh{padding:10px 14px;font-size:11px;color:#6b7280;font-family:monospace;border-bottom:1px solid #2a2d32}
.sev{display:inline-flex;font-size:10px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;padding:1px 7px;border-radius:4px}
.crit{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.25)}
.high{background:rgba(249,115,22,.15);color:#f97316;border:1px solid rgba(249,115,22,.25)}
.med{background:rgba(234,179,8,.15);color:#eab308;border:1px solid rgba(234,179,8,.25)}
.low{background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.25)}
.info{background:rgba(59,130,246,.15);color:#3b82f6;border:1px solid rgba(59,130,246,.25)}
</style></head><body>
<h1>🔪 Butcher — Security Report</h1>
<div class="meta">Generated ${ts}</div>
${cards}
</body></html>`;
  const a=document.createElement('a');
  a.href='data:text/html;charset=utf-8,'+encodeURIComponent(html);
  a.download='butcher_report_'+Date.now()+'.html';a.click();
}

/* history (bug fix: pass raw task, not escaped) */
function saveHistory(task,summary){
  const entry={id:Date.now(),task,summary,ts:new Date().toLocaleTimeString()};
  history.unshift(entry);
  if(history.length>25) history=history.slice(0,25);
  localStorage.setItem('butcher_history',JSON.stringify(history));
  renderHistory();
}
function clearHistory(){history=[];localStorage.removeItem('butcher_history');renderHistory();}
function deleteHistEntry(id){
  history=history.filter(h=>h.id!==id);
  localStorage.setItem('butcher_history',JSON.stringify(history));
  renderHistory();
}
function restoreHistRun(task){
  document.getElementById('mainInput').value=task;
  autoResize(document.getElementById('mainInput'));
  document.querySelectorAll('.scn').forEach(b=>b.classList.remove('active'));
  runAgent(task);
}
function renderHistory(){
  const el=document.getElementById('histList');
  if(!history.length){el.innerHTML='<div class="hist-empty">No runs yet</div>';return;}
  el.innerHTML=history.map(h=>`
    <div class="hist-item" onclick="restoreHistRun(${JSON.stringify(h.task)})">
      <span class="hist-body">
        <span class="hist-task" title="${esc(h.task)}">${esc(h.task.slice(0,44))}${h.task.length>44?'…':''}</span>
        <span class="hist-meta"><span>${h.ts}</span></span>
      </span>
      <button class="hist-del" onclick="event.stopPropagation();deleteHistEntry(${h.id})">✕</button>
    </div>`).join('');
}
renderHistory();

/* search */
function toggleSearch(){
  const bar=document.getElementById('searchBar');
  bar.classList.toggle('visible');
  if(bar.classList.contains('visible')) document.getElementById('searchInput').focus();
  else clearSearch();
}
function closeSearch(){document.getElementById('searchBar').classList.remove('visible');clearSearch();}
function clearSearch(){
  document.getElementById('searchInput').value='';
  document.getElementById('searchCount').textContent='';
  document.querySelectorAll('.highlighted').forEach(el=>{el.outerHTML=el.textContent;});
}
function doSearch(q){
  document.querySelectorAll('.highlighted').forEach(el=>{el.outerHTML=el.textContent;});
  if(!q.trim()){document.getElementById('searchCount').textContent='';return;}
  let count=0;
  document.querySelectorAll('.cb').forEach(el=>{
    const re=new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'gi');
    el.innerHTML=el.innerHTML.replace(re,m=>{count++;return`<mark class="highlighted">${m}</mark>`;});
  });
  document.getElementById('searchCount').textContent=count?`${count} match${count>1?'es':''}`:'no matches';
}
document.addEventListener('keydown',e=>{
  if(e.key==='k'&&e.ctrlKey){e.preventDefault();toggleSearch();}
});

/* renderers */
function renderStep(n){incStep();push(`<div class="step-sep">Step ${n}</div>`);}

function renderThought(txt){
  push(`<div class="card thought">
    <div class="ch" onclick="toggleCard(this)">
      <span class="ico">💭</span><span class="lbl">Thinking</span>
      <span class="preview">${esc(txt.slice(0,80))}${txt.length>80?'…':''}</span>
      <span class="toggle">▸</span>
    </div>
    <div class="cb" style="display:none;white-space:pre-wrap;font-family:var(--mono);font-size:12px">${esc(txt)}</div>
  </div>`);
}

function renderToolCall(name,input){
  const rows=Object.entries(input).map(([k,v])=>{
    const val=typeof v==='object'?JSON.stringify(v,null,2):String(v);
    return `<div class="prow"><span class="pk">${esc(k)}</span><span class="pv">${esc(val)}</span></div>`;
  }).join('');
  push(`<div class="card tcall">
    <div class="ch" onclick="toggleCard(this)">
      <span class="ico">🔧</span><span class="lbl">Tool Call</span>
      <span class="badge">${esc(name)}</span>
      <span class="toggle">▸</span>
    </div>
    <div class="cb" style="display:none"><div class="pblock">${rows}</div></div>
  </div>`);
}

function renderToolResult(name,output){
  const id='r'+Date.now()+Math.random().toString(36).slice(2);
  const sid=id+'s';
  const trunc=output.length>1400;
  const preview=trunc?output.slice(0,1400)+'\n\n… ('+output.length+' chars total)':output;
  const isErr=output.startsWith('[TOOL NOT FOUND]')||output.startsWith('[ERROR]')||
              output.startsWith('[CONFIG MISSING]')||output.startsWith('[TIMEOUT]');
  const firstLine=output.split('\n')[0]||'';
  const sev=detectSeverity(output);
  incTool();
  push(`<div class="card tresult">
    <div class="ch" onclick="toggleCard(this)">
      <span class="ico">📤</span><span class="lbl">Result</span>
      <span class="badge">${esc(name)}</span>
      ${sev?`<span class="sev ${sev}">${sev}</span>`:''}
      <span class="preview" style="color:var(--result)">${esc(firstLine.slice(0,50))}${firstLine.length>50?'…':''}</span>
      <span class="toggle">▸</span>
    </div>
    <div class="cb" style="display:none">
      <pre class="rpre${isErr?' raw-err':''}" id="${id}">${esc(preview)}</pre>
      <span id="${sid}" style="display:none">${esc(output)}</span>
      <div class="result-footer">
        ${trunc?`<button class="more-btn" onclick="expandResult('${id}','${sid}',this)">↓ Show all ${output.length} chars</button>`:'<span></span>'}
        <button class="copy-btn" onclick="copyText(document.getElementById('${id}').textContent)">Copy</button>
      </div>
    </div>
  </div>`);
}

function detectSeverity(output){
  const low=output.toLowerCase();
  if(/critical|rce|remote code exec|exploit.*success|ms17-010.*vuln/i.test(output)) return 'crit';
  if(/high|cve-20\d\d-\d+.*open|445.*open|22.*open.*banner/i.test(output)) return 'high';
  if(/medium|medium risk|moderate/i.test(output)) return 'med';
  if(/low risk|informational|info:/i.test(output)) return 'low';
  if(/\[tool not found\]|\[config missing\]|\[error\]/i.test(output)) return null;
  return null;
}

function renderFinal(txt){
  lastFinalText=txt;
  _initMarked();
  const html=typeof marked!=='undefined'?marked.parse(txt):esc(txt).replace(/\n/g,'<br>');
  push(`<div class="card final">
    <div class="ch" onclick="toggleCard(this)">
      <span class="ico">✅</span><span class="lbl">Final Answer</span>
      <button class="copy-btn" style="margin-left:auto" onclick="event.stopPropagation();copyText(${JSON.stringify(txt)})">Copy</button>
      <span class="toggle">▾</span>
    </div>
    <div class="cb">${html}</div>
  </div>`);
  saveHistory(lastTask,txt.slice(0,120));
  notifyDone();
}

function renderError(txt){
  push(`<div class="card errc">
    <div class="ch"><span class="ico">❌</span><span class="lbl">Error</span></div>
    <div class="cb">${esc(txt)}</div>
  </div>`);
}

function addRunHeader(task){
  runCount++;
  push(`<div class="run-hdr">
    <span class="run-badge">Run #${runCount}</span>
    <span class="run-ts">${new Date().toLocaleTimeString()}</span>
    <span class="run-task">${esc(task)}</span>
  </div>`);
}

function toggleCard(ch){
  const cb = ch.nextElementSibling;
  const hidden = cb.style.display === 'none';
  cb.style.display = hidden ? '' : 'none';
  ch.querySelector('.toggle').textContent = hidden ? '▾' : '▸';
}
function expandResult(preId,spanId,btn){
  document.getElementById(preId).textContent=document.getElementById(spanId).textContent;
  btn.remove();
}

/* browser notification on completion */
function notifyDone(){
  if(!('Notification' in window)) return;
  if(Notification.permission==='granted'){
    new Notification('Butcher — Scan complete',{body:lastTask.slice(0,80),icon:'/favicon.ico'});
  } else if(Notification.permission!=='denied'){
    Notification.requestPermission();
  }
}

/* stop */
function stopAgent(){
  if(evSrc){evSrc.close();evSrc=null;}
  push(`<div class="stopped-sep">— stopped —</div>`);
  setStatus('done','Stopped');
}

/* core runner */
function runAgent(task){
  if(evSrc){evSrc.close();evSrc=null;}
  lastTask=task; autoScroll=true;
  resetCounters();
  document.getElementById('scrollPaused').classList.remove('visible');
  hideWelcome(); addRunHeader(task);
  setStatus('running','Running…');
  showThinking('Butcher is thinking…');

  evSrc=new EventSource('/stream?task='+encodeURIComponent(task));
  evSrc.onmessage=(e)=>{
    const d=JSON.parse(e.data);
    switch(d.type){
      case 'step':
        renderStep(d.step);
        showThinking('Butcher is thinking…');
        break;
      case 'thought':
        hideThinking(); renderThought(d.text);
        showThinking('Choosing next tool…');
        break;
      case 'tool_call':
        hideThinking(); renderToolCall(d.name,d.input);
        showThinking(`Running ${d.name}…`);
        break;
      case 'tool_result':
        hideThinking(); renderToolResult(d.name,d.output);
        showThinking('Analysing output…');
        break;
      case 'final':
        hideThinking(); renderFinal(d.text); setStatus('done','Done');
        break;
      case 'error':
        hideThinking(); renderError(d.text); setStatus('error','Error');
        break;
      case 'done':
        hideThinking(); evSrc.close(); evSrc=null;
        if(document.getElementById('dot').classList.contains('running')) setStatus('done','Done');
        break;
    }
  };
  evSrc.onerror=()=>{hideThinking();renderError('Stream connection lost.');evSrc.close();evSrc=null;setStatus('error','Error');};
}

function runOrStop(){if(evSrc) stopAgent();else runCustom();}

function runCustom(){
  const q=document.getElementById('mainInput').value.trim();
  if(!q) return;
  document.querySelectorAll('.scn').forEach(b=>b.classList.remove('active'));
  runAgent(q);
}

function runScenario(btn){
  if(evSrc) stopAgent();
  document.querySelectorAll('.scn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  fetch('/scenario/'+btn.dataset.key)
    .then(r=>r.json())
    .then(d=>{
      if(d.task){document.getElementById('mainInput').value=d.task;autoResize(document.getElementById('mainInput'));runAgent(d.task);}
      else renderError(d.error||'Unknown scenario');
    });
}

function quickRun(key){
  switchTab('ops');
  const btn=document.querySelector(`.scn[data-key="${key}"]`);
  if(btn) runScenario(btn);
}

/* tool status */
fetch('/tools-status')
  .then(r=>r.json())
  .then(data=>{
    document.getElementById('toolStatus').innerHTML=Object.entries(data).map(([k,v])=>{
      const ready = typeof v === 'object' ? v.ready : v;
      const install = typeof v === 'object' ? (v.install||'') : '';
      const cls = ready ? 'ok' : 'miss';
      const label = ready ? 'ready' : 'missing';
      const installRow = (!ready && install)
        ? `<div class="ts-install" title="click to copy" onclick="navigator.clipboard.writeText(${JSON.stringify(install)})">📋 ${esc(install)}</div>`
        : '';
      return `<div class="ts-item">
        <div class="ts-main">
          <span class="ts-dot ${cls}"></span>
          <span class="ts-name">${esc(k)}</span>
          <span class="ts-badge ${cls}">${label}</span>
        </div>${installRow}
      </div>`;
    }).join('');
  }).catch(()=>{});
</script>
</body>
</html>
"""


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    import uvicorn
    import webbrowser
    import threading
    def _open():
        import time; time.sleep(1.2)
        webbrowser.open("http://localhost:8000")
    threading.Thread(target=_open, daemon=True).start()
    print("Butcher Security Agent → http://localhost:8000")
    uvicorn.run("quavo:app", host="0.0.0.0", port=8000, reload=True)
