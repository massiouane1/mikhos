# 🛡️ Security ReAct Agent

A tool-using AI security agent built with the **ReAct pattern** (Reason + Act) using Claude's function calling. The agent chains security tools autonomously to investigate targets, hunt threats, and audit systems — all through a live-streaming web UI.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python) ![Claude](https://img.shields.io/badge/Claude-Opus%204-orange?logo=anthropic) ![FastAPI](https://img.shields.io/badge/FastAPI-latest-green?logo=fastapi) ![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## How It Works

```
User Query → Claude reasons → calls security tool → observes result → reasons again → ...→ Final Answer
```

Claude autonomously decides which tools to call, in what order, and how to chain results together — no hardcoded logic.

---

## Tools

| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scan, service version detection, OS fingerprint |
| `http_probe` | HTTP/HTTPS audit — status, security headers, server banner, body |
| `dns_lookup` | A / MX / NS / TXT / CNAME / PTR record resolution |
| `osquery_query` | SQL queries against the local host (processes, ports, users, tasks) |
| `splunk_search` | SPL queries against a Splunk SIEM for threat hunting |
| `metasploit_run` | Run Metasploit modules on authorized targets |

All tools use real binaries (`nmap`, `osqueryi`, `msfconsole`, `dig`). If a tool isn't installed, it returns a clear error with install instructions — no fake mock data.

---

## UI

Dark-theme streaming web console built with vanilla JS + FastAPI SSE:

- **Live stream** — each reasoning step, tool call, and result appears in real time
- **Run history** — previous queries stay visible, timestamped and labelled
- **Tool status** — sidebar shows which tools are installed on your system
- **Copy button** — on every result block
- **4 preset scenarios** + custom free-text query box

---

## Quickstart

### 1. Install dependencies

```bash
pip install fastapi uvicorn anthropic
```

Optional (for real tool execution):
```bash
# nmap
sudo apt install nmap          # Linux
brew install nmap              # macOS
# https://nmap.org/download.html  # Windows

# osquery
# https://osquery.io/downloads/official/

# Metasploit
# https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html
```

### 2. Configure

```bash
cp .env.example .env
# edit .env and set your ANTHROPIC_API_KEY
```

### 3. Run

```bash
python tp17_server.py
# open http://localhost:8000
```

---

## Scenarios

| Scenario | What it does |
|----------|--------------|
| **Recon Scan** | nmap version scan + DNS lookup + osquery host surface map |
| **Web Audit** | nmap port check + HTTP probe for headers, server info, missing security controls |
| **Brute Force Hunt** | Splunk SPL hunt for failed SSH auth, top attacking IPs, remediation advice |
| **Vuln Scan** | nmap `--script vuln` + Metasploit MS17-010 EternalBlue checker |
| **Host Audit** | osquery: listening ports, owning processes, logged-in users, scheduled tasks |

Or type any free-form query — the agent picks the right tools automatically.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | ✅ | Get from [console.anthropic.com](https://console.anthropic.com) |
| `SPLUNK_URL` | Optional | e.g. `https://splunk.company.com:8089` |
| `SPLUNK_TOKEN` | Optional | Splunk Bearer token |

---

## Architecture

```
tp17_react_security_agent.py   ← tool schemas, executors, ReAct loop (generator)
tp17_server.py                 ← FastAPI server, SSE streaming, embedded HTML/CSS/JS
```

The ReAct loop is a Python generator that `yield`s typed event dicts (`thought`, `tool_call`, `tool_result`, `final`). The server runs it in a background thread and streams events to the browser via Server-Sent Events.

---

## ⚠️ Legal

Only use against systems you own or have explicit written authorization to test. Unauthorized scanning is illegal in most jurisdictions.

---

## License

MIT
