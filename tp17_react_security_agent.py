"""
TP17 - Tool-Using Security Agents (ReAct Pattern)
Agents invoking security tools through Claude function calling.

ReAct = Reason + Act: think → call tool → observe → repeat
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
import urllib.parse
import urllib.error
from typing import Any, Generator
import anthropic


# ============================================================
# PART 1 — TOOL DEFINITIONS
# ============================================================

TOOLS: list[dict] = [
    {
        "name": "nmap_scan",
        "description": (
            "Run nmap on a target host or network. Returns open ports, services, "
            "OS fingerprint. Only use on hosts you are authorized to scan."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP, hostname, or CIDR (e.g. 192.168.1.1 or 10.0.0.0/24)",
                },
                "flags": {
                    "type": "string",
                    "description": (
                        "nmap flags string. Examples: '-sV' (version), '-sS' (stealth), "
                        "'-A' (aggressive), '-sU' (UDP), '-sn' (ping sweep), "
                        "'-p 22,80,443' (specific ports), '-p 1-1024' (range), "
                        "'--script vuln' (vuln scripts). Can combine: '-sV -p 1-1024'"
                    ),
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "http_probe",
        "description": (
            "Probe an HTTP/HTTPS endpoint. Returns status code, security headers, "
            "server banner, redirect chain, and a body excerpt. "
            "Useful for web recon, detecting frameworks, and checking security posture."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL including scheme, e.g. https://target.com/admin",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "HEAD", "POST", "OPTIONS"],
                    "description": "HTTP method (default GET)",
                },
                "headers": {
                    "type": "object",
                    "description": "Extra request headers as key-value dict",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "dns_lookup",
        "description": (
            "Resolve DNS records for a domain. Supports A, AAAA, MX, NS, TXT, CNAME, PTR. "
            "Useful for recon, SPF/DMARC checks, subdomain enumeration hints."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain or IP to query"},
                "record_type": {
                    "type": "string",
                    "enum": ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "PTR", "ANY"],
                    "description": "DNS record type (default A)",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "osquery_query",
        "description": (
            "Execute an osquery SQL query against the local host. "
            "Tables include: processes, listening_ports, users, logged_in_users, "
            "startup_items, scheduled_tasks, arp_cache, etc."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "SQL against osquery virtual tables. "
                        "E.g. 'SELECT pid, name, listening FROM listening_ports JOIN processes USING (pid)'"
                    ),
                }
            },
            "required": ["query"],
        },
    },
    {
        "name": "splunk_search",
        "description": (
            "Search Splunk SIEM using SPL. "
            "Useful for hunting IOCs, failed auth events, network anomalies."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "search": {
                    "type": "string",
                    "description": "SPL query, e.g. 'index=security failed password | stats count by src_ip | sort -count'",
                },
                "time_range": {
                    "type": "string",
                    "description": "Relative time: '-1h', '-24h', '-7d' (default '-1h')",
                },
                "max_results": {"type": "integer", "description": "Max results (default 50)"},
            },
            "required": ["search"],
        },
    },
    {
        "name": "metasploit_run",
        "description": (
            "Run a Metasploit module. ONLY on hosts explicitly in pentest scope. "
            "Use auxiliary scanners (not exploits) unless specifically required."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "module": {
                    "type": "string",
                    "description": "Module path, e.g. 'auxiliary/scanner/smb/smb_ms17_010'",
                },
                "options": {
                    "type": "object",
                    "description": "Module options, must include RHOSTS. E.g. {'RHOSTS': '10.0.0.1', 'THREADS': 4}",
                },
            },
            "required": ["module", "options"],
        },
    },
]


# ============================================================
# PART 2 — TOOL EXECUTORS (no mocks — real or clear error)
# ============================================================

def _exec(cmd: list[str], timeout: int = 120, input_data: str | None = None) -> tuple[str, int]:
    """Run a subprocess, return (output, returncode)."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, input=input_data,
        )
        out = (r.stdout or "") + (r.stderr or "")
        return out.strip() or "(no output)", r.returncode
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s", -1
    except Exception as exc:
        return f"[EXEC ERROR] {exc}", -1


def _not_found(tool: str, install: str) -> str:
    return f"[TOOL NOT FOUND] '{tool}' is not on PATH.\n  Install: {install}"


# ── nmap ──────────────────────────────────────────────────────

def execute_nmap(target: str, flags: str = "-sV") -> str:
    if not shutil.which("nmap"):
        return _not_found("nmap", "https://nmap.org/download.html  |  apt install nmap  |  brew install nmap")
    cmd = ["nmap"] + flags.split() + [target]
    out, _ = _exec(cmd, timeout=180)
    return out


# ── http_probe ────────────────────────────────────────────────

_SECURITY_HEADERS = {
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
    "x-powered-by", "server", "set-cookie",
}

def execute_http_probe(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
) -> str:
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Security-Audit/1.0)",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)

    try:
        req = urllib.request.Request(url, method=method, headers=req_headers)
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
        with opener.open(req, timeout=15) as resp:
            status     = resp.status
            resp_hdrs  = dict(resp.headers)
            body_bytes = resp.read(2048)

        lines = [f"HTTP {status}  {url}"]
        lines.append("\n--- Security-relevant headers ---")
        for k, v in resp_hdrs.items():
            if k.lower() in _SECURITY_HEADERS:
                lines.append(f"  {k}: {v}")

        missing = _SECURITY_HEADERS - {k.lower() for k in resp_hdrs}
        if missing:
            lines.append("\n--- MISSING security headers ---")
            for h in sorted(missing):
                lines.append(f"  ✗ {h}")

        try:
            body = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            body = repr(body_bytes[:500])
        lines.append(f"\n--- Body excerpt (first 1 KB) ---\n{body[:1000]}")

        return "\n".join(lines)

    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}  {e.reason}\n{dict(e.headers)}"
    except Exception as exc:
        return f"[HTTP ERROR] {exc}"


# ── dns_lookup ────────────────────────────────────────────────

def execute_dns_lookup(domain: str, record_type: str = "A") -> str:
    # Try dig first (most info), fall back to nslookup, then socket for A
    if shutil.which("dig"):
        out, _ = _exec(["dig", "+noall", "+answer", "+authority", record_type, domain])
        return out or f"(no {record_type} records found for {domain})"

    if shutil.which("nslookup"):
        out, _ = _exec(["nslookup", "-type=" + record_type, domain])
        return out

    # stdlib fallback for A/AAAA only
    if record_type in ("A", "AAAA", "ANY"):
        try:
            family = socket.AF_INET6 if record_type == "AAAA" else socket.AF_INET
            results = socket.getaddrinfo(domain, None, family)
            addrs = list({r[4][0] for r in results})
            return f"{domain} {record_type} → {', '.join(addrs)}"
        except socket.gaierror as e:
            return f"[DNS ERROR] {e}"

    return _not_found("dig / nslookup", "apt install dnsutils  |  brew install bind  |  (built-in on Windows)")


# ── osquery ───────────────────────────────────────────────────

def execute_osquery(query: str) -> str:
    binary = shutil.which("osqueryi") or shutil.which("osqueryi.exe")
    if not binary:
        return _not_found("osqueryi", "https://osquery.io/downloads/official/")
    out, _ = _exec([binary, "--json", query], timeout=30)
    # Pretty-print if valid JSON
    try:
        data = json.loads(out)
        return json.dumps(data, indent=2)
    except json.JSONDecodeError:
        return out


# ── splunk ────────────────────────────────────────────────────

def execute_splunk(search: str, time_range: str = "-1h", max_results: int = 50) -> str:
    url   = os.getenv("SPLUNK_URL")
    token = os.getenv("SPLUNK_TOKEN")

    if not url or not token:
        return (
            "[CONFIG MISSING] Splunk not configured.\n"
            "  Add to .env:\n"
            "    SPLUNK_URL=https://your-splunk:8089\n"
            "    SPLUNK_TOKEN=your-bearer-token"
        )

    payload = urllib.parse.urlencode({
        "search": f"search {search}",
        "earliest_time": time_range,
        "count": max_results,
        "output_mode": "json",
    }).encode()

    try:
        req = urllib.request.Request(
            f"{url.rstrip('/')}/services/search/jobs/export",
            data=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        # Disable SSL verification for self-signed Splunk certs
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            raw = resp.read().decode()
        # Each line is a JSON object (Splunk streaming format)
        events = []
        for line in raw.strip().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return json.dumps(events, indent=2) if events else "(no results)"
    except Exception as exc:
        return f"[SPLUNK ERROR] {exc}"


# ── metasploit ────────────────────────────────────────────────

def execute_metasploit(module: str, options: dict[str, Any]) -> str:
    msf = shutil.which("msfconsole")
    if not msf:
        return _not_found(
            "msfconsole",
            "https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
        )

    rc_lines = [f"use {module}"]
    for k, v in options.items():
        rc_lines.append(f"set {k} {v}")
    rc_lines += ["run", "exit -y"]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
        f.write("\n".join(rc_lines))
        rc_path = f.name

    try:
        out, _ = _exec([msf, "-q", "-r", rc_path], timeout=180)
        return out
    finally:
        try:
            os.unlink(rc_path)
        except OSError:
            pass


# ============================================================
# PART 3 — TOOL DISPATCH
# ============================================================

def dispatch_tool(name: str, inputs: dict[str, Any]) -> str:
    if name == "nmap_scan":
        return execute_nmap(
            target=inputs["target"],
            flags=inputs.get("flags", "-sV"),
        )
    if name == "http_probe":
        return execute_http_probe(
            url=inputs["url"],
            method=inputs.get("method", "GET"),
            headers=inputs.get("headers"),
        )
    if name == "dns_lookup":
        return execute_dns_lookup(
            domain=inputs["domain"],
            record_type=inputs.get("record_type", "A"),
        )
    if name == "osquery_query":
        return execute_osquery(query=inputs["query"])
    if name == "splunk_search":
        return execute_splunk(
            search=inputs["search"],
            time_range=inputs.get("time_range", "-1h"),
            max_results=inputs.get("max_results", 50),
        )
    if name == "metasploit_run":
        return execute_metasploit(
            module=inputs["module"],
            options=inputs.get("options", {}),
        )
    return f"[ERROR] Unknown tool: {name}"


# ============================================================
# PART 4 — TOOL AVAILABILITY CHECK
# ============================================================

def check_tools() -> dict[str, bool | str]:
    """Return install status of each security tool."""
    return {
        "nmap":        bool(shutil.which("nmap")),
        "osquery":     bool(shutil.which("osqueryi") or shutil.which("osqueryi.exe")),
        "metasploit":  bool(shutil.which("msfconsole")),
        "splunk":      bool(os.getenv("SPLUNK_URL") and os.getenv("SPLUNK_TOKEN")),
        "dig":         bool(shutil.which("dig")),
        "nslookup":    bool(shutil.which("nslookup")),
    }


# ============================================================
# PART 5 — ReAct AGENT (streaming generator + sync wrapper)
# ============================================================

SCENARIOS: dict[str, str] = {
    "recon": (
        "Perform full reconnaissance on 192.168.1.10. "
        "Start with a version scan on common ports, run a DNS lookup, "
        "then check local listening ports and running processes with osquery. "
        "Summarize the attack surface."
    ),
    "web_audit": (
        "Audit the web server at http://testphp.vulnweb.com. "
        "First scan it with nmap to confirm HTTP/HTTPS ports, "
        "then probe the HTTP endpoint for security headers and server info. "
        "Flag any missing headers and identify the technology stack."
    ),
    "brute_force_hunt": (
        "Investigate whether there has been a brute-force SSH attack in the last hour. "
        "Search Splunk for failed authentication events, identify attacking IPs, "
        "count attempts per source, and recommend remediation."
    ),
    "vuln_scan": (
        "Perform an authorized vulnerability scan on 192.168.1.10. "
        "Use nmap with vuln scripts, then run the Metasploit MS17-010 scanner. "
        "Summarize findings and assign a risk rating."
    ),
    "host_audit": (
        "Audit this host with osquery: list all listening ports with owning processes, "
        "show logged-in users, check startup items or scheduled tasks, "
        "and flag anything suspicious (unexpected ports, unknown processes, etc.)."
    ),
}

_SYSTEM = (
    "You are an expert penetration tester. Use the available tools to investigate "
    "the request methodically. Reason about each step before acting, interpret "
    "tool output carefully, and chain calls as needed. "
    "Only run metasploit_run on hosts explicitly in scope. "
    "End with a structured findings summary including risk ratings."
)


def react_agent_stream(task: str, max_steps: int = 12) -> Generator[dict, None, None]:
    """
    Streaming ReAct loop. Yields event dicts:
      {"type": "step",        "step": int}
      {"type": "thought",     "text": str}
      {"type": "tool_call",   "name": str, "input": dict}
      {"type": "tool_result", "name": str, "output": str}
      {"type": "final",       "text": str}
      {"type": "error",       "text": str}
    """
    client   = anthropic.Anthropic()
    messages: list[dict] = [{"role": "user", "content": task}]

    for step in range(1, max_steps + 1):
        yield {"type": "step", "step": step}

        response = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=4096,
            system=_SYSTEM,
            tools=TOOLS,
            messages=messages,
        )

        tool_results = []
        final_text   = None
        has_tools    = any(b.type == "tool_use" for b in response.content)

        for block in response.content:
            if block.type == "text":
                final_text = block.text
                if has_tools:
                    yield {"type": "thought", "text": block.text}

            elif block.type == "tool_use":
                yield {"type": "tool_call", "name": block.name, "input": block.input}
                output = dispatch_tool(block.name, block.input)
                yield {"type": "tool_result", "name": block.name, "output": output}
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     output,
                })

        messages.append({"role": "assistant", "content": response.content})

        if tool_results:
            messages.append({"role": "user", "content": tool_results})
            continue

        yield {"type": "final", "text": final_text or "(no answer)"}
        return

    yield {"type": "final", "text": "[Max steps reached] " + (final_text or "")}


def react_agent(task: str, max_steps: int = 12) -> str:
    """CLI wrapper — prints events to stdout."""
    sep   = "-" * 62
    final = ""
    for ev in react_agent_stream(task, max_steps):
        t = ev["type"]
        if t == "step":
            print(f"\n{sep}\nSTEP {ev['step']}\n{sep}")
        elif t == "thought":
            print(f"\n[Thought]\n{ev['text']}")
        elif t == "tool_call":
            print(f"\n[{ev['name']}] {json.dumps(ev['input'], indent=2)}")
        elif t == "tool_result":
            print(f"[result]\n{ev['output']}")
        elif t == "final":
            final = ev["text"]
            print(f"\n{'='*62}\nFINAL ANSWER\n{'='*62}\n{final}")
        elif t == "error":
            final = ev["text"]
            print(f"[ERROR] {final}")
    return final


# ============================================================
# CLI entry point
# ============================================================

if __name__ == "__main__":
    import sys

    # Load .env
    try:
        from dotenv import load_dotenv; load_dotenv()
    except ImportError:
        env = os.path.join(os.path.dirname(__file__), ".env")
        if os.path.exists(env):
            with open(env) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, _, v = line.partition("=")
                        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

    key  = sys.argv[1] if len(sys.argv) > 1 else "recon"
    task = SCENARIOS.get(key)
    if not task:
        print(f"Unknown scenario. Choose: {list(SCENARIOS)}")
        sys.exit(1)

    print(f"\nScenario: {key}\nTask: {task}\n")
    react_agent(task)
