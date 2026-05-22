"""
Butcher - Security ReAct Agent (ReAct Pattern)
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
    {
        "name": "ssl_audit",
        "description": (
            "Inspect the TLS/SSL certificate of a host. Returns cert subject, issuer, "
            "validity dates, SANs, cipher suite, and flags weak configs or expiry issues."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP"},
                "port": {"type": "integer", "description": "Port (default 443)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "banner_grab",
        "description": (
            "Raw TCP/UDP banner grab on a port. Sends a probe and returns whatever "
            "the service replies with. Useful for fingerprinting non-HTTP services."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target IP or hostname"},
                "port": {"type": "integer", "description": "Port to connect to"},
                "probe": {"type": "string", "description": "Optional string to send before reading (e.g. 'HEAD / HTTP/1.0\\r\\n\\r\\n')"},
            },
            "required": ["host", "port"],
        },
    },
    {
        "name": "whois_lookup",
        "description": (
            "WHOIS / RDAP lookup for a domain or IP. Returns registrar, registrant, "
            "creation/expiry dates, name servers, and ASN info."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Domain name or IP address"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "subdomain_enum",
        "description": (
            "Enumerate subdomains for a domain using DNS brute-force and certificate "
            "transparency logs. Returns discovered live subdomains with IPs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Root domain, e.g. 'example.com'"},
                "wordlist": {"type": "string", "description": "Preset wordlist: 'small' (50), 'medium' (200), 'large' (500). Default 'small'"},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "shodan_search",
        "description": (
            "Query Shodan for internet-exposed hosts matching a search term or IP. "
            "Returns open ports, banners, CVEs, and geolocation. Requires SHODAN_API_KEY in .env."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Shodan search string or IP, e.g. 'apache 2.4 country:US' or '8.8.8.8'"},
                "limit": {"type": "integer", "description": "Max results (default 10)"},
            },
            "required": ["query"],
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


def _nmap_bin() -> str | None:
    return (
        shutil.which("nmap")
        or (r"C:\Program Files (x86)\Nmap\nmap.exe"
            if os.path.exists(r"C:\Program Files (x86)\Nmap\nmap.exe") else None)
        or (r"C:\Program Files\Nmap\nmap.exe"
            if os.path.exists(r"C:\Program Files\Nmap\nmap.exe") else None)
    )


# ── nmap ──────────────────────────────────────────────────────

def execute_nmap(target: str, flags: str = "-sV") -> str:
    nmap = _nmap_bin()
    if not nmap:
        return _not_found("nmap", "https://nmap.org/download.html  |  winget install nmap")
    out, _ = _exec([nmap] + flags.split() + [target], timeout=180)
    # Auto-retry with -Pn if host blocks ICMP ping probes
    if "Host seems down" in out and "-Pn" not in flags:
        out2, rc = _exec([nmap] + flags.split() + ["-Pn", target], timeout=180)
        return "[Retried with -Pn — host blocks ping]\n\n" + out2
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

def _windows_osquery_fallback(query: str) -> str:
    """Map common osquery table queries to native Windows commands."""
    q = query.lower()
    parts = []

    if "listening_ports" in q or "open_sockets" in q or "network" in q:
        out, _ = _exec(["netstat", "-ano"], timeout=15)
        parts.append("=== Listening Ports (netstat -ano) ===\n" + out)

    if "processes" in q:
        out, _ = _exec(["tasklist", "/v", "/fo", "csv"], timeout=15)
        parts.append("=== Running Processes (tasklist /v) ===\n" + out[:4000])

    if "logged_in_users" in q:
        out, _ = _exec(["query", "user"], timeout=10)
        parts.append("=== Logged-in Users ===\n" + (out or "(none)"))

    if "users" in q and "logged_in" not in q:
        out, _ = _exec(["net", "user"], timeout=10)
        parts.append("=== Local Users (net user) ===\n" + out)

    if "scheduled_tasks" in q:
        out, _ = _exec(["schtasks", "/query", "/fo", "LIST"], timeout=20)
        parts.append("=== Scheduled Tasks ===\n" + out[:4000])

    if "startup_items" in q or "startup" in q:
        out, _ = _exec(["wmic", "startup", "list", "brief"], timeout=15)
        parts.append("=== Startup Items (wmic) ===\n" + out[:2000])

    if "arp_cache" in q:
        out, _ = _exec(["arp", "-a"], timeout=10)
        parts.append("=== ARP Cache ===\n" + out)

    if "patches" in q or "programs" in q or "software" in q:
        out, _ = _exec(["wmic", "product", "get", "Name,Version", "/format:csv"], timeout=30)
        parts.append("=== Installed Software ===\n" + out[:3000])

    if not parts:
        # Generic: ports + processes
        out, _ = _exec(["netstat", "-ano"], timeout=15)
        parts.append("=== Network Connections (netstat -ano) ===\n" + out)
        out, _ = _exec(["tasklist", "/fo", "csv"], timeout=15)
        parts.append("=== Processes (tasklist) ===\n" + out[:2000])

    header = "[NOTE] osqueryi not installed — using native Windows equivalents.\n\n"
    return header + "\n\n".join(parts)


def execute_osquery(query: str) -> str:
    binary = shutil.which("osqueryi") or shutil.which("osqueryi.exe")
    if not binary:
        for path in [
            r"C:\Program Files\osquery\osqueryi.exe",
            r"C:\Program Files (x86)\osquery\osqueryi.exe",
        ]:
            if os.path.exists(path):
                binary = path
                break

    if binary:
        out, _ = _exec([binary, "--json", query], timeout=30)
        try:
            return json.dumps(json.loads(out), indent=2)
        except json.JSONDecodeError:
            return out

    return _windows_osquery_fallback(query)


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
        # Fallback: run nmap equivalent scripts for common modules
        rhosts = options.get("RHOSTS", options.get("rhosts", ""))
        nmap = _nmap_bin()
        mod_low = module.lower()
        if nmap and rhosts:
            if "ms17_010" in mod_low or ("smb" in mod_low and "vuln" in mod_low):
                note = f"[NOTE] msfconsole not installed. Running nmap smb-vuln equivalent for {module}.\n\n"
                out, _ = _exec([nmap, "-p", "445,139", "--script",
                                 "smb-vuln-ms17-010,smb-security-mode,smb2-security-mode",
                                 rhosts], timeout=120)
                return note + out
            if "portscan" in mod_low or "scanner" in mod_low:
                note = f"[NOTE] msfconsole not installed. Running nmap port scan equivalent.\n\n"
                out, _ = _exec([nmap, "-sV", "-p", "1-1024", rhosts], timeout=120)
                return note + out
            # Generic: run nmap vuln scripts
            note = f"[NOTE] msfconsole not installed. Running nmap --script vuln equivalent for {module}.\n\n"
            out, _ = _exec([nmap, "--script", "vuln", rhosts], timeout=180)
            return note + out
        return (
            "[TOOL NOT FOUND] msfconsole not installed.\n"
            "  Install: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html\n"
            "  Tip: nmap --script vuln <target> covers many of the same checks."
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


# ── ssl_audit ─────────────────────────────────────────────────

def execute_ssl_audit(host: str, port: int = 443) -> str:
    import ssl, datetime
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=10),
                              server_hostname=host) as s:
            cert    = s.getpeercert()
            cipher  = s.cipher()
            version = s.version()

        def _fmt_dn(dn):
            return ", ".join(f"{k}={v}" for rdn in dn for k, v in rdn)

        subject  = _fmt_dn(cert.get("subject", []))
        issuer   = _fmt_dn(cert.get("issuer", []))
        not_bef  = cert.get("notBefore", "?")
        not_aft  = cert.get("notAfter", "?")
        sans     = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        # Expiry check
        try:
            expiry = datetime.datetime.strptime(not_aft, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days
            expiry_flag = f"⚠️  EXPIRES IN {days_left} DAYS" if days_left < 30 else f"✓ {days_left} days remaining"
        except Exception:
            expiry_flag = not_aft

        weak = []
        if cipher and cipher[0] and any(w in cipher[0].upper() for w in ("RC4","DES","NULL","EXPORT","MD5")):
            weak.append(f"WEAK CIPHER: {cipher[0]}")
        if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            weak.append(f"WEAK PROTOCOL: {version}")

        lines = [
            f"=== SSL/TLS Audit: {host}:{port} ===",
            f"Protocol  : {version}",
            f"Cipher    : {cipher[0] if cipher else '?'} ({cipher[2] if cipher else '?'} bits)",
            f"Subject   : {subject}",
            f"Issuer    : {issuer}",
            f"Valid From: {not_bef}",
            f"Valid To  : {not_aft}  — {expiry_flag}",
            f"SANs ({len(sans)}): {', '.join(sans[:10])}{'...' if len(sans)>10 else ''}",
        ]
        if weak:
            lines.append("\n⚠️  WEAKNESSES FOUND:")
            lines.extend(f"  {w}" for w in weak)
        else:
            lines.append("✓ No obvious cipher/protocol weaknesses")
        return "\n".join(lines)

    except ConnectionRefusedError:
        return f"[ERROR] Connection refused — {host}:{port} not listening"
    except Exception as exc:
        return f"[SSL ERROR] {exc}"


# ── banner_grab ───────────────────────────────────────────────

def execute_banner_grab(host: str, port: int, probe: str | None = None) -> str:
    try:
        with socket.create_connection((host, port), timeout=8) as s:
            if probe:
                s.sendall(probe.replace("\\r\\n", "\r\n").encode())
            else:
                # Common probes by port
                default_probes = {
                    21: b"",  22: b"",  25: b"EHLO test\r\n",
                    80: b"HEAD / HTTP/1.0\r\n\r\n",
                    110: b"", 143: b"", 443: b"",
                }
                p = default_probes.get(port, b"")
                if p:
                    s.sendall(p)
            s.settimeout(4)
            chunks = []
            try:
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if len(b"".join(chunks)) > 4096:
                        break
            except socket.timeout:
                pass
            raw = b"".join(chunks)
        banner = raw.decode("utf-8", errors="replace").strip()
        if not banner:
            return f"[{host}:{port}] Connection succeeded but no banner returned."
        return f"=== Banner: {host}:{port} ===\n{banner[:2000]}"
    except ConnectionRefusedError:
        return f"[{host}:{port}] Port closed / connection refused"
    except socket.timeout:
        return f"[{host}:{port}] Timeout — host did not respond"
    except Exception as exc:
        return f"[BANNER ERROR] {exc}"


# ── whois_lookup ──────────────────────────────────────────────

def execute_whois(query: str) -> str:
    # Try CLI whois first
    if shutil.which("whois"):
        out, rc = _exec(["whois", query], timeout=15)
        if out and "[EXEC ERROR]" not in out:
            return out[:4000]

    # RDAP fallback (pure HTTP, no deps)
    try:
        is_ip = False
        try:
            socket.inet_pton(socket.AF_INET, query)
            is_ip = True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, query)
                is_ip = True
            except socket.error:
                pass

        if is_ip:
            rdap_url = f"https://rdap.arin.net/registry/ip/{urllib.parse.quote(query)}"
        else:
            tld = query.rsplit(".", 1)[-1]
            rdap_url = f"https://rdap.verisign.com/com/v1/domain/{urllib.parse.quote(query)}"
            if tld not in ("com", "net"):
                rdap_url = f"https://rdap.org/domain/{urllib.parse.quote(query)}"

        req = urllib.request.Request(rdap_url,
              headers={"User-Agent": "Butcher-SecurityAgent/1.0", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read())

        lines = [f"=== RDAP: {query} ==="]
        if "handle" in data:
            lines.append(f"Handle     : {data['handle']}")
        if "ldhName" in data:
            lines.append(f"Domain     : {data['ldhName']}")
        for ev in data.get("events", []):
            lines.append(f"{ev.get('eventAction','?').title():12}: {ev.get('eventDate','?')[:10]}")
        for ns in data.get("nameservers", []):
            lines.append(f"Nameserver : {ns.get('ldhName','?')}")
        entities = data.get("entities", [])
        for ent in entities[:3]:
            roles = ", ".join(ent.get("roles", []))
            vcards = ent.get("vcardArray", [None, []])[1]
            name = next((v[3] for v in vcards if v[0] == "fn"), "?")
            lines.append(f"Entity ({roles}): {name}")
        return "\n".join(lines)

    except urllib.error.HTTPError as e:
        return f"[WHOIS ERROR] RDAP returned HTTP {e.code} — try 'whois' CLI: winget install whois"
    except Exception as exc:
        return f"[WHOIS ERROR] {exc}\n  Install whois: winget install --id=DEVCOM.Whois"


# ── subdomain_enum ────────────────────────────────────────────

_SUBDOMAINS_SMALL = [
    "www","mail","ftp","smtp","pop","imap","vpn","remote","api","dev","staging",
    "test","beta","admin","portal","app","blog","shop","store","support","help",
    "login","auth","cdn","static","assets","img","media","ns1","ns2","mx",
    "autodiscover","webmail","cpanel","whm","server","host","direct","secure",
    "m","mobile","docs","wiki","git","gitlab","github","jenkins","ci","jira",
    "confluence","dashboard","status","monitor","grafana","kibana",
]
_SUBDOMAINS_MEDIUM = _SUBDOMAINS_SMALL + [
    "vpn2","vpn1","remote2","lab","sandbox","qa","uat","prod","stg","int",
    "internal","intranet","extranet","corp","office","exchange","outlook",
    "teams","sharepoint","sso","saml","idp","oauth","token","api2","v1","v2",
    "rest","graphql","ws","wss","socket","upload","download","files","backup",
    "db","database","mysql","postgres","redis","mongo","elastic","kibana2",
    "logstash","fluentd","prometheus","alertmanager","registry","docker",
    "k8s","kubernetes","rancher","vault","consul","nomad","terraform","ansible",
    "puppet","chef","nagios","zabbix","opsgenie","pagerduty","datadog","newrelic",
    "splunk","graylog","syslog","ntp","dns","dns2","dhcp","proxy","firewall",
    "waf","lb","loadbalancer","ha","cluster","node1","node2","worker","master",
    "replica","slave","primary","secondary","read","write","pub","sub","queue",
    "broker","kafka","rabbitmq","activemq","celery","worker1","worker2",
    "cron","batch","scheduler","payment","checkout","cart","order","invoice",
    "report","analytics","tracking","metrics","telemetry","log","logs","audit",
    "billing","account","accounts","user","users","profile","member","members",
    "forum","community","feedback","survey","ticket","helpdesk","kb",
]

def execute_subdomain_enum(domain: str, wordlist: str = "small") -> str:
    domain = domain.lstrip("*.").strip()

    # Try subfinder first if available
    sf = shutil.which("subfinder")
    if sf:
        out, rc = _exec([sf, "-d", domain, "-silent", "-t", "50"], timeout=60)
        if out and "[EXEC ERROR]" not in out and "[TIMEOUT]" not in out:
            subs = [s.strip() for s in out.splitlines() if s.strip()]
            return f"=== subfinder: {domain} ({len(subs)} found) ===\n" + "\n".join(subs[:200])

    # DNS brute-force fallback
    words = _SUBDOMAINS_SMALL if wordlist == "small" else (
        _SUBDOMAINS_MEDIUM if wordlist == "medium" else
        _SUBDOMAINS_MEDIUM  # large = same for now, extend as needed
    )

    found = []
    for sub in words:
        fqdn = f"{sub}.{domain}"
        try:
            addr = socket.gethostbyname(fqdn)
            found.append(f"  {fqdn:<45} → {addr}")
        except socket.gaierror:
            pass

    header = f"=== Subdomain Enum: {domain} ({len(found)}/{len(words)} resolved) ===\n"
    note   = "[NOTE] subfinder not installed — using DNS brute-force. Install: https://github.com/projectdiscovery/subfinder/releases\n\n"
    if not found:
        return header + note + "No subdomains resolved."
    return header + (note if not sf else "") + "\n".join(found)


# ── shodan ────────────────────────────────────────────────────

def execute_shodan(query: str, limit: int = 10) -> str:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return (
            "[CONFIG MISSING] Shodan not configured.\n"
            "  1. Get free API key: https://account.shodan.io\n"
            "  2. Add to .env:  SHODAN_API_KEY=your-key\n"
            "  3. pip install shodan  (optional — we use the REST API directly)"
        )

    is_ip = False
    try:
        socket.inet_pton(socket.AF_INET, query)
        is_ip = True
    except socket.error:
        pass

    try:
        if is_ip:
            url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(query)}?key={api_key}"
        else:
            params = urllib.parse.urlencode({"key": api_key, "query": query, "minify": "true"})
            url = f"https://api.shodan.io/shodan/host/search?{params}"

        req = urllib.request.Request(url, headers={"User-Agent": "Butcher-SecurityAgent/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        lines = [f"=== Shodan: {query} ==="]
        if is_ip:
            lines.append(f"IP        : {data.get('ip_str','?')}")
            lines.append(f"Org       : {data.get('org','?')}")
            lines.append(f"Country   : {data.get('country_name','?')} ({data.get('country_code','?')})")
            lines.append(f"ISP       : {data.get('isp','?')}")
            lines.append(f"Hostnames : {', '.join(data.get('hostnames',[]) or ['none'])}")
            vulns = data.get("vulns", {})
            if vulns:
                lines.append(f"\n⚠️  CVEs ({len(vulns)}): {', '.join(list(vulns)[:10])}")
            ports = data.get("ports", [])
            lines.append(f"\nOpen ports: {', '.join(str(p) for p in sorted(ports))}")
            for svc in data.get("data", [])[:5]:
                lines.append(f"\n  :{svc.get('port')} {svc.get('transport','tcp')} — {svc.get('product','')} {svc.get('version','')}")
                banner = svc.get("data","").strip()
                if banner:
                    lines.append("    " + banner[:120].replace("\n", "\n    "))
        else:
            total = data.get("total", 0)
            lines.append(f"Total matches: {total}")
            for match in data.get("matches", [])[:limit]:
                lines.append(f"\n  {match.get('ip_str','?')}:{match.get('port','?')} "
                              f"[{match.get('org','?')} / {match.get('location',{}).get('country_name','?')}]")
                banner = match.get("data","").strip()
                if banner:
                    lines.append("    " + banner[:100].replace("\n"," "))
        return "\n".join(lines)

    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return f"[SHODAN ERROR] HTTP {e.code}: {body[:200]}"
    except Exception as exc:
        return f"[SHODAN ERROR] {exc}"


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
    if name == "ssl_audit":
        return execute_ssl_audit(
            host=inputs["host"],
            port=inputs.get("port", 443),
        )
    if name == "banner_grab":
        return execute_banner_grab(
            host=inputs["host"],
            port=inputs["port"],
            probe=inputs.get("probe"),
        )
    if name == "whois_lookup":
        return execute_whois(query=inputs["query"])
    if name == "subdomain_enum":
        return execute_subdomain_enum(
            domain=inputs["domain"],
            wordlist=inputs.get("wordlist", "small"),
        )
    if name == "shodan_search":
        return execute_shodan(
            query=inputs["query"],
            limit=inputs.get("limit", 10),
        )
    return f"[ERROR] Unknown tool: {name}"


# ============================================================
# PART 4 — TOOL AVAILABILITY CHECK
# ============================================================

def check_tools() -> dict:
    """Return install status of each security tool, with install hints for missing ones."""
    osquery_bin = (
        shutil.which("osqueryi") or shutil.which("osqueryi.exe")
        or (r"C:\Program Files\osquery\osqueryi.exe"
            if os.path.exists(r"C:\Program Files\osquery\osqueryi.exe") else None)
        or (r"C:\Program Files (x86)\osquery\osqueryi.exe"
            if os.path.exists(r"C:\Program Files (x86)\osquery\osqueryi.exe") else None)
    )

    def _tool(ready: bool, install: str = "") -> dict:
        return {"ready": ready, "install": install if not ready else ""}

    return {
        "nmap":           _tool(bool(_nmap_bin()),
                                "winget install nmap"),
        "osquery":        _tool(bool(osquery_bin),
                                "winget install osquery.osquery"),
        "osquery-fallback": _tool(True),
        "metasploit":     _tool(bool(shutil.which("msfconsole")),
                                "https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"),
        "splunk":         _tool(bool(os.getenv("SPLUNK_URL") and os.getenv("SPLUNK_TOKEN")),
                                "Add SPLUNK_URL + SPLUNK_TOKEN to .env"),
        "nslookup":       _tool(bool(shutil.which("nslookup"))),
        "ssl_audit":      _tool(True),
        "banner_grab":    _tool(True),
        "whois":          _tool(bool(shutil.which("whois")),
                                "winget install --id DEVCOM.Whois  (optional — RDAP fallback active)"),
        "subdomain_enum": _tool(True),
        "subfinder":      _tool(bool(shutil.which("subfinder")),
                                "https://github.com/projectdiscovery/subfinder/releases"),
        "shodan":         _tool(bool(os.getenv("SHODAN_API_KEY")),
                                "Add SHODAN_API_KEY to .env  (free at account.shodan.io)"),
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
