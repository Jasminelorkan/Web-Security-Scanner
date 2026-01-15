import asyncio
import aiohttp
import socket
import ssl
import os
import re
import json
import time
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template_string, request, jsonify, send_file
from functools import partial
from concurrent.futures import ThreadPoolExecutor

# optional PDF support
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    REPORTLAB = True
except Exception:
    REPORTLAB = False

# ---------- configuration ----------
APP_PORT = 5000
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)
HISTORY_FILE = Path("scan_history.json")
CONSENT_LOG = Path("consent.log")
MAX_LOG = 800

SUBDOMAIN_WORDLIST = ["www","api","admin","dev","test","staging","mail","ftp","beta","portal","dashboard","shop","static","cdn"]
COMMON_PORTS = [21,22,25,53,80,110,143,443,465,587,8080,8443,3306,5432,27017]

SAFE_XSS_PAYLOADS = ['<scr1pt>alert(1)</scr1pt>', '"><svg onload=1>']
SAFE_SQLI_PAYLOADS = ["' OR '1'='1' -- ", '" OR "1"="1" -- ']

# global UI state
STATE = {
    "running": False,
    "progress": 0,
    "target": None,
    "log": [],
    "last_report": None,
    "last_report_name": None,
    "stop_requested": False,
    "threat_score": None,
    "threat_class": None,
    "threat_reasons": []
}

def append_log(msg: str):
    t = datetime.now().strftime("%H:%M:%S")
    STATE["log"].append(f"[{t}] {msg}")
    if len(STATE["log"]) > MAX_LOG:
        STATE["log"].pop(0)

def safe_filename(s: str):
    return re.sub(r"[^0-9A-Za-z_\-\.]", "_", s)

def write_consent(host: str):
    try:
        CONSENT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(CONSENT_LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now().isoformat()} | consent | {host}\n")
    except Exception:
        pass

def save_history(entry: dict):
    hist = []
    try:
        if HISTORY_FILE.exists():
            hist = json.loads(HISTORY_FILE.read_text(encoding="utf-8") or "[]")
    except Exception:
        hist = []
    hist.insert(0, entry)
    hist = hist[:50]
    try:
        HISTORY_FILE.write_text(json.dumps(hist, indent=2), encoding="utf-8")
    except Exception:
        pass

# ---------- network helpers ----------
async def fetch_text(session: aiohttp.ClientSession, url: str, timeout=12):
    try:
        async with session.get(url, timeout=timeout) as r:
            txt = await r.text()
            return r.status, dict(r.headers), txt
    except Exception as e:
        return None, None, None

LINK_RE = re.compile(r'href=["\']?([^"\' >]+)', re.IGNORECASE)
INPUT_NAME_RE = re.compile(r'<(?:input|textarea|select)[^>]*name=["\']?([^"\' >]+)', re.IGNORECASE)

async def async_crawl(start_url: str, max_depth: int=2, concurrency:int=12, polite:float=0.08):
    """Async crawler staying on same host; returns (found_urls_set, params_map)."""
    if not (start_url.startswith("http://") or start_url.startswith("https://")):
        start_url = "http://" + start_url
    parsed = aiohttp.client_reqrep.URL(start_url)
    base_host = parsed.host
    session_timeout = aiohttp.ClientTimeout(total=20)
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    queue = [(start_url, 0)]
    seen = set([start_url])
    found = set()
    params_map = {}
    sem = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(timeout=session_timeout, connector=connector) as session:
        async def worker(u, depth):
            async with sem:
                if STATE["stop_requested"]:
                    return
                append_log(f"GET {u} (d={depth})")
                try:
                    status, headers, text = await fetch_text(session, u)
                    if status is None:
                        return
                    found.add(u)
                    # query params
                    try:
                        qp = set(aiohttp.client_reqrep.URL(u).query.keys())
                    except Exception:
                        qp = set()
                    # form inputs
                    fi = set(m.group(1) for m in INPUT_NAME_RE.finditer(text or ""))
                    params_map[u] = {"query_params": qp, "form_inputs": fi}
                    # discover links
                    if depth < max_depth and text:
                        for m in LINK_RE.findall(text):
                            href = m.strip()
                            if href.startswith("mailto:") or href.startswith("javascript:") or href.startswith("#"):
                                continue
                            try:
                                candidate = str(aiohttp.client_reqrep.URL(href).join(aiohttp.client_reqrep.URL(u)))
                            except Exception:
                                if href.startswith("/"):
                                    candidate = f"{parsed.scheme}://{base_host}{href}"
                                elif href.startswith("http"):
                                    candidate = href
                                else:
                                    candidate = u.rstrip("/") + "/" + href
                            try:
                                cand_parsed = aiohttp.client_reqrep.URL(candidate)
                                if cand_parsed.host == base_host and candidate not in seen:
                                    seen.add(candidate)
                                    queue.append((candidate, depth+1))
                            except Exception:
                                pass
                except Exception as e:
                    append_log(f"crawl error {u}: {e}")
                if polite:
                    await asyncio.sleep(polite)

        idx = 0
        while idx < len(queue):
            tasks = []
            while idx < len(queue) and len(tasks) < concurrency:
                u, d = queue[idx]
                tasks.append(asyncio.create_task(worker(u, d)))
                idx += 1
            if tasks:
                await asyncio.gather(*tasks)
            if STATE["stop_requested"]:
                append_log("Stop requested; aborting crawl.")
                break
    return found, params_map

# ---------- TLS, port, banner checks ----------
def tls_check(host: str, port=443, timeout=6.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                proto = ss.version() if hasattr(ss, "version") else None
                cipher = ss.cipher() if hasattr(ss, "cipher") else None
                notAfter = None
                if cert and "notAfter" in cert:
                    try:
                        # convert cert notAfter to unix seconds if possible
                        notAfter = ssl.cert_time_to_seconds(cert["notAfter"])
                    except Exception:
                        notAfter = None
                return {"protocol": proto, "cipher": cipher, "cert": cert, "notAfter": notAfter}
    except Exception:
        return None

def banner_grab(host: str, port: int, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except Exception:
                pass
            try:
                data = s.recv(1024)
                return data.decode(errors="ignore").strip()
            except Exception:
                return ""
    except Exception:
        return None

def enumerate_subdomains(host: str, wordlist=None):
    wordlist = wordlist or SUBDOMAIN_WORDLIST
    found = []
    for w in wordlist:
        sub = f"{w}.{host}"
        try:
            ip = socket.gethostbyname(sub)
            found.append((sub, ip))
        except Exception:
            continue
    return found

def scan_common_ports(host: str, ports=None, timeout=0.8):
    ports = ports or COMMON_PORTS
    open_ports = []
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((host, p))
                if res == 0:
                    open_ports.append(p)
        except Exception:
            pass
    return open_ports

# ---------- safe parameter reflection tests (thread) ----------
def test_param_reflection_http(url_base: str, param: str, payloads):
    import requests
    found = []
    for p in payloads:
        try:
            injected = f"{url_base}?{param}={requests.utils.requote_uri(p)}"
            r = requests.get(injected, timeout=6, verify=False)
            if p in (r.text or ""):
                found.append((injected, p))
        except Exception:
            pass
    return found

# ---------- heuristics & explanations ----------
def compute_risk_and_explain(security_lines, discovered_paths, auto_scan_results, tls_info, open_ports):
    # simple scoring: lower is better, higher means more severe
    score = 20  # baseline safe-ish
    reasons = []
    # missing headers add weight
    missing = [l for l in security_lines if "Missing" in l]
    if missing:
        weight = len(missing) * 8
        score += weight
        reasons.append(f"Missing security headers ({len(missing)}) — add HSTS, CSP, X-Frame-Options, X-Content-Type-Options")
    # discovered common paths
    if discovered_paths:
        score += min(15, len(discovered_paths) * 3)
        reasons.append(f"Discovered common/interesting paths: {', '.join(p for p, _ in discovered_paths[:6])}")
    # auto scan findings
    vuln_count = 0
    if auto_scan_results:
        for page, params in auto_scan_results.items():
            for param, items in params.items():
                vuln_count += len(items)
    if vuln_count:
        score += min(30, vuln_count * 8)
        reasons.append(f"Potential reflected/injection indicators found: {vuln_count} (requires manual verification)")
    # TLS issues
    if tls_info is None:
        score += 15
        reasons.append("No TLS / HTTPS or TLS handshake failed (use HTTPS).")
    else:
        if tls_info.get("protocol") and "TLSv1" in str(tls_info.get("protocol")):
            score += 8
            reasons.append("Server using old TLS version — upgrade to TLS1.2+.")
        if tls_info.get("notAfter") and (tls_info.get("notAfter") - time.time() < 30*24*3600):
            score += 8
            reasons.append("Certificate expires soon — renew certificate.")
    # open ports
    if open_ports:
        score += min(20, len(open_ports) * 6)
        reasons.append(f"Open ports detected: {', '.join(map(str, open_ports[:6]))}")
    # clamp
    score = int(max(0, min(100, score)))
    if score >= 75:
        cls = "Critical"
    elif score >= 55:
        cls = "High"
    elif score >= 35:
        cls = "Medium"
    else:
        cls = "Low"
    # add brief human-friendly 'why' explanation assembled
    explain = []
    if missing:
        explain.append("Missing headers allow clickjacking, XSS or content sniffing attacks.")
    if vuln_count:
        explain.append("Detected reflections/errors indicate possible XSS/SQLi vectors — validate manually.")
    if tls_info is None:
        explain.append("No TLS — data may be intercepted in transit.")
    if open_ports:
        explain.append("Open ports can expose services; ensure only required services are accessible and updated.")
    # return
    return score, cls, reasons, explain

# ---------- reporting ----------
def write_report_txt(path: Path, target, headers, security_lines, discovered_paths, crawled, params_map, auto_scan, subdomains, tls_info, banners, open_ports, score, cls, reasons, explain):
    lines = []
    lines.append("=== SECURESCAN Report ===")
    lines.append(f"Target: {target}")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("=== Server Headers ===")
    if headers:
        for k,v in headers.items():
            lines.append(f"{k}: {v}")
    else:
        lines.append("No headers.")
    lines.append("")
    lines.append("=== Security Headers Check ===")
    for l in security_lines:
        lines.append(l)
    lines.append("")
    lines.append("=== Discovered Paths ===")
    for p,s in discovered_paths:
        lines.append(f"/{p} - {s}")
    lines.append("")
    lines.append("=== Crawled URLs ===")
    for u in sorted(crawled):
        lines.append(u)
    lines.append("")
    lines.append("=== Parameter Map ===")
    for page,info in params_map.items():
        qp = ",".join(sorted(list(info.get("query_params", []))))
        fi = ",".join(sorted(list(info.get("form_inputs", []))))
        lines.append(f"{page} | query_params: {qp or '-'} | form_inputs: {fi or '-'}")
    lines.append("")
    lines.append("=== Safe Auto Scan Results ===")
    if not auto_scan:
        lines.append("No automatic findings.")
    else:
        for page, params in auto_scan.items():
            lines.append(f"PAGE: {page}")
            for param, items in params.items():
                for vuln,injected,payload in items:
                    lines.append(f"  - {vuln}: {injected} | payload: {payload}")
    lines.append("")
    lines.append("=== Subdomains ===")
    for s, ip in subdomains:
        lines.append(f"{s} -> {ip}")
    lines.append("")
    lines.append("=== Banners (common ports) ===")
    for p,b in banners.items():
        lines.append(f"Port {p}: {b or 'none'}")
    lines.append("")
    lines.append("=== Open Ports ===")
    if open_ports:
        lines.append(", ".join(map(str, open_ports)))
    else:
        lines.append("None detected (from common ports list).")
    lines.append("")
    lines.append("=== TLS Info ===")
    if tls_info:
        lines.append(f"Protocol: {tls_info.get('protocol')} Cipher: {tls_info.get('cipher')}")
        lines.append(f"Cert notAfter: {tls_info.get('notAfter')}")
    else:
        lines.append("TLS handshake failed or non-HTTPS.")
    lines.append("")
    lines.append("=== Risk & Threat Meter ===")
    lines.append(f"Score: {score} Classification: {cls}")
    lines.append("Reasons (quick):")
    for r in reasons:
        lines.append(f" - {r}")
    lines.append("")
    lines.append("Why vulnerabilities may occur (explanation):")
    for e in explain:
        lines.append(f" - {e}")
    lines.append("")
    lines.append("=== End of Report ===")
    try:
        path.write_text("\n".join(lines), encoding="utf-8")
    except Exception:
        pass
    return "\n".join(lines)

def generate_pdf_from_text(text: str, outpath: Path):
    if not REPORTLAB:
        return False
    c = canvas.Canvas(str(outpath), pagesize=letter)
    width, height = letter
    margin = 40
    y = height - margin
    for line in text.splitlines():
        if y < margin:
            c.showPage()
            y = height - margin
        try:
            c.drawString(margin, y, line[:200])
        except Exception:
            pass
        y -= 12
    c.save()
    return True

# ---------- orchestrator (async) ----------
async def run_scan_async(target: str, depth: int, speed: str, categories: list):
    """Main async orchestrator. Produces report and updates STATE."""
    try:
        STATE["target"] = target
        STATE["progress"] = 2
        append_log("Starting scan.")
        if not (target.startswith("http://") or target.startswith("https://")):
            target = "http://" + target
        # parse host
        parsed = aiohttp.client_reqrep.URL(target)
        host = parsed.host

        # initial fetch
        connector = aiohttp.TCPConnector(ssl=False, limit=40)
        timeout = aiohttp.ClientTimeout(total=20)
        headers = {}
        text = ""
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(target) as r:
                    headers = dict(r.headers or {})
                    text = await r.text()
                    append_log(f"Fetched {target} status={r.status}")
        except Exception as e:
            append_log(f"Initial fetch failed: {e}")

        STATE["progress"] = 8

        # security header checks
        required = {
            "X-Frame-Options":"Helps prevent clickjacking",
            "X-XSS-Protection":"Protects against XSS",
            "Content-Security-Policy":"Prevents script injection",
            "Strict-Transport-Security":"Forces HTTPS",
            "X-Content-Type-Options":"Prevents MIME-sniffing",
            "Referrer-Policy":"Controls referrer header information"
        }
        sec_lines = []
        for k,desc in required.items():
            if k in headers:
                sec_lines.append(f"{k}: Present")
            else:
                sec_lines.append(f"{k}: Missing - {desc}")

        # crawl
        append_log("Crawling site (async)...")
        polite = 0.18 if speed=="polite" else 0.06 if speed=="normal" else 0.0
        concurrency = 8 if speed=="polite" else 20 if speed=="normal" else 40
        found_links, params_map = await async_crawl(target, max_depth=depth, concurrency=concurrency, polite=polite)
        STATE["progress"] = 45
        append_log(f"Crawl done: {len(found_links)} URLs")

        # safe parameter reflection checks (threadpool)
        append_log("Running safe parameter reflection checks...")
        loop = asyncio.get_event_loop()
        executor = ThreadPoolExecutor(max_workers=10)
        auto_scan = {}
        for page, info in params_map.items():
            params = set(info.get("query_params", set())) | set(info.get("form_inputs", set()))
            for p in params:
                if "XSS" in categories:
                    hits = await loop.run_in_executor(executor, partial(test_param_reflection_http, page, p, SAFE_XSS_PAYLOADS))
                    if hits:
                        auto_scan.setdefault(page, {})[p] = [("XSS", inj, payload) for inj, payload in hits]
                if "SQLi" in categories:
                    hits2 = await loop.run_in_executor(executor, partial(test_param_reflection_http, page, p, SAFE_SQLI_PAYLOADS))
                    if hits2:
                        existing = auto_scan.setdefault(page, {}).get(p, [])
                        existing += [("SQLi", inj, payload) for inj, payload in hits2]
                        auto_scan.setdefault(page, {})[p] = existing
        STATE["progress"] = 72
        append_log("Auto param checks complete.")

        # TLS info
        append_log("Checking TLS (if any)...")
        tls = tls_check(host, 443)
        STATE["progress"] = 82

        # subdomains + banner grabbing
        append_log("Enumerating common subdomains...")
        subd = await loop.run_in_executor(executor, partial(enumerate_subdomains, host))
        append_log("Grabbing banners on common ports...")
        banners = {}
        for port in [80,443,8080,22]:
            b = await loop.run_in_executor(executor, partial(banner_grab, host, port))
            banners[port] = b
        STATE["progress"] = 90

        # port scan (sync via threadpool)
        append_log("Scanning common ports...")
        open_ports = await loop.run_in_executor(executor, partial(scan_common_ports, host, COMMON_PORTS, 0.6))
        append_log(f"Open ports: {open_ports}")

        # compute risk & explanation
        score, cls, reasons, explain = compute_risk_and_explain(sec_lines, [], auto_scan, tls, open_ports)
        STATE["threat_score"] = score
        STATE["threat_class"] = cls
        STATE["threat_reasons"] = reasons

        append_log(f"Threat meter: {score} ({cls})")
        STATE["progress"] = 96

        # write unified report (txt) + optional PDF
        name = f"report_{safe_filename(host)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        outpath = REPORTS_DIR / name
        report_text = write_report_txt(outpath, target, headers, sec_lines, [], found_links, params_map, auto_scan, subd, tls, banners, open_ports, score, cls, reasons, explain)
        STATE["last_report"] = str(outpath)
        STATE["last_report_name"] = outpath.name
        STATE["progress"] = 100
        append_log(f"Report saved: {outpath}")

        if REPORTLAB:
            try:
                pdfp = outpath.with_suffix(".pdf")
                generate_pdf_from_text(report_text, pdfp)
                append_log(f"PDF generated: {pdfp}")
            except Exception as e:
                append_log(f"PDF gen error: {e}")

        save_history({"target":target, "time":datetime.now().isoformat(), "report":outpath.name, "score": score, "class":cls})
    except Exception as e:
        append_log(f"Scan error: {e}")
    finally:
        STATE["running"] = False

# ---------- Flask UI (keeps your GUI, with threat meter element) ----------
app = Flask(__name__)

INDEX_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SECURESCAN</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#02040a;--card:#071526;--muted:#78a5b1;--accent:#00ffd5;--accent2:#8b4bff}
body{background:linear-gradient(180deg,#02040a,#041021);color:#bff9ff;font-family:Inter,system-ui,Segoe UI,Roboto,Arial;margin:0;padding:18px;}
.container{max-width:1100px;margin:0 auto}
.header{display:flex;align-items:center;gap:16px}
.logo{width:56px;height:56px;border-radius:10px;background:linear-gradient(90deg,var(--accent),var(--accent2));box-shadow:0 6px 30px rgba(139,75,255,0.12)}
h1{margin:0;font-size:22px;color:var(--accent)}
.layout{display:grid;grid-template-columns:360px 1fr;gap:16px;margin-top:18px}
.card{background:linear-gradient(180deg,rgba(255,255,255,0.02),rgba(255,255,255,0.01));border-radius:12px;padding:14px}
input,select{width:100%;padding:10px;border-radius:8px;background:transparent;border:1px solid rgba(255,255,255,0.06);color:#dff8ff}
label{font-size:13px;color:var(--muted)}
.btn{padding:10px 12px;border-radius:10px;border:none;background:linear-gradient(90deg,var(--accent),var(--accent2));color:#02121a;font-weight:700;cursor:pointer}
.terminal{background:#010b0f;border-radius:8px;padding:12px;height:320px;overflow:auto;color:#9ff7ff;font-family:jetbrains mono,monospace;font-size:13px;white-space:pre-wrap}
.progressOuter{height:10px;background:#021425;border-radius:8px;margin-top:8px;overflow:hidden}
.progressInner{height:100%;width:0%;background:linear-gradient(90deg,var(--accent),#8ff)}
.threatBox{margin-top:10px;padding:10px;border-radius:8px;background:linear-gradient(90deg, rgba(255,255,255,0.01), transparent);display:flex;align-items:center;gap:12px}
.threatMeter{height:12px;background:#021425;border-radius:8px;overflow:hidden;width:100%}
.threatInner{height:100%;width:0%;background:linear-gradient(90deg,#ffb100,#ff3b3b)}
.threatLabel{font-weight:700;color:#ffd8a8}
.footer{color:var(--muted);font-size:12px;text-align:center;margin-top:14px}
.small{font-size:13px;color:var(--muted)}
.link{color:var(--accent);text-decoration:none}
.row{display:flex;gap:8px}
.checkbox{transform:scale(1.0);margin-right:6px}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="logo"></div>
    <div>
      <h1>SECURESCAN</h1>
      <div class="small">Fast. Safe. Cinematic.</div>
    </div>
  </div>

  <div class="layout">
    <div>
      <div class="card">
        <label>Target (domain or URL)</label>
        <input id="url" placeholder="testphp.vulnweb.com or https://testphp.vulnweb.com">
        <div style="display:flex;gap:8px;margin-top:8px">
          <div style="flex:1">
            <label>Depth</label>
            <select id="depth"><option>1</option><option selected>2</option><option>3</option></select>
          </div>
          <div style="flex:1">
            <label>Preset</label>
            <select id="speed"><option value="polite">Polite</option><option value="normal">Normal</option><option value="aggressive">Aggressive</option></select>
          </div>
        </div>

        <div style="margin-top:10px">
          <label class="small">Tests</label><br>
          <label><input id="t_xss" class="checkbox" type="checkbox" checked> XSS</label>
          <label style="margin-left:8px"><input id="t_sqli" class="checkbox" type="checkbox" checked> SQLi</label>
          <label style="margin-left:8px"><input id="t_lfi" class="checkbox" type="checkbox"> LFI</label>
        </div>

        <div style="margin-top:10px">
          <label><input id="consent" class="checkbox" type="checkbox"> I confirm I have permission to test this target</label>
        </div>

        <div style="display:flex;gap:8px;margin-top:12px">
          <button id="startBtn" class="btn">LAUNCH SCAN</button>
          <button id="stopBtn" class="btn" style="background:#ff5f6d;color:white">ABORT</button>
        </div>

        <div style="margin-top:12px">
          <div class="small">Status: <span id="statusText">Idle</span></div>
          <div class="progressOuter"><div id="progressBar" class="progressInner"></div></div>

          <div class="threatBox">
            <div style="width:110px"><div class="small">Threat Meter</div><div class="threatLabel" id="threatClass">—</div></div>
            <div class="threatMeter"><div id="threatInner" class="threatInner"></div></div>
            <div style="width:60px;text-align:right"><strong id="threatScore">—</strong></div>
          </div>
        </div>
      </div>

      <div class="card" style="margin-top:12px">
        <div class="small">Latest report</div>
        <div id="reportArea" style="margin-top:8px"><span class="small">No report yet</span></div>
        <div style="margin-top:10px">
          <button id="downloadTxt" class="btn">Download TXT</button>
          <button id="downloadPdf" class="btn" style="margin-left:8px">Download PDF</button>
        </div>
      </div>
    </div>

    <div>
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div><strong>Live Terminal</strong><div class="small">Scan events & progress</div></div>
          <div class="small">Target: <span id="targetLabel">—</span></div>
        </div>
        <div id="terminal" class="terminal">(waiting...)</div>
        <div style="margin-top:10px" class="small">Quick reasons: <span id="quickReasons">—</span></div>
      </div>
    </div>
  </div>

  <div class="footer">SECURESCAN • Ethical testing only</div>
</div>

<script>
let pollInterval = null;
async function poll(){
  try {
    const r = await fetch('/status');
    if(!r.ok) return;
    const j = await r.json();
    document.getElementById('statusText').textContent = j.running ? 'Running' : 'Idle';
    document.getElementById('progressBar').style.width = (j.progress || 0) + '%';
    document.getElementById('terminal').textContent = (j.log || []).join('\\n');
    document.getElementById('terminal').scrollTop = document.getElementById('terminal').scrollHeight;
    document.getElementById('targetLabel').textContent = j.target || '—';

    // threat meter
    if (typeof j.threat_score !== 'undefined' && j.threat_score !== null){
      document.getElementById('threatScore').textContent = j.threat_score + '%';
      document.getElementById('threatInner').style.width = j.threat_score + '%';
      document.getElementById('threatClass').textContent = j.threat_class || '—';
      document.getElementById('quickReasons').textContent = (j.threat_reasons || []).slice(0,3).join(' | ') || '—';
    }

    if (j.last_report_name){
      document.getElementById('reportArea').innerHTML = '<b>'+j.last_report_name+'</b>';
    }
  } catch(e){}
}

document.getElementById('startBtn').addEventListener('click', async ()=>{
  const url = document.getElementById('url').value.trim();
  const depth = parseInt(document.getElementById('depth').value);
  const speed = document.getElementById('speed').value;
  const cats = [];
  if (document.getElementById('t_xss').checked) cats.push('XSS');
  if (document.getElementById('t_sqli').checked) cats.push('SQLi');
  if (document.getElementById('t_lfi').checked) cats.push('LFI');
  const consent = document.getElementById('consent').checked;
  if (!url){ alert('Enter target'); return; }
  if (!consent){ alert('You must confirm permission'); return; }
  let target = url;
  if (!target.startsWith('http://') && !target.startsWith('https://')) target = 'http://' + target;
  await fetch('/start', {method:'POST',headers:{'Content-Type':'application/json'}, body: JSON.stringify({target, depth, speed, categories:cats})});
  if (!pollInterval) pollInterval = setInterval(poll, 1200);
  poll();
});

document.getElementById('stopBtn').addEventListener('click', async ()=>{
  await fetch('/stop');
});

document.getElementById('downloadTxt').addEventListener('click', ()=>{ window.location.href='/download?format=txt'; });
document.getElementById('downloadPdf').addEventListener('click', ()=>{ window.location.href='/download?format=pdf'; });

poll();
setInterval(poll, 2000);
</script>
</body>
</html>
"""

# ---------- Flask routes ----------
@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/start", methods=["POST"])
def start_scan():
    if STATE["running"]:
        append_log("Attempt to start while running — ignored.")
        return ("Scan already running", 400)
    data = request.get_json() or {}
    target = data.get("target")
    depth = int(data.get("depth", 2))
    speed = data.get("speed", "polite")
    categories = data.get("categories", ["XSS","SQLi"])
    if not target:
        return ("Missing target", 400)
    # log consent (UI already requested user confirmation)
    try:
        h = aiohttp.client_reqrep.URL(target).host
    except Exception:
        h = target
    write_consent(h)
    append_log(f"Consent recorded for {h}")

    STATE["running"] = True
    STATE["progress"] = 0
    STATE["target"] = target
    STATE["log"].clear()
    STATE["stop_requested"] = False
    STATE["threat_score"] = None
    STATE["threat_class"] = None
    STATE["threat_reasons"] = []

    # run scan in background thread (async runner)
    def bg():
        try:
            asyncio.run(run_scan_async(target, depth, speed, categories))
        except Exception as e:
            append_log(f"Background scan error: {e}")
        finally:
            STATE["running"] = False
    import threading
    t = threading.Thread(target=bg, daemon=True)
    t.start()
    append_log("Scan thread launched.")
    return ("", 204)

@app.route("/stop")
def stop_scan():
    if STATE["running"]:
        STATE["stop_requested"] = True
        append_log("Stop requested by user.")
    return ("", 204)

@app.route("/status")
def status():
    return jsonify({
        "running": STATE.get("running", False),
        "progress": STATE.get("progress", 0),
        "target": STATE.get("target"),
        "log": STATE.get("log")[-400:],
        "last_report": STATE.get("last_report"),
        "last_report_name": STATE.get("last_report_name"),
        "threat_score": STATE.get("threat_score"),
        "threat_class": STATE.get("threat_class"),
        "threat_reasons": STATE.get("threat_reasons") or []
    })

@app.route("/download")
def download():
    fmt = request.args.get("format", "txt").lower()
    rp = STATE.get("last_report")
    if not rp:
        return ("No report yet", 404)
    rp_path = Path(rp)
    if fmt == "pdf":
        pdfp = rp_path.with_suffix(".pdf")
        if pdfp.exists():
            return send_file(str(pdfp), as_attachment=True)
        else:
            if REPORTLAB:
                try:
                    txt = rp_path.read_text(encoding="utf-8")
                    generate_pdf_from_text(txt, pdfp)
                    if pdfp.exists():
                        return send_file(str(pdfp), as_attachment=True)
                    else:
                        return ("PDF create failed", 500)
                except Exception:
                    return ("PDF create failed", 500)
            else:
                return ("reportlab not installed", 400)
    else:
        if rp_path.exists():
            return send_file(str(rp_path), as_attachment=True)
        else:
            return ("Report not found", 404)

# ---------- run app ----------
if __name__ == "__main__":
    append_log("SECURESCAN starting")
    app.run(host="0.0.0.0", port=APP_PORT, debug=True)
