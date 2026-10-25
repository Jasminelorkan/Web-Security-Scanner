import asyncio
import aiohttp
import socket
import ssl
import os
import re
import json
import time
from urllib.parse import urljoin, urlparse
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

# common hidden paths — this is what actually populates "Discovered Paths"
COMMON_PATHS = ["robots.txt","sitemap.xml",".git/HEAD","admin","backup",".env",
                 "config.php","wp-login.php",".DS_Store","server-status","phpinfo.php"]

SAFE_XSS_PAYLOADS = ['<scr1pt>alert(1)</scr1pt>', '"><svg onload=1>']
# SQLi payloads now paired: an error-trigger and a time-based check, not just reflection bait
SQLI_ERROR_PAYLOADS = ["'", '"', "' OR '1'='1", '" OR "1"="1']
SQLI_TIME_PAYLOAD = "' OR SLEEP(5)-- -"
SQLI_TIME_THRESHOLD = 4.5  # seconds — baseline response should be well under this

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "sqlstate", "pg_query():", "sqlite3.operationalerror",
    "ora-01756", "microsoft odbc"
]

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
    except Exception:
        return None, None, None

LINK_RE = re.compile(r'href=["\']?([^"\' >]+)', re.IGNORECASE)
INPUT_RE = re.compile(r'<(input|textarea|select)[^>]*name=["\']?([^"\' >]+)[^>]*>', re.IGNORECASE)
FORM_METHOD_RE = re.compile(r'<form[^>]*method=["\']?(\w+)', re.IGNORECASE)

async def async_crawl(start_url: str, max_depth: int = 2, concurrency: int = 12, polite: float = 0.08):
    """Async crawler staying on same host; returns (found_urls_set, params_map)."""
    if not (start_url.startswith("http://") or start_url.startswith("https://")):
        start_url = "http://" + start_url
    base_host = urlparse(start_url).netloc
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
                    try:
                        qp = set(urlparse(u).query and
                                 dict(pair.split("=") for pair in urlparse(u).query.split("&") if "=" in pair).keys() or [])
                    except Exception:
                        qp = set()
                    fi = set(m.group(2) for m in INPUT_RE.finditer(text or ""))
                    method_match = FORM_METHOD_RE.search(text or "")
                    form_method = (method_match.group(1).upper() if method_match else "GET")
                    params_map[u] = {"query_params": qp, "form_inputs": fi, "form_method": form_method}

                    if depth < max_depth and text:
                        for m in LINK_RE.findall(text):
                            href = m.strip()
                            if href.startswith(("mailto:", "javascript:", "#", "tel:")):
                                continue
                            # FIX: urljoin(base, relative) — not the reversed order the
                            # original had (it joined relative-as-base, which made any
                            # absolute href resolve back to itself, so nothing new was
                            # ever queued and the crawl never left page 1).
                            candidate = urljoin(u, href)
                            try:
                                if urlparse(candidate).netloc == base_host and candidate not in seen:
                                    seen.add(candidate)
                                    queue.append((candidate, depth + 1))
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

# ---------- path discovery (was a dead feature — report section existed, nothing filled it) ----------
async def discover_paths(base_url: str, wordlist=None, concurrency=10):
    wordlist = wordlist or COMMON_PATHS
    results = []
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    timeout = aiohttp.ClientTimeout(total=8)
    sem = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async def check(path):
            async with sem:
                url = base_url.rstrip("/") + "/" + path
                try:
                    async with session.get(url, allow_redirects=False) as r:
                        if r.status in (200, 301, 302, 403):
                            results.append((path, r.status))
                except Exception:
                    pass
        await asyncio.gather(*(check(p) for p in wordlist))
    return results

# ---------- TLS, port, banner checks ----------
def _parse_notAfter_from_der(der_bytes):
    """
    getpeercert() in dict form only populates when the cert chain validates —
    with verify_mode=CERT_NONE (needed here for self-signed/test targets) it
    returns {}. getpeercert(binary_form=True) always returns the raw DER bytes
    regardless of verification, so parse notAfter out of that instead.
    Uses `cryptography` if present; returns None (logged, not crashed) if not.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        return cert.not_valid_after_utc.timestamp()
    except ImportError:
        return None
    except Exception:
        return None

def tls_check(host: str, port=443, timeout=6.0):
    # FIX: original set verify_mode=CERT_NONE then read dict-form getpeercert(),
    # which is documented to return {} when verification is off — notAfter could
    # never be populated, so the "certificate expiring soon" check was dead code
    # on every scan. Fix: always pull the DER form (populated regardless of
    # verification) and parse notAfter out of that directly.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                proto = ss.version() if hasattr(ss, "version") else None
                cipher = ss.cipher() if hasattr(ss, "cipher") else None
                der = ss.getpeercert(binary_form=True)
                notAfter = _parse_notAfter_from_der(der) if der else None
                if der and notAfter is None:
                    append_log("TLS cert fetched but notAfter unparsed — install `cryptography` for expiry checks")
                return {"protocol": proto, "cipher": cipher, "notAfter": notAfter}
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

# ---------- injection checks (rewritten — was reflection-only, which isn't SQLi detection) ----------
def test_xss_reflection(url_base: str, param: str, payloads, method="GET"):
    """XSS: reflection is actually the right test here — if your unescaped payload
    comes back in the HTML verbatim, that's a real stored/reflected XSS indicator."""
    import requests
    found = []
    for p in payloads:
        try:
            if method == "POST":
                r = requests.post(url_base, data={param: p}, timeout=6, verify=False)
            else:
                r = requests.get(url_base, params={param: p}, timeout=6, verify=False)
            if p in (r.text or ""):
                found.append((r.url if method == "GET" else url_base, p))
        except Exception:
            pass
    return found

def test_sqli(url_base: str, param: str, method="GET"):
    """
    SQLi: reflection tells you nothing about the database layer. This checks two
    real signals instead:
      1. Error-based — does a bare quote break the query and surface a DB error
         string in the response that a baseline request doesn't produce?
      2. Time-based  — does a conditional SLEEP() payload measurably delay the
         response vs. an unmodified baseline request?
    Both are compared against a baseline so a slow site or an error-page-by-default
    site doesn't get flagged for not being a controlled test.
    """
    import requests
    findings = []

    def send(payload):
        if method == "POST":
            return requests.post(url_base, data={param: payload}, timeout=10, verify=False)
        return requests.get(url_base, params={param: payload}, timeout=10, verify=False)

    # baseline
    try:
        base_start = time.time()
        base_resp = send("1")
        base_elapsed = time.time() - base_start
        base_text = (base_resp.text or "").lower()
    except Exception:
        return findings  # can't test without a baseline

    # error-based
    for p in SQLI_ERROR_PAYLOADS:
        try:
            r = send(p)
            body = (r.text or "").lower()
            for sig in SQL_ERROR_SIGNATURES:
                if sig in body and sig not in base_text:
                    findings.append(("SQLi-error", url_base, p, sig))
                    break
        except Exception:
            pass

    # time-based — only trust this if it's clearly outside baseline variance
    try:
        t_start = time.time()
        send(SQLI_TIME_PAYLOAD)
        elapsed = time.time() - t_start
        if elapsed - base_elapsed > SQLI_TIME_THRESHOLD:
            findings.append(("SQLi-time", url_base, SQLI_TIME_PAYLOAD, f"{elapsed:.1f}s vs baseline {base_elapsed:.1f}s"))
    except Exception:
        pass

    return findings

# ---------- heuristics & explanations ----------
def compute_risk_and_explain(security_lines, discovered_paths, auto_scan_results, tls_info, open_ports):
    """
    FIX: original baseline (20) + flat +8/header meant 6 missing headers (68, "High")
    outscored real injection indicators (+8 each, capped at 30). Headers are
    best-practice hardening; confirmed/likely injection is exploitable now.
    Rebalanced so injection and open DB ports dominate the score, headers are a
    smaller, capped contribution, and error-based SQLi (higher confidence) weighs
    more than time-based (higher false-positive risk under network jitter).
    """
    score = 10
    reasons = []

    missing = [l for l in security_lines if "Missing" in l]
    if missing:
        weight = min(15, len(missing) * 2)  # capped — hardening gaps, not exploitation
        score += weight
        reasons.append(f"Missing security headers ({len(missing)}) — add HSTS, CSP, X-Frame-Options, X-Content-Type-Options")

    if discovered_paths:
        score += min(10, len(discovered_paths) * 3)
        reasons.append(f"Discovered sensitive/interesting paths: {', '.join(p for p, _ in discovered_paths[:6])}")

    error_hits = 0
    time_hits = 0
    xss_hits = 0
    if auto_scan_results:
        for page, params in auto_scan_results.items():
            for param, items in params.items():
                for item in items:
                    kind = item[0]
                    if kind == "SQLi-error":
                        error_hits += 1
                    elif kind == "SQLi-time":
                        time_hits += 1
                    elif kind == "XSS":
                        xss_hits += 1

    if error_hits:
        score += min(35, error_hits * 15)
        reasons.append(f"Error-based SQLi indicators: {error_hits} (high confidence — DB error disclosed)")
    if time_hits:
        score += min(20, time_hits * 10)
        reasons.append(f"Time-based SQLi indicators: {time_hits} (verify manually — timing can be noisy)")
    if xss_hits:
        score += min(20, xss_hits * 8)
        reasons.append(f"Reflected XSS indicators: {xss_hits}")

    if tls_info is None:
        score += 15
        reasons.append("No TLS / HTTPS or TLS handshake failed (use HTTPS).")
    else:
        proto = str(tls_info.get("protocol") or "")
        # FIX: "TLSv1" was matching TLSv1.3 as a substring. Flag only the actually
        # deprecated versions explicitly.
        if proto in ("TLSv1", "TLSv1.1"):
            score += 10
            reasons.append(f"Server using deprecated {proto} — upgrade to TLS1.2+.")
        if tls_info.get("notAfter") and (tls_info["notAfter"] - time.time() < 30 * 24 * 3600):
            score += 8
            reasons.append("Certificate expires within 30 days — renew certificate.")

    if open_ports:
        db_ports = {3306, 5432, 27017}
        risky = [p for p in open_ports if p in db_ports]
        if risky:
            score += min(20, len(risky) * 12)
            reasons.append(f"Database port(s) exposed to the internet: {risky} — should not be publicly reachable")
        other = [p for p in open_ports if p not in db_ports]
        if other:
            score += min(10, len(other) * 3)
            reasons.append(f"Other open ports: {other}")

    score = int(max(0, min(100, score)))
    if score >= 75:
        cls = "Critical"
    elif score >= 50:
        cls = "High"
    elif score >= 30:
        cls = "Medium"
    else:
        cls = "Low"

    explain = []
    if missing:
        explain.append("Missing headers allow clickjacking, XSS or content sniffing attacks.")
    if error_hits:
        explain.append("A raw quote broke a database query and leaked an error string — this is a strong signal the input reaches SQL unsanitized.")
    if time_hits:
        explain.append("A conditional SLEEP payload measurably delayed the response — consistent with blind SQLi, but confirm manually since network jitter can produce false positives.")
    if xss_hits:
        explain.append("Unescaped input was reflected back in the page — a browser would execute it as script.")
    if tls_info is None:
        explain.append("No TLS — data may be intercepted in transit.")
    if open_ports:
        explain.append("Open ports can expose services; ensure only required services are accessible and updated.")
    return score, cls, reasons, explain

# ---------- reporting ----------
def write_report_txt(path, target, headers, security_lines, discovered_paths, crawled, params_map,
                      auto_scan, subdomains, tls_info, banners, open_ports, score, cls, reasons, explain):
    lines = []
    lines.append("=== SECURESCAN Report ===")
    lines.append(f"Target: {target}")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("=== Server Headers ===")
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
    else:
        lines.append("No headers.")
    lines.append("")
    lines.append("=== Security Headers Check ===")
    lines.extend(security_lines)
    lines.append("")
    lines.append("=== Discovered Paths ===")
    if discovered_paths:
        for p, s in discovered_paths:
            lines.append(f"/{p} - {s}")
    else:
        lines.append("None found from wordlist.")
    lines.append("")
    lines.append("=== Crawled URLs ===")
    lines.extend(sorted(crawled))
    lines.append("")
    lines.append("=== Parameter Map ===")
    for page, info in params_map.items():
        qp = ",".join(sorted(info.get("query_params", []))) or "-"
        fi = ",".join(sorted(info.get("form_inputs", []))) or "-"
        method = info.get("form_method", "GET")
        lines.append(f"{page} | method: {method} | query_params: {qp} | form_inputs: {fi}")
    lines.append("")
    lines.append("=== Safe Auto Scan Results ===")
    if not auto_scan:
        lines.append("No automatic findings.")
    else:
        for page, params in auto_scan.items():
            lines.append(f"PAGE: {page}")
            for param, items in params.items():
                for item in items:
                    lines.append(f"  - {' | '.join(str(x) for x in item)}")
    lines.append("")
    lines.append("=== Subdomains ===")
    for s, ip in subdomains:
        lines.append(f"{s} -> {ip}")
    lines.append("")
    lines.append("=== Banners (common ports) ===")
    for p, b in banners.items():
        lines.append(f"Port {p}: {b or 'none'}")
    lines.append("")
    lines.append("=== Open Ports ===")
    lines.append(", ".join(map(str, open_ports)) if open_ports else "None detected (from common ports list).")
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
    lines.append("Reasons:")
    for r in reasons:
        lines.append(f" - {r}")
    lines.append("")
    lines.append("Why these matter:")
    for e in explain:
        lines.append(f" - {e}")
    lines.append("")
    lines.append("=== End of Report ===")
    text = "\n".join(lines)
    try:
        path.write_text(text, encoding="utf-8")
    except Exception:
        pass
    return text

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
    try:
        STATE["target"] = target
        STATE["progress"] = 2
        append_log("Starting scan.")
        if not (target.startswith("http://") or target.startswith("https://")):
            target = "http://" + target
        host = urlparse(target).netloc

        connector = aiohttp.TCPConnector(ssl=False, limit=40)
        timeout = aiohttp.ClientTimeout(total=20)
        headers = {}
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                async with session.get(target) as r:
                    headers = dict(r.headers or {})
                    await r.text()
                    append_log(f"Fetched {target} status={r.status}")
        except Exception as e:
            append_log(f"Initial fetch failed: {e}")

        STATE["progress"] = 8

        required = {
            "X-Frame-Options": "Helps prevent clickjacking",
            "Content-Security-Policy": "Prevents script injection",
            "Strict-Transport-Security": "Forces HTTPS",
            "X-Content-Type-Options": "Prevents MIME-sniffing",
            "Referrer-Policy": "Controls referrer header information"
            # FIX: X-XSS-Protection removed — deprecated, stripped from modern
            # browsers (Chrome/Edge removed support), flagging it as "missing"
            # inflates risk for sites that correctly dropped a dead header.
        }
        sec_lines = []
        for k, desc in required.items():
            sec_lines.append(f"{k}: Present" if k in headers else f"{k}: Missing - {desc}")

        append_log("Crawling site (async)...")
        polite = 0.18 if speed == "polite" else 0.06 if speed == "normal" else 0.0
        concurrency = 8 if speed == "polite" else 20 if speed == "normal" else 40
        found_links, params_map = await async_crawl(target, max_depth=depth, concurrency=concurrency, polite=polite)
        STATE["progress"] = 35
        append_log(f"Crawl done: {len(found_links)} URLs")

        append_log("Discovering hidden paths...")
        disc_paths = await discover_paths(target)
        STATE["progress"] = 45
        append_log(f"Path discovery done: {len(disc_paths)} found")

        append_log("Running injection checks (XSS + SQLi)...")
        loop = asyncio.get_event_loop()
        executor = ThreadPoolExecutor(max_workers=10)
        auto_scan = {}
        for page, info in params_map.items():
            params = set(info.get("query_params", set())) | set(info.get("form_inputs", set()))
            method = info.get("form_method", "GET")
            for p in params:
                if "XSS" in categories:
                    hits = await loop.run_in_executor(executor, partial(test_xss_reflection, page, p, SAFE_XSS_PAYLOADS, method))
                    if hits:
                        auto_scan.setdefault(page, {}).setdefault(p, [])
                        auto_scan[page][p] += [("XSS", inj, payload) for inj, payload in hits]
                if "SQLi" in categories:
                    hits2 = await loop.run_in_executor(executor, partial(test_sqli, page, p, method))
                    if hits2:
                        auto_scan.setdefault(page, {}).setdefault(p, [])
                        auto_scan[page][p] += hits2
        STATE["progress"] = 72
        append_log("Injection checks complete.")

        append_log("Checking TLS (if any)...")
        tls = tls_check(host, 443)
        STATE["progress"] = 82

        append_log("Enumerating common subdomains...")
        subd = await loop.run_in_executor(executor, partial(enumerate_subdomains, host))
        append_log("Grabbing banners on common ports...")
        banners = {}
        for port in [80, 443, 8080, 22]:
            banners[port] = await loop.run_in_executor(executor, partial(banner_grab, host, port))
        STATE["progress"] = 90

        append_log("Scanning common ports...")
        open_ports = await loop.run_in_executor(executor, partial(scan_common_ports, host, COMMON_PORTS, 0.6))
        append_log(f"Open ports: {open_ports}")

        score, cls, reasons, explain = compute_risk_and_explain(sec_lines, disc_paths, auto_scan, tls, open_ports)
        STATE["threat_score"] = score
        STATE["threat_class"] = cls
        STATE["threat_reasons"] = reasons
        append_log(f"Threat meter: {score} ({cls})")
        STATE["progress"] = 96

        name = f"report_{safe_filename(host)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        outpath = REPORTS_DIR / name
        report_text = write_report_txt(outpath, target, headers, sec_lines, disc_paths, found_links, params_map,
                                        auto_scan, subd, tls, banners, open_ports, score, cls, reasons, explain)
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

        save_history({"target": target, "time": datetime.now().isoformat(), "report": outpath.name, "score": score, "class": cls})
    except Exception as e:
        append_log(f"Scan error: {e}")
    finally:
        STATE["running"] = False

# ---------- Flask UI ----------
app = Flask(__name__)

INDEX_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>SECURESCAN</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* Muted slate/graphite palette — low saturation, severity colors reserved
   for actual severity, no decorative gradients or glow. */
:root{
  --bg:#f7f8fa;
  --bg2:#ffffff;
  --card:#ffffff;
  --border:#e1e5ea;
  --text:#1c2430;
  --muted:#6b7684;
  --accent:#2f6690;       /* navy-blue — interactive elements only */
  --accent-hover:#3a7aa8;
  --danger:#b3463f;       /* muted red — critical/high */
  --warn:#a9752e;         /* muted amber — medium */
  --ok:#3f7d5c;           /* muted green — low/present */
}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:0;padding:18px;}
.container{max-width:1100px;margin:0 auto}
.header{display:flex;align-items:center;gap:16px}
.logo{width:48px;height:48px;border-radius:8px;background:var(--bg2);border:1px solid var(--border)}
h1{margin:0;font-size:20px;font-weight:600;color:var(--text);letter-spacing:0.01em}
.layout{display:grid;grid-template-columns:360px 1fr;gap:16px;margin-top:18px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px;box-shadow:0 1px 2px rgba(16,24,40,0.04)}
input,select{width:100%;padding:9px 10px;border-radius:6px;background:#fff;border:1px solid var(--border);color:var(--text)}
label{font-size:13px;color:var(--muted)}
.btn{padding:9px 14px;border-radius:6px;border:1px solid transparent;background:var(--accent);color:#ffffff;font-weight:600;font-size:13px;cursor:pointer}
.btn:hover{background:var(--accent-hover)}
.terminal{background:#f1f3f6;border:1px solid var(--border);border-radius:6px;padding:12px;height:320px;overflow:auto;color:#3a4654;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;white-space:pre-wrap}
.progressOuter{height:6px;background:var(--bg);border-radius:4px;margin-top:8px;overflow:hidden;border:1px solid var(--border)}
.progressInner{height:100%;width:0%;background:var(--accent)}
.threatBox{margin-top:10px;padding:10px;border-radius:6px;background:var(--bg);border:1px solid var(--border);display:flex;align-items:center;gap:12px}
.threatMeter{height:8px;background:#e9ecf0;border-radius:4px;overflow:hidden;width:100%}
.threatInner{height:100%;width:0%;background:var(--warn)}
.threatLabel{font-weight:600;color:var(--warn);font-size:13px}
.footer{color:var(--muted);font-size:12px;text-align:center;margin-top:14px}
.small{font-size:12.5px;color:var(--muted)}
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
      <div class="small">Web application security scanner</div>
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
    categories = data.get("categories", ["XSS", "SQLi"])
    if not target:
        return ("Missing target", 400)
    try:
        h = urlparse(target if "//" in target else "http://" + target).netloc
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

    def bg():
        try:
            asyncio.run(run_scan_async(target, depth, speed, categories))
        except Exception as e:
            append_log(f"Background scan error: {e}")
        finally:
            STATE["running"] = False
    import threading
    threading.Thread(target=bg, daemon=True).start()
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
        if REPORTLAB:
            try:
                txt = rp_path.read_text(encoding="utf-8")
                generate_pdf_from_text(txt, pdfp)
                if pdfp.exists():
                    return send_file(str(pdfp), as_attachment=True)
                return ("PDF create failed", 500)
            except Exception:
                return ("PDF create failed", 500)
        return ("reportlab not installed", 400)
    else:
        if rp_path.exists():
            return send_file(str(rp_path), as_attachment=True)
        return ("Report not found", 404)

# ---------- run app ----------
if __name__ == "__main__":
    append_log("SECURESCAN starting")
    # FIX: was host="0.0.0.0", debug=True — exposed the Werkzeug debugger (arbitrary
    # code execution) to the whole network, and let anyone on your LAN launch scans
    # from your machine. Local-only, debugger off, by default.
    app.run(host="127.0.0.1", port=APP_PORT, debug=False)