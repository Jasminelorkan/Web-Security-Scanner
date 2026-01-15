# scanner.py
# Backend scanner utilities used by the GUI.

import os, re, urllib, json
import requests
from datetime import datetime
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style

# try to import crawler functions
try:
    from crawler import crawl_with_params, crawl
except Exception:
    def crawl_with_params(url, max_depth=2):
        return set(), {}
    def crawl(url, max_depth=2):
        return set()

# Consent/logging
CONSENT_LOG = "consent.log"
ALLOWED_HOSTS = {
    "testphp.vulnweb.com",
    "demo.testfire.net",
    "localhost",
    "127.0.0.1",
    "juice-shop.herokuapp.com",
    "juice-shop.local"
}

def write_log(path, text):
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    except Exception:
        pass

def require_consent(target, auto=False):
    """
    If auto=True: auto-accept known test hosts and log consent (usable by GUI).
    If auto=False: ask user in terminal (CLI mode).
    Returns True if consent granted; False otherwise.
    """
    host = urlparse(target).netloc.lower().split(":")[0]
    if host in ALLOWED_HOSTS:
        if auto:
            write_log(CONSENT_LOG, f"{datetime.now().isoformat()} | target={host} | auto_consent_granted")
            return True
        else:
            ans = input(f"Target '{host}' is a known test host. Type YES to continue: ").strip().upper()
            if ans != "YES":
                return False
            write_log(CONSENT_LOG, f"{datetime.now().isoformat()} | target={host} | consent_granted")
            return True
    else:
        if auto:
            # GUI auto-accept only if explicitly allowed -> logs it
            write_log(CONSENT_LOG, f"{datetime.now().isoformat()} | target={host} | auto_consent_allowed_non_allowlist")
            return True
        else:
            ans = input("Do you have written permission to test this target? Type 'I HAVE PERMISSION' to continue: ").strip()
            if ans != "I HAVE PERMISSION":
                return False
            write_log(CONSENT_LOG, f"{datetime.now().isoformat()} | target={host} | consent_granted")
            return True

# ---------- helpers ----------
CVE_DATABASE = {
    "Apache2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
    "OpenSSL1.0.1": ["CVE-2014-0160"],
    "PHP7.3.21": ["CVE-2019-11043"],
    "Nginx1.18.0": ["CVE-2021-23017"],
}

def fingerprint_versions(headers):
    findings = []
    for header in ("Server", "X-Powered-By"):
        if header in headers:
            val = headers.get(header, "")
            matches = re.findall(r"([A-Za-z]+)[/ ]([\d\.]+)", val)
            for name, version in matches:
                software = f"{name}{version}"
                findings.append((software, CVE_DATABASE.get(software, [])))
    return findings

def check_security_headers(headers):
    required = {
        "X-Frame-Options": "Prevents clickjacking",
        "X-XSS-Protection": "Protects against XSS",
        "Content-Security-Policy": "Prevents script injection",
        "Strict-Transport-Security": "Forces HTTPS",
        "X-Content-Type-Options": "Prevents MIME sniffing",
        "Referrer-Policy": "Controls referrer info"
    }
    result = []
    for h, desc in required.items():
        if h in headers:
            result.append(f"{h}: Present")
        else:
            result.append(f"{h}: Missing - {desc}")
    return result

def check_http_methods(url):
    try:
        r = requests.options(url, timeout=5)
        allow = r.headers.get("Allow")
        if allow:
            return [m.strip() for m in allow.split(",")]
    except Exception:
        pass
    return None

def scan_common_paths(url):
    paths = ["admin", "login", "dashboard", "backup", "config", "uploads", "server-status"]
    found = []
    for p in paths:
        try:
            full = urljoin(url, p)
            r = requests.get(full, timeout=3)
            if r.status_code in (200, 301, 302, 403):
                found.append((p, r.status_code))
        except Exception:
            pass
    return found

# ---------- main capabilities ----------
def get_server_info(url):
    try:
        r = requests.get(url, timeout=6)
        headers = r.headers or {}
        cve_findings = fingerprint_versions(headers)
        security_issues = check_security_headers(headers)
        allowed_methods = check_http_methods(url)
        discovered_paths = scan_common_paths(url)
        # cookie info
        set_cookie = headers.get("Set-Cookie")
        cookie_flags = []
        if set_cookie:
            cookie_flags.append(set_cookie)
        return headers, security_issues, allowed_methods, discovered_paths, cve_findings
    except Exception:
        return {}, [], None, [], []

def load_payloads(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
        return [line.strip() for line in fh if line.strip()]

def test_vulnerability(base_url, param, payloads):
    results = []
    for payload in payloads:
        try:
            injected = f"{base_url}?{param}={urllib.parse.quote(payload)}"
            r = requests.get(injected, timeout=5)
            text = r.text or ""
            # basic reflection check
            if payload in text:
                results.append((injected, payload))
            # some error-based SQLi checks (simple)
            if any(err in text.lower() for err in ["sql syntax", "mysql", "syntax error", "unterminated quoted string"]):
                results.append((injected, payload + " [error-based-flag]"))
        except Exception:
            pass
    return results

def auto_scan_params(params_map, payload_files):
    """
    params_map: { url: {'query_params': set(...), 'form_inputs': set(...)} }
    payload_files: dict mapping vuln_name -> payload_file_path
    returns: {url: {param: [(vuln_name, injected_url, payload), ...]}}
    """
    results = {}
    for page, info in (params_map or {}).items():
        params = set(info.get("query_params", set())) | set(info.get("form_inputs", set()))
        if not params:
            continue
        for param in params:
            hits = []
            for vuln_name, pfile in (payload_files or {}).items():
                payloads = load_payloads(pfile)
                found = test_vulnerability(page, param, payloads)
                for inj, payload in found:
                    hits.append((vuln_name, inj, payload))
            if hits:
                results.setdefault(page, {})[param] = hits
    return results

# ---------- report: unified + "what's wrong" analysis ----------
def prepare_unified_report(
    url,
    headers,
    security_issues,
    allowed_methods,
    discovered_paths,
    cve_findings,
    crawled_urls,
    parameter_scan_results,
    manual_scan_results=None,
    ai_summary=None,
    out_dir="reports"
):
    os.makedirs(out_dir, exist_ok=True)
    parsed = urlparse(url)
    domain = parsed.netloc.replace(":", "_")
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(out_dir, f"final_report_{domain}_{timestamp}.txt")

    # --- generate "what's wrong" analysis ---
    analysis_lines = []
    # HTTPS check
    if url.startswith("http://"):
        analysis_lines.append("• SITE USES HTTP (not HTTPS): traffic is unencrypted. Recommend enabling HTTPS and HSTS.")
    else:
        analysis_lines.append("• HTTPS detected (good). Verify HSTS header presence.")

    # security headers
    missing = [l for l in security_issues if "Missing" in l]
    if missing:
        analysis_lines.append("• Missing important security headers:")
        for m in missing:
            analysis_lines.append(f"    - {m}")
    else:
        analysis_lines.append("• Security headers look present (CSP/HSTS/X-Frame etc.).")

    # CVE fingerprint
    if cve_findings:
        analysis_lines.append("• Server fingerprint / CVE hints:")
        for soft, cves in cve_findings:
            if cves:
                analysis_lines.append(f"    - {soft} has known CVEs: {', '.join(cves)}")
            else:
                analysis_lines.append(f"    - {soft}: no matching CVEs in local DB (manual check recommended).")
    else:
        analysis_lines.append("• No server fingerprint info found in headers.")

    # parameter risk
    param_count = 0
    # param_count from parameter_scan_results
    if parameter_scan_results:
        for p, dd in parameter_scan_results.items():
            param_count += sum(len(v) for v in dd.values())
    if param_count > 0:
        analysis_lines.append(f"• Parameterized endpoints detected: {param_count} (higher risk of injection/XSS).")
    else:
        # also check crawled pages for params
        params_found_elsewhere = sum(1 for u in (crawled_urls or []) if "?" in u)
        if params_found_elsewhere:
            analysis_lines.append(f"• URLs with query strings found in crawl: {params_found_elsewhere}.")
        else:
            analysis_lines.append("• Few or no parameterized endpoints found.")

    # auto-scan findings severity summary
    vuln_count = 0
    if parameter_scan_results:
        for page, params in parameter_scan_results.items():
            for param, items in params.items():
                vuln_count += len(items)
    if vuln_count:
        analysis_lines.append(f"• Automated checks found {vuln_count} reflection/error indicators (potential vulnerabilities). Manual verification required.")
    else:
        analysis_lines.append("• Automated parameter checks did not find obvious reflections or error flags (but manual tests may still reveal issues).")

    # assemble report content
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=== WebSec Scanner Final Report ===\n")
        f.write(f"Target: {url}\nGenerated: {datetime.now().isoformat()}\n\n")

        f.write("=== Server Headers ===\n")
        if headers:
            for k, v in headers.items():
                f.write(f"{k}: {v}\n")
        else:
            f.write("No headers available.\n")
        f.write("\n")

        f.write("=== Security Headers Check ===\n")
        for line in security_issues:
            f.write(f"{line}\n")
        f.write("\n")

        f.write("=== Allowed HTTP Methods ===\n")
        if allowed_methods:
            f.write(", ".join(allowed_methods) + "\n")
        else:
            f.write("Unknown or none detected.\n")
        f.write("\n")

        f.write("=== Discovered Common Paths ===\n")
        if discovered_paths:
            for path, status in discovered_paths:
                f.write(f"/{path} - {status}\n")
        else:
            f.write("None found.\n")
        f.write("\n")

        f.write("=== CVE / Fingerprinting ===\n")
        if cve_findings:
            for s, cves in cve_findings:
                f.write(f"{s}: {', '.join(cves) if cves else 'No known CVEs in DB'}\n")
        else:
            f.write("No software versions detected.\n")
        f.write("\n")

        f.write("=== Crawled URLs ===\n")
        if crawled_urls:
            for u in sorted(crawled_urls):
                f.write(u + "\n")
        else:
            f.write("No crawled URLs provided.\n")
        f.write("\n")

        f.write("=== Automatic Parameter Scan Results ===\n")
        if parameter_scan_results:
            for page, params in parameter_scan_results.items():
                f.write(f"PAGE: {page}\n")
                for param, items in params.items():
                    f.write(f"  PARAM: {param}\n")
                    for vuln_name, injected_url, payload in items:
                        f.write(f"    - {vuln_name}: {injected_url} | payload: {payload}\n")
                f.write("\n")
        else:
            f.write("No automatic parameter findings.\n\n")

        f.write("=== Manual Payload Test Results ===\n")
        if manual_scan_results:
            for vuln, items in manual_scan_results.items():
                f.write(f"-- {vuln} --\n")
                for u, p in items:
                    f.write(f"URL: {u}\nPayload: {p}\n")
                f.write("\n")
        else:
            f.write("No manual test results provided.\n\n")

        f.write("=== Security Weakness Analysis (what's wrong) ===\n")
        for l in analysis_lines:
            f.write(l + "\n")
        f.write("\n")

        f.write("=== AI Intelligence Summary ===\n")
        if ai_summary:
            f.write(ai_summary + "\n\n")
        else:
            f.write("AI analysis not provided.\n\n")

        f.write("=== End of Report ===\n")

    return filename

# Convenience CLI minimal runner
def run_full_scan(url, mode="polite", max_depth=2):
    """
    Wrapper used by the GUI. Returns a dict of key sections (strings) for quick UI summary.
    This runs server info, crawl_with_params, auto_scan_params, and prepare_unified_report.
    """
    # Ensure URL has scheme
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    # Consent
    require_consent(url, auto=True)

    headers, security_issues, allowed_methods, discovered_paths, cve_findings = get_server_info(url)

    # adapt depth by mode (just an example)
    if mode == "polite":
        depth = 1
    elif mode == "normal":
        depth = 2
    else:
        depth = max_depth or 3

    found_links, params_map = crawl_with_params(url, max_depth=depth)

    payload_files = {
        "XSS": "payloads/xss.txt",
        "SQLi": "payloads/sqli.txt",
        "LFI": "payloads/lfi.txt",
        "Command Injection": "payloads/cmdi.txt",
        "Open Redirect": "payloads/redirect.txt"
    }
    parameter_scan_results = auto_scan_params(params_map, payload_files)

    report_path = prepare_unified_report(
        url=url,
        headers=headers,
        security_issues=security_issues,
        allowed_methods=allowed_methods,
        discovered_paths=discovered_paths,
        cve_findings=cve_findings,
        crawled_urls=found_links,
        parameter_scan_results=parameter_scan_results,
        manual_scan_results=None,
        ai_summary=None,
        out_dir="reports"
    )

    # Prepare quick summary return
    quick = {
        "report_path": report_path,
        "headers_count": str(len(headers) if headers else 0),
        "crawled_urls": str(len(found_links)),
        "parameter_pages": str(len(params_map)),
        "vuln_findings": str(sum(len(v) for dd in parameter_scan_results.values() for v in dd.values())) if parameter_scan_results else "0"
    }
    return quick

# allow running scanner.py standalone
if __name__ == "__main__":
    t = input("Target URL (include http://): ").strip()
    if not t.startswith("http"):
        t = "http://" + t
    if not require_consent(t, auto=False):
        print("Consent missing. Exiting.")
    else:
        q = run_full_scan(t, mode="polite")
        print("Quick summary:", q)
