import os
import re
import urllib
import requests
from datetime import datetime
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style
from crawler import crawl_with_params
import time
from functools import wraps
from urllib.parse import urlparse


# ================= BASIC SCAN COMPONENTS =================

ALLOWED_HOSTS={
    "testphp.vulnweb.com",
    "demo.testfire.net",
    "localhost",
    "127.0.0.1",
    "juice-shop.herokuapp.com",
    "juice-shop.local"
}

SAFE_MODE = True

# consent and activity log locations
CONSENT_LOG="consent.log"
ACTIVITY_LOG="activity.log"

def write_log(path,text):
    try:
        with open(path,"a",encoding="utf-8") as fh:
            fh.write(text+"\n")
    except Exception:
        pass

def require_consent(target):
    """
    Check allowlist and require typed consent if target not on allowlist.
    Returns True if consent recorded, False otherwise.
    """
    host=urlparse(target).netloc.lower().split(":")[0]
    print("\nIMPORTANT: Only scan sites you own or have written permission to test.")     

    if host in ALLOWED_HOSTS:
        ans=input(f"Target '{host}' is a known test host. Type YES to continue: ").strip().upper()
        if ans!="YES":
            print("Consent not given. Aborting.")
            return False  
    else:
        print(f"Target '{host}' is NOT on the built-in allowlist.")
        ans = input("Do you have written permission to test this target? Type 'I HAVE PERMISSION' to continue: ").strip()
        if ans != "I HAVE PERMISSION":
            print("Consent not provided. Aborting.")
            return False             

    # record consent 
    write_log(CONSENT_LOG, f"{datetime.now().isoformat()} | target={host} | consent_granted")
    return True    

def rate_limited(min_delay_seconds=0.6):
    """Decorator to ensure polite delays between requests."""
    def decorator(fn):
        last = {"t": 0.0}
        @wraps(fn)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last["t"]
            wait = min_delay_seconds - elapsed
            if wait > 0:
                time.sleep(wait)
            result = fn(*args, **kwargs)
            last["t"] = time.time()
            return result
        return wrapper
    return decorator

def get_server_info(url):
    try:
        print(Fore.CYAN + f"\n[+] Connecting to {url}..." + Style.RESET_ALL)
        response = requests.get(url, timeout=5)
        print(Fore.GREEN + f"[+] Site reachable! Status Code: {response.status_code}\n" + Style.RESET_ALL)

        headers = response.headers
        for k, v in headers.items():
            print(f"    {k}: {v}")

        cve_findings = fingerprint_versions(headers)
        security_issues = check_security_headers(headers)
        allowed_methods = check_http_methods(url)
        discovered_paths = scan_common_paths(url)

        return headers, security_issues, allowed_methods, discovered_paths, cve_findings

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[-] Error: {e}" + Style.RESET_ALL)
        return {}, [], None, [], []


def check_security_headers(headers):
    print(Fore.CYAN + "\n[+] Checking Security Headers..." + Style.RESET_ALL)
    report_lines = []
    required = {
        "X-Frame-Options": "Prevents clickjacking",
        "X-XSS-Protection": "Protects against XSS",
        "Content-Security-Policy": "Prevents script injection",
        "Strict-Transport-Security": "Forces HTTPS",
        "X-Content-Type-Options": "Prevents MIME sniffing",
        "Referrer-Policy": "Controls referrer info"
    }

    for h, desc in required.items():
        if h in headers:
            print(Fore.GREEN + f"[+] {h} Present ✅" + Style.RESET_ALL)
            report_lines.append(f"{h}: Present")
        else:
            print(Fore.RED + f"[-] {h} Missing ❌ - {desc}" + Style.RESET_ALL)
            report_lines.append(f"{h}: Missing - {desc}")

    return report_lines


def check_http_methods(url):
    print("\n[+] Checking allowed HTTP methods...")
    try:
        r = requests.options(url)
        allow = r.headers.get("Allow")
        if allow:
            methods = [m.strip() for m in allow.split(",")]
            print("    Allowed Methods:", ", ".join(methods))
            return methods
        else:
            print("    ❓ Could not determine allowed methods.")
            return None
    except Exception as e:
        print("    ❌ Error:", e)
        return None


def scan_common_paths(url):
    print("\n[+] Discovering common directories...")
    paths = ["admin", "login", "dashboard", "backup", "config", "uploads", "server-status"]
    found = []
    for path in paths:
        full = urljoin(url, path)
        try:
            r = requests.get(full, timeout=3)
            if r.status_code in [200, 301, 302, 403]:
                print(f"  /{path} - {r.status_code} ✅")
                found.append((path, r.status_code))
            else:
                print(f"  /{path} - {r.status_code} ❌")
        except:
            pass
    return found


# ================= CVE CHECK =================

CVE_DATABASE = {
    "Apache2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
    "OpenSSL1.0.1": ["CVE-2014-0160"],
    "PHP7.3.21": ["CVE-2019-11043"],
    "Nginx1.18.0": ["CVE-2021-23017"],
}

def fingerprint_versions(headers):
    detected = []
    findings = []
    for header in ["Server", "X-Powered-By"]:
        if header in headers:
            matches = re.findall(r"([A-Za-z]+)[/ ]([\d\.]+)", headers[header])
            for name, version in matches:
                software = f"{name}{version}"
                detected.append(software)
                if software in CVE_DATABASE:
                    findings.append((software, CVE_DATABASE[software]))
                else:
                    findings.append((software, []))
    return findings


# ================= PAYLOAD SCANNER =================

def load_payloads(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        return [p.strip() for p in f if p.strip()]


def test_vulnerability(base_url, param, payloads):
    results = []
    for payload in payloads:
        url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
        try:
            r = requests.get(url, timeout=5)
            if payload in r.text:
                results.append((url, payload))
        except:
            pass
    return results


# ================= UNIFIED REPORT =================

def prepare_unified_report(url, headers, security_issues, allowed_methods,
                           discovered_paths, cve_findings, crawled, params_map, auto_scan):
    os.makedirs("reports", exist_ok=True)
    domain = urlparse(url).netloc.replace(":", "_")
    filename = f"reports/{domain}_Final_Report.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=== Web Security Scanner Unified Report ===\n")
        f.write(f"Target: {url}\nGenerated: {datetime.now()}\n\n")

        f.write("=== SERVER INFO ===\n")
        for k, v in headers.items():
            f.write(f"{k}: {v}\n")
        f.write("\n")

        f.write("=== SECURITY HEADERS ===\n")
        for i in security_issues:
            f.write(f"{i}\n")
        f.write("\n")

        f.write("=== ALLOWED HTTP METHODS ===\n")
        f.write(", ".join(allowed_methods or []) + "\n\n")

        f.write("=== HIDDEN DIRECTORIES ===\n")
        for p, s in discovered_paths:
            f.write(f"/{p} - {s}\n")
        f.write("\n")

        f.write("=== CVE FINDINGS ===\n")
        for s, cves in cve_findings:
            f.write(f"{s}: {', '.join(cves) if cves else 'No known CVEs'}\n")
        f.write("\n")

        f.write("=== CRAWLED LINKS ===\n")
        for link in sorted(crawled):
            f.write(link + "\n")
        f.write("\n")

        f.write("=== PARAMETER MAP ===\n")
        for page, info in params_map.items():
            qp = ", ".join(info.get("query_params", []))
            fi = ", ".join(info.get("form_inputs", []))
            f.write(f"{page} | Query: {qp} | Forms: {fi}\n")
        f.write("\n")

        f.write("=== AUTO SCAN RESULTS ===\n")
        if not auto_scan:
            f.write("No vulnerabilities found.\n")
        else:
            for page, params in auto_scan.items():
                for param, items in params.items():
                    for vuln, inj_url, payload in items:
                        f.write(f"{vuln} -> {inj_url} | Payload: {payload}\n")
        f.write("\n=== END OF REPORT ===\n")

    print(Fore.GREEN + f"\n[+] Unified Report saved: {filename}\n" + Style.RESET_ALL)



# ================= MAIN =================

if __name__ == "__main__":
    print(Fore.MAGENTA + "\n=== WebSec Scanner ===" + Style.RESET_ALL)
    url = input("Enter target URL (e.g., https://example.com): ").strip()
    if not url.startswith("http"):
        url = "https://" + url

    # ✅ Require consent before scanning
    if not require_consent(url):
        exit()

    # ✅ Log scan start
    write_log(ACTIVITY_LOG, f"{datetime.now().isoformat()} | target={url} | scan_started")

    # Basic scan
    headers, security_issues, allowed_methods, discovered_paths, cve_findings = get_server_info(url)

    # Crawl the site
    print(Fore.CYAN + "\n[+] Crawling site..." + Style.RESET_ALL)
    found_links, params_map = crawl_with_params(url, max_depth=2)
    print(f"[+] Crawl complete. {len(found_links)} URLs found, {len(params_map)} pages with parameters.\n")

    # Automatic payload tests
    print(Fore.CYAN + "[+] Running automatic payload tests..." + Style.RESET_ALL)
    payload_files = {
        "XSS": "payloads/xss.txt",
        "SQLi": "payloads/sqli.txt",
        "LFI": "payloads/lfi.txt",
        "Command Injection": "payloads/cmdi.txt",
        "Open Redirect": "payloads/redirect.txt"
    }

    auto_scan_results = {}
    for url_page, info in params_map.items():
        auto_scan_results.setdefault(url_page, {})
        params = set(info.get("query_params", [])) | set(info.get("form_inputs", []))
        for param in params:
            findings = []
            for vuln, file in payload_files.items():
                payloads = load_payloads(file)
                found = test_vulnerability(url_page, param, payloads)
                for u, p in found:
                    findings.append((vuln, u, p))
            if findings:
                auto_scan_results[url_page][param] = findings

    # Final unified report
    prepare_unified_report(
        url,
        headers,
        security_issues,
        allowed_methods,
        discovered_paths,
        cve_findings,
        found_links,
        params_map,
        auto_scan_results
    )

    # ✅ Log scan completion
    write_log(ACTIVITY_LOG, f"{datetime.now().isoformat()} | target={url} | scan_completed")

    print(Fore.GREEN + "[+] Scan completed successfully!" + Style.RESET_ALL)
