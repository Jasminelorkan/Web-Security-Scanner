from flask import Flask, render_template_string, request, send_file, jsonify
import os
import datetime
import scanner  # your scanner.py
import crawler  # your crawler.py

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>CyberScanX – Cinematic Web Scanner</title>
    <style>
        body {
            background-color: #030303;
            color: #00ffcc;
            font-family: Consolas, monospace;
            margin: 0;
            padding: 0;
        }
        h1 {
            text-align: center;
            padding: 20px;
            color: #00ffcc;
            font-size: 32px;
            text-shadow: 0px 0px 12px #00ffcc;
        }
        .container {
            width: 85%;
            margin: auto;
            padding: 20px;
            background: rgba(0, 255, 200, 0.05);
            border: 1px solid #00ffcc;
            border-radius: 10px;
            box-shadow: 0 0 20px #00ffcc33;
        }
        label { font-size: 18px; }
        input, select {
            width: 100%;
            padding: 10px;
            background: #000;
            color: #00ffcc;
            border: 1px solid #00ffcc;
            margin-top: 5px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #00ffcc;
            border: none;
            margin-top: 15px;
            color: #000;
            font-size: 18px;
            font-weight: bold;
            box-shadow: 0 0 10px #00ffccaa;
            cursor: pointer;
        }
        button:hover {
            background: #00ffaa;
            box-shadow: 0 0 20px #00ffaa;
        }
        #terminal {
            width: 100%;
            height: 350px;
            background: #000;
            color: #00ffcc;
            padding: 12px;
            margin-top: 20px;
            border: 1px solid #00ffcc;
            overflow-y: scroll;
            white-space: pre-wrap; /* FIXES HORIZONTAL LOG ISSUE */
        }
        .checkbox-container {
            margin-top: 10px;
        }
    </style>
</head>

<body>
<h1>CyberScanX – Web Vulnerability Scanner</h1>

<div class="container">
    <label>Enter Target URL</label>
    <input id="url" type="text" placeholder="https://example.com">

    <label>Scan Mode</label>
    <select id="mode">
        <option value="normal">Normal</option>
        <option value="polite">Polite (Slow, Safe)</option>
        <option value="aggressive">Aggressive (Fast)</option>
    </select>

    <div class="checkbox-container">
        <input id="consent" type="checkbox">
        <label for="consent">I have authorization to scan this website</label>
    </div>

    <button onclick="startScan()">▶ Start Scan</button>
    <button onclick="downloadReport()">⬇ Download Report</button>

    <div id="terminal"></div>
</div>

<script>
function log(msg) {
    let term = document.getElementById("terminal");
    term.textContent += msg + "\\n"; 
    term.scrollTop = term.scrollHeight;
}

function startScan() {
    let url = document.getElementById("url").value;
    let mode = document.getElementById("mode").value;
    let consent = document.getElementById("consent").checked;

    document.getElementById("terminal").textContent = "";
    log("[*] Initializing cinematic scan...");
    log("[*] Mode: " + mode);

    if (!consent) {
        log("[!] ERROR: Consent required.");
        return;
    }

    fetch("/scan", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({url:url, mode:mode, consent:true})
    })
    .then(res => res.json())
    .then(data => {
        data.logs.forEach(line => log(line));
        log("\\n[✓] Scan finished.");
        log("[*] Report saved as: " + data.report_name);
    });
}

function downloadReport() {
    window.location.href = "/download_report";
}
</script>

</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML)

@app.route("/scan", methods=["POST"])
def scan_site():
    data = request.get_json()
    url = data["url"]
    mode = data["mode"]
    consent = data["consent"]

    logs = []

    if not consent:
        return jsonify({"error": "Consent missing"}), 400

    def log(msg):
        logs.append(msg)

    log("[+] Connecting to target...")
    alive, headers = scanner.check_site(url)
    if not alive:
        log("[-] Site unreachable.")
    else:
        log("[+] Site reachable.")
        for h, v in headers.items():
            log(f"    {h}: {v}")

    log("\n[+] Crawling website...")
    crawled = crawler.start_crawl(url)
    log(f"[+] Found {len(crawled)} URLs")

    log("\n[+] Running vulnerability checks...")
    results = scanner.run_tests(url, crawled)
    for r in results:
        log(" - " + r)

    # Create report
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_name = f"Unified_Report_{now}.txt"
    os.makedirs("reports", exist_ok=True)
    report_path = os.path.join("reports", report_name)

    with open(report_path, "w") as f:
        f.write("\n".join(logs))

    app.config["last_report"] = report_path

    return jsonify({"logs": logs, "report_name": report_name})

@app.route("/download_report")
def download_report():
    report_path = app.config.get("last_report", None)
    if not report_path:
        return "No report generated yet."
    return send_file(report_path, as_attachment=True)

if __name__ == "__main__":
    app.run(port=5000, debug=True)
