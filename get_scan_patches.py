import sys
import os
import time
import json
import urllib.request
import urllib.error

# Ensure UTF-8 output in Windows PowerShell
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

def fetch_scan(scan_id):
    url = f"http://localhost:8000/scan/{scan_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VerseScan-CLI"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, Exception):
        return None

def print_finding(i, finding):
    name = finding.get("name", "Unknown Vulnerability")
    sev = str(finding.get("severity", "MEDIUM")).upper()
    cwe = finding.get("cwe", "CWE-Unknown")
    vuln_url = finding.get("url", "")
    param = finding.get("param", "N/A")
    payload = finding.get("payload", "N/A")
    remediation = finding.get("remediation", "Apply input validation and parameterized handlers.")

    sev_color = RED if sev in ["CRITICAL", "HIGH"] else YELLOW

    print(f"\n{BOLD}{sev_color}───────────────────────────────────────────────────────────────────────────{RESET}")
    print(f"{BOLD}#{i} [{sev}] {name} ({cwe}){RESET}")
    print(f"  {CYAN}Endpoint{RESET} : {vuln_url}")
    if param != "N/A":
        print(f"  {CYAN}Param{RESET}    : {param}")
    if payload != "N/A":
        print(f"  {CYAN}Payload{RESET}  : {payload}")

    print(f"\n  {BOLD}{GREEN}[★] VIRTUAL SHIELD RULE (Autonomous WAF Directive):{RESET}")
    p_name = param if param != "N/A" else "input"
    rule_id = 1000 + i
    if "sql" in name.lower():
        rule = 'SecRule ARGS:%s "@rx (?i)(\\b(OR|AND)\\b|UNION\\s+SELECT|--|\'\\s*OR\\s*\'1\'=\'1)" "id:%d,phase:2,deny,status:403,msg:\'VerseScan Shield: Blocked SQLi Attack\'"' % (p_name, rule_id)
    elif "remote code" in name.lower() or "rce" in name.lower():
        rule = 'SecRule ARGS:%s "@rx (?i)(;|\\||&&|\\bexec\\b|\\bsystem\\b|\\bcat\\b|\\bwhoami\\b)" "id:%d,phase:2,deny,status:403,msg:\'VerseScan Shield: Blocked RCE Attack\'"' % (p_name, rule_id)
    elif "template injection" in name.lower() or "ssti" in name.lower():
        rule = 'SecRule ARGS:%s "@rx (\\{\\{.*?\\}\\}|\\$\\{.*?\\}|<%%.*?%%>)" "id:%d,phase:2,deny,status:403,msg:\'VerseScan Shield: Blocked SSTI Delimiter\'"' % (p_name, rule_id)
    elif "prompt" in name.lower() or "genai" in name.lower():
        rule = 'SecRule ARGS "@rx (?i)(ignore previous instructions|system prompt|bypass safety)" "id:%d,phase:2,deny,status:403,msg:\'VerseScan Shield: Blocked GenAI Prompt Injection\'"' % rule_id
    else:
        rule = 'SecRule REQUEST_URI "@rx (?i)(%s)" "id:%d,phase:2,deny,status:403,msg:\'VerseScan Shield: Blocked Exploit Payload\'"' % (p_name, rule_id)
    print(f"    {GREEN}{rule}{RESET}")

    print(f"\n  {BOLD}{CYAN}[★] SOURCE CODE REMEDIATION PATCH:{RESET}")
    print(f"    {remediation}")


def get_latest_scan_id():
    try:
        req = urllib.request.Request("http://localhost:8000/history", headers={"User-Agent": "VerseScan-CLI"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data and len(data) > 0:
                return data[0].get("id")
    except Exception:
        pass
    return "7f556a46-8974-48c2-a831-7f8ea004d777"

def main():
    if len(sys.argv) > 1:
        scan_id = sys.argv[1].strip("<> ")
    else:
        scan_id = get_latest_scan_id()

    print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN}  VerseScan — Live Continuous Patch Streamer{RESET}")
    print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════════════════════════════{RESET}")
    print(f"Connecting to live scan: {BOLD}{scan_id}{RESET}")
    print(f"{MAGENTA}[*] Continuous mode active: Streaming new patches until scan completes...{RESET}\n")

    printed_count = 0
    dots = 0

    try:
        while True:
            scan_data = fetch_scan(scan_id)
            if not scan_data:
                print(f"\r{YELLOW}[!] Waiting for backend to respond...{RESET}", end="", flush=True)
                time.sleep(2)
                continue

            target = scan_data.get("target_url") or scan_data.get("target", "Target")
            status = scan_data.get("status", "Running")
            findings = scan_data.get("findings", [])
            total_vulns = len(findings)

            # Print newly discovered findings
            if total_vulns > printed_count:
                for idx in range(printed_count, total_vulns):
                    finding = findings[idx]
                    sev = str(finding.get("severity", "")).upper()
                    # Highlight Critical, High and Medium
                    print_finding(idx + 1, finding)
                printed_count = total_vulns
                print(f"\n{CYAN}───────────────────────────────────────────────────────────────────────────{RESET}")

            # Check if scan is finished
            if str(status).lower() in ["completed", "done", "finished"]:
                print(f"\n{BOLD}{GREEN}✔ SCAN COMPLETED SUCCESSFULLY!{RESET}")
                print(f"Final Count: {BOLD}{total_vulns} total vulnerabilities discovered and protected.{RESET}")
                print(f"Executive Report: {BOLD}http://localhost:8000/owasp-report/{scan_id}{RESET}\n")
                break
            elif str(status).lower() in ["failed", "error", "stopped"]:
                print(f"\n{RED}[!] Scan ended with status: {status}{RESET}\n")
                break

            # Live heartbeat line
            anim = "." * ((dots % 4) + 1)
            dots += 1
            sys.stdout.write(f"\r{YELLOW}[Scanning{anim:<4}]{RESET} Target: {target[:30]} | Vulns Found: {BOLD}{total_vulns}{RESET} | Status: {GREEN}{status}{RESET} (Ctrl+C to exit)   ")
            sys.stdout.flush()

            time.sleep(3)

    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[*] Live stream paused by user. Scan is still running in background.{RESET}\n")


if __name__ == "__main__":
    main()
