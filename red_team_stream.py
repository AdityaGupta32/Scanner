import sys
import os
import time
import json
import urllib.request
import urllib.error

# Ensure UTF-8 output in Windows PowerShell
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

RED = "\033[91m"
BOLD_RED = "\033[1;91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
WHITE = "\033[97m"
RESET = "\033[0m"

def fetch_scan(scan_id):
    url = f"http://localhost:8000/scan/{scan_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VerseScan-RedTeam-CLI"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, Exception):
        return None

def print_red_exploit(i, finding):
    name = finding.get("name", "Arbitrary Exploit")
    sev = str(finding.get("severity", "MEDIUM")).upper()
    cwe = finding.get("cwe", "CWE-Unknown")
    vuln_url = finding.get("url", "")
    param = finding.get("param", "RAW_REQUEST")
    payload = finding.get("payload", "[N/A]")
    evidence = finding.get("evidence", "Payload executed on target endpoint.")

    print(f"\n{BOLD_RED}╔═══════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD_RED}║ [EXPLOIT #{i:03d}] {name:<45} [{sev}] ║{RESET}")
    print(f"{BOLD_RED}╚═══════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"  {BOLD}Target Endpoint{RESET} : {WHITE}{vuln_url}{RESET}")
    print(f"  {BOLD}Attack Surface {RESET} : Param: {YELLOW}{param}{RESET} | Standard: {CYAN}{cwe}{RESET}")
    print(f"  {BOLD_RED}Injected Payload{RESET}: {BOLD_RED}{payload}{RESET}")
    
    # Evidence / Exploit Proof
    evidence_clean = str(evidence).strip()
    if len(evidence_clean) > 200:
        evidence_clean = evidence_clean[:200] + "..."
    print(f"  {BOLD}Exploit Proof  {RESET} : {YELLOW}{evidence_clean}{RESET}")

def get_latest_scan_id():
    try:
        req = urllib.request.Request("http://localhost:8000/history", headers={"User-Agent": "VerseScan-RedTeam-CLI"})
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

    print(f"\n{BOLD_RED}╔═══════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD_RED}║  VerseScan — RED TEAM AUTONOMOUS EXPLOIT LAUNCHER                             ║{RESET}")
    print(f"{BOLD_RED}║  Live Offensive Attack Stream & Payload Delivery Telemetry                   ║{RESET}")
    print(f"{BOLD_RED}╚═══════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print(f"Connecting to Target Scan: {BOLD}{scan_id}{RESET}")
    print(f"{RED}[*] Live Red Team offensive stream active. Tracking payload deliveries...{RESET}\n")

    printed_count = 0
    dots = 0

    try:
        while True:
            scan_data = fetch_scan(scan_id)
            if not scan_data:
                time.sleep(2)
                continue

            target = scan_data.get("target_url") or scan_data.get("target", "Target")
            status = scan_data.get("status", "Running")
            findings = scan_data.get("findings", [])
            total_vulns = len(findings)

            # Stream newly delivered exploits
            if total_vulns > printed_count:
                for idx in range(printed_count, total_vulns):
                    print_red_exploit(idx + 1, findings[idx])
                printed_count = total_vulns
                print(f"\n{BOLD_RED}───────────────────────────────────────────────────────────────────────────────{RESET}")

            # Exit if scan complete
            if str(status).lower() in ["completed", "done", "finished"]:
                print(f"\n{BOLD_RED}[✔] RED TEAM RUN COMPLETE — {total_vulns} offensive vectors delivered and documented.{RESET}\n")
                break
            elif str(status).lower() in ["failed", "error", "stopped"]:
                print(f"\n{RED}[!] Offensive run stopped. Status: {status}{RESET}\n")
                break

            # Live offensive heartbeat
            anim = ">" * ((dots % 4) + 1)
            dots += 1
            sys.stdout.write(f"\r{BOLD_RED}[ATTACKING {anim:<4}]{RESET} Target: {target[:32]} | Exploits Fired: {BOLD_RED}{total_vulns}{RESET} | Status: {status} (Ctrl+C to pause)   ")
            sys.stdout.flush()

            time.sleep(3)

    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[*] Red Team stream paused by user.{RESET}\n")

if __name__ == "__main__":
    main()
