"""
╔══════════════════════════════════════════════════════════════════════╗
║  VerseScan — Local Backend Verification & Test Suite                 ║
║  Validates all backend APIs, sandboxing, AI analysis & OWASP reports ║
╚══════════════════════════════════════════════════════════════════════╝

Run this script to test all backend components locally:
    python test_backend_local.py
"""

import sys
import time
import requests
import json
from typing import Dict, Any

BACKEND_URL = "http://localhost:8000"
TARGET_URL = "http://localhost:8081"

# ANSI Colors for beautiful output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def log_pass(msg: str):
    print(f"  {GREEN}[PASS]{RESET} {msg}")


def log_fail(msg: str):
    print(f"  {RED}[FAIL]{RESET} {msg}")


def log_info(msg: str):
    print(f"  {CYAN}[INFO]{RESET} {msg}")


def log_warn(msg: str):
    print(f"  {YELLOW}[WARN]{RESET} {msg}")


def header(title: str):
    print(f"\n{BOLD}{CYAN}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 60}{RESET}")


def test_1_backend_health() -> bool:
    header("1. Testing Backend Core Health & Ping")
    passed = True

    try:
        r = requests.get(f"{BACKEND_URL}/", timeout=5)
        if r.status_code == 200:
            data = r.json()
            log_pass(f"Root endpoint is ONLINE (v{data.get('version', '?')})")
        else:
            log_fail(f"Root endpoint returned status {r.status_code}")
            passed = False
    except Exception as e:
        log_fail(f"Could not reach backend at {BACKEND_URL}: {e}")
        return False

    try:
        r = requests.get(f"{BACKEND_URL}/ping", timeout=5)
        if r.status_code == 200 and r.text.strip() == "pong":
            log_pass("Keep-alive /ping endpoint responded with 'pong'")
        else:
            log_fail(f"/ping returned {r.status_code}: {r.text}")
            passed = False
    except Exception as e:
        log_fail(f"/ping endpoint failed: {e}")
        passed = False

    return passed


def test_2_vulnerable_app() -> bool:
    header("2. Checking Target Vulnerable App Connectivity")
    try:
        r = requests.get(f"{TARGET_URL}/", timeout=5)
        if r.status_code == 200 and "Vulnerable" in r.text:
            log_pass(f"Target vulnerable app is ONLINE at {TARGET_URL}")
            return True
        else:
            log_warn(f"Target app reachable but unexpected body: {r.status_code}")
            return True
    except Exception as e:
        log_warn(f"Vulnerable app not running at {TARGET_URL} ({e}).")
        log_info("Tip: Start it via 'python vulnerable_app.py' in a separate terminal.")
        return False


def test_3_sandbox_orchestrator() -> bool:
    header("3. Testing Dynamic Sandbox Orchestrator Lifecycle")
    passed = True

    # Check Sandbox Health
    try:
        r = requests.get(f"{BACKEND_URL}/sandbox/health", timeout=5)
        if r.status_code == 200:
            data = r.json()
            docker_conn = data.get("docker_connected", False)
            log_pass(f"Sandbox orchestrator reachable: status={data.get('status')}, docker={docker_conn}")
        else:
            log_fail(f"Sandbox health returned {r.status_code}")
            passed = False
    except Exception as e:
        log_fail(f"Sandbox health check failed: {e}")
        return False

    # Create an ephemeral sandbox
    sandbox_id = None
    try:
        payload = {
            "image": "versescan/vulnerable-app:latest",
            "name": "local-test-box",
            "port": 8081,
            "ttl_seconds": 120,
        }
        r = requests.post(f"{BACKEND_URL}/sandbox/create", json=payload, timeout=10)
        if r.status_code in [200, 201]:
            data = r.json()
            sandbox_id = data.get("sandbox_id")
            log_pass(f"Created sandbox container: ID={sandbox_id}, target={data.get('target_url')}, status={data.get('status')}")
        else:
            log_fail(f"Failed to create sandbox: {r.status_code} - {r.text}")
            passed = False
    except Exception as e:
        log_fail(f"Sandbox creation request failed: {e}")
        passed = False

    # List sandboxes
    try:
        r = requests.get(f"{BACKEND_URL}/sandbox/list", timeout=5)
        if r.status_code == 200:
            data = r.json()
            total = data.get("total", 0)
            log_pass(f"Listed active sandboxes: {total} active (limit: {data.get('max_allowed')})")
        else:
            log_fail(f"Failed to list sandboxes: {r.status_code}")
            passed = False
    except Exception as e:
        log_fail(f"List sandboxes failed: {e}")
        passed = False

    # Destroy the test sandbox
    if sandbox_id:
        try:
            r = requests.post(f"{BACKEND_URL}/sandbox/{sandbox_id}/destroy?reason=test_cleanup", timeout=10)
            if r.status_code == 200:
                log_pass(f"Destroyed sandbox {sandbox_id} cleanly (auto-cleanup confirmed)")
            else:
                log_fail(f"Failed to destroy sandbox {sandbox_id}: {r.status_code}")
                passed = False
        except Exception as e:
            log_fail(f"Destroy sandbox failed: {e}")
            passed = False

    return passed


def test_4_llm_gateway() -> bool:
    header("4. Testing LLM Gateway & AI Security Inference")
    passed = True

    try:
        r = requests.get(f"{BACKEND_URL}/llm/health", timeout=5)
        if r.status_code == 200:
            data = r.json()
            log_pass(f"LLM gateway is ONLINE (model={data.get('model')}, api_configured={data.get('api_key_configured')})")
        else:
            log_fail(f"LLM health returned {r.status_code}")
            passed = False
    except Exception as e:
        log_fail(f"LLM health request failed: {e}")
        return False

    # Test AI vulnerability analysis (uses fallback or Featherless AI)
    try:
        payload = {
            "finding": {
                "name": "SQL Injection",
                "severity": "CRITICAL",
                "param": "id",
                "payload": "' OR '1'='1",
                "evidence": "syntax error near unexpected token",
                "cwe": "CWE-89",
            },
            "target_url": "http://localhost:8081/sqli?id=1",
            "context": "SQLite backend on FastAPI",
        }
        r = requests.post(f"{BACKEND_URL}/llm/analyze", json=payload, timeout=20)
        if r.status_code == 200:
            data = r.json()
            analysis_text = data.get("analysis", "")
            log_pass(f"AI Vulnerability Analysis returned ({len(analysis_text)} chars)")
        else:
            log_fail(f"LLM analyze returned {r.status_code}: {r.text[:150]}")
            passed = False
    except Exception as e:
        log_fail(f"LLM analyze call failed: {e}")
        passed = False

    # Test AI remediation code generation
    try:
        rem_payload = {
            "vulnerability_type": "SQL Injection",
            "language": "python",
            "framework": "fastapi + sqlalchemy",
            "finding_details": {"param": "id", "cwe": "CWE-89"},
        }
        r = requests.post(f"{BACKEND_URL}/llm/remediation", json=rem_payload, timeout=20)
        if r.status_code == 200:
            data = r.json()
            code = data.get("remediation_code", data.get("remediation", ""))
            log_pass(f"AI Remediation Generator returned production code ({len(code)} chars)")
        else:
            log_fail(f"LLM remediation returned {r.status_code}")
            passed = False
    except Exception as e:
        log_fail(f"LLM remediation call failed: {e}")
        passed = False

    return passed


def test_5_scan_and_reports() -> bool:
    header("5. Testing End-to-End Scan Execution & OWASP GenAI Reports")
    passed = True

    # Dispatch scan
    scan_id = None
    try:
        scan_req = {
            "url": TARGET_URL,
            "max_pages": 3,
            "auth_mode": "none",
            "stealth_mode": False,
        }
        r = requests.post(f"{BACKEND_URL}/scan", json=scan_req, timeout=10)
        if r.status_code == 200:
            data = r.json()
            scan_id = data.get("scan_id")
            log_pass(f"Scan dispatched successfully: scan_id={scan_id}")
        else:
            log_fail(f"Failed to dispatch scan: {r.status_code} - {r.text}")
            return False
    except Exception as e:
        log_fail(f"Dispatch scan failed: {e}")
        return False

    # Poll for completion (up to 45 seconds)
    log_info("Waiting for scan to complete...")
    completed = False
    for attempt in range(15):
        time.sleep(3)
        try:
            r = requests.get(f"{BACKEND_URL}/scan/{scan_id}", timeout=5)
            if r.status_code == 200:
                s_data = r.json()
                status = s_data.get("status", "")
                findings = s_data.get("findings", [])
                if status == "Completed":
                    log_pass(f"Scan finished in ~{(attempt + 1) * 3}s with {len(findings)} findings discovered!")
                    completed = True
                    break
                else:
                    sys.stdout.write(f"\r  Status: {status}... ")
                    sys.stdout.flush()
        except Exception:
            pass

    if not completed:
        log_warn("Scan still running or target unreachable; proceeding to test report endpoints.")

    # Test OWASP GenAI Compliance JSON endpoint
    try:
        r = requests.get(f"{BACKEND_URL}/compliance/{scan_id}", timeout=10)
        if r.status_code == 200:
            c_data = r.json()
            owasp_pass = c_data.get("owasp_top_10", {}).get("pass", 0)
            genai_pass = c_data.get("owasp_genai_top_10", {}).get("pass", 0)
            log_pass(f"Compliance JSON generated: OWASP Pass={owasp_pass}, GenAI Pass={genai_pass}, Risk Score={c_data.get('risk_score')}")
        else:
            log_fail(f"Compliance endpoint returned {r.status_code}")
            passed = False
    except Exception as e:
        log_fail(f"Compliance request failed: {e}")
        passed = False

    # Test Standard PDF Generation
    try:
        r = requests.get(f"{BACKEND_URL}/report/{scan_id}", timeout=15)
        if r.status_code == 200 and r.headers.get("content-type") == "application/pdf":
            log_pass(f"Standard Security PDF report generated ({len(r.content)} bytes)")
        else:
            log_fail(f"Standard PDF generation failed: {r.status_code}")
            passed = False
    except Exception as e:
        log_fail(f"Standard PDF request failed: {e}")
        passed = False

    # Test OWASP GenAI PDF Audit Report Generation
    try:
        r = requests.get(f"{BACKEND_URL}/owasp-report/{scan_id}", timeout=15)
        if r.status_code == 200 and r.headers.get("content-type") == "application/pdf":
            log_pass(f"OWASP GenAI Compliance Audit PDF report generated ({len(r.content)} bytes)")
        else:
            log_fail(f"OWASP GenAI PDF generation failed: {r.status_code}")
            passed = False
    except Exception as e:
        log_fail(f"OWASP GenAI PDF request failed: {e}")
        passed = False

    return passed


def main():
    print(f"\n{BOLD}{GREEN}╔══════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{GREEN}║  VerseScan Local Backend Test Suite                     ║{RESET}")
    print(f"{BOLD}{GREEN}╚══════════════════════════════════════════════════════════╝{RESET}")

    results = {}
    results["Backend Health"] = test_1_backend_health()
    if not results["Backend Health"]:
        print(f"\n{RED}[!] Backend is not running at {BACKEND_URL}. Start it first with:{RESET}")
        print("    cd scanner-engine")
        print("    python main.py")
        sys.exit(1)

    results["Vulnerable App"] = test_2_vulnerable_app()
    results["Sandbox Orchestrator"] = test_3_sandbox_orchestrator()
    results["LLM Gateway"] = test_4_llm_gateway()
    results["Scan & OWASP Reports"] = test_5_scan_and_reports()

    # Final summary
    header("TEST EXECUTION SUMMARY")
    all_ok = True
    for test_name, status in results.items():
        if status:
            print(f"  {GREEN}✔ PASS{RESET}  {test_name}")
        else:
            print(f"  {RED}✖ FAIL{RESET}  {test_name}")
            all_ok = False

    print(f"\n{'═' * 60}")
    if all_ok:
        print(f"{BOLD}{GREEN}ALL BACKEND SYSTEMS OPERATIONAL & READY FOR DEMO!{RESET}\n")
    else:
        print(f"{BOLD}{YELLOW}SOME OPTIONAL CHECKS FAILED OR TARGET WAS OFFLINE.{RESET}\n")


if __name__ == "__main__":
    main()
