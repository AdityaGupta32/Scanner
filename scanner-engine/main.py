import os
import asyncio
import aiohttp
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse
from report_generator import PDFReport
from owasp_genai_report import OWASPGenAIReport, OWASPMapper
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from supabase import create_client, Client

# Import Engine Modules
from spider import Spider
from scanner import VulnerabilityScanner
from dotenv import load_dotenv

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

load_dotenv()

# --- Config ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
SANDBOX_ORCHESTRATOR_URL = os.environ.get("SANDBOX_ORCHESTRATOR_URL")
LLM_SERVICE_URL = os.environ.get("LLM_SERVICE_URL")

try:
    import sandbox_orchestrator as sb_orch
except ImportError:
    sb_orch = None

try:
    import llm_gateway as llm_gw
except ImportError:
    llm_gw = None

supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("[+] Supabase Connected")
else:
    print("[!] Warning: Supabase Credentials missing. Using in-memory storage.")

# In-memory fallback storage
scan_results: Dict[str, Any] = {}

app = FastAPI(title="Verse Scan API", version="2.0")

# CORS - Allow all origins for now
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Models ---
class ScanRequest(BaseModel):
    url: str
    max_pages: int = 10
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    auth_mode: str = "none"
    stealth_mode: bool = False
    user_id: Optional[str] = None
    session_cookies: Optional[List[Dict[str, str]]] = None  # [{name, value}, ...]

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str

# --- Helper Functions ---
def save_finding_to_db(scan_id: str, finding: dict):
    """Save individual finding to Supabase"""
    if not supabase:
        return
    try:
        supabase.table("vulnerabilities").insert({
            "scan_id": scan_id,
            "name": finding.get("name"),
            "severity": finding.get("severity"),
            "url": finding.get("url"),
            "evidence": finding.get("evidence"),
            "param": finding.get("param"),
            "payload": finding.get("payload"),
            "cwe": finding.get("cwe"),
            "description": finding.get("description"),
            "remediation": finding.get("remediation"),
        }).execute()
    except Exception as e:
        print(f"[!] Failed to save finding: {e}")

# --- Core Scan Logic ---
async def run_scan(scan_id: str, target_url: str, max_pages: int, 
                   login_url: str, username: str, password: str, 
                   auth_mode: str, stealth_mode: bool,
                   session_cookies: List[Dict[str, str]] = None):
    """
    Main scan workflow:
    1. Crawl target with Spider
    2. Scan each URL with VulnerabilityScanner
    3. Save findings to DB
    """
    print(f"[INIT] Starting scan {scan_id} for {target_url}")
    
    # Initialize in-memory store
    scan_results[scan_id] = {
        "status": "Running",
        "target_url": target_url,
        "crawled_urls": [],
        "findings": [],
        "started_at": datetime.utcnow().isoformat()
    }
    
    session = None
    try:
        # Update DB status
        if supabase:
            supabase.table("scans").update({
                "status": "Running"
            }).eq("id", scan_id).execute()

        # --- Phase 1: Crawl ---
        print(f"[*] Phase 1: Crawling {target_url}...")
        spider = Spider(
            start_url=target_url, 
            max_pages=max_pages,
            auth_mode=auth_mode,
            login_url=login_url,
            username=username,
            password=password
        )
        crawled_urls, cookies = await spider.crawl()
        
        # Use session_cookies if provided (for cookies auth mode)
        if session_cookies:
            cookies = session_cookies
            print(f"[*] Using {len(cookies)} provided session cookies")
        
        # Initialize Session with Cookies
        cookie_jar = {c['name']: c['value'] for c in cookies}
        session = aiohttp.ClientSession(cookies=cookie_jar)
        
        # Include base URL if not already crawled
        if target_url not in crawled_urls:
            crawled_urls.insert(0, target_url)
        
        crawled_count = len(crawled_urls)
        print(f"[*] Crawl Complete. Found {crawled_count} URLs.")
        
        scan_results[scan_id]["crawled_urls"] = crawled_urls
        
        if supabase:
            supabase.table("scans").update({
                "crawled_count": crawled_count
            }).eq("id", scan_id).execute()

        # --- Phase 2: Scan ---
        print(f"[*] Phase 2: Scanning {crawled_count} URLs...")
        scanner = VulnerabilityScanner(
            scan_id=scan_id, 
            supabase_client=supabase, 
            stealth_mode=stealth_mode
        )
        
        # Scan each crawled URL
        for i, url in enumerate(crawled_urls):
            if not url.startswith("http"):
                continue
            print(f"[*] Scanning ({i+1}/{crawled_count}): {url}")
            try:
                await scanner.scan_url(url, session)
            except Exception as e:
                print(f"[!] Error scanning {url}: {e}")
            
            # Update findings in real-time (in-memory)
            scan_results[scan_id]["findings"] = scanner.findings

        # --- Phase 3: Complete ---
        vulnerability_count = len(scanner.findings)
        print(f"[SUCCESS] Scan completed. Found {vulnerability_count} vulnerabilities.")

        scan_results[scan_id]["status"] = "Completed"
        scan_results[scan_id]["vulnerability_count"] = vulnerability_count
        scan_results[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        
        if supabase:
            supabase.table("scans").update({
                "status": "Completed",
                "vulnerability_count": vulnerability_count,
                "completed_at": datetime.utcnow().isoformat()
            }).eq("id", scan_id).execute()

    except Exception as e:
        print(f"[ERROR] Scan Failed: {e}")
        import traceback
        traceback.print_exc()
        
        scan_results[scan_id]["status"] = "Error"
        scan_results[scan_id]["error"] = str(e)
        
        if supabase:
            supabase.table("scans").update({
                "status": "Error"
            }).eq("id", scan_id).execute()
    
    finally:
        if session:
            await session.close()

# --- API Routes ---

@app.post("/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan"""
    try:
        scan_id = None
        
        if supabase:
            # Insert into DB
            scan_data = {
                "target_url": request.url,
                "status": "Pending",
                "user_id": request.user_id 
            }
            res = supabase.table("scans").insert(scan_data).execute()
            scan_id = res.data[0]['id']
        else:
            # Generate UUID for in-memory
            import uuid
            scan_id = str(uuid.uuid4())
            scan_results[scan_id] = {
                "id": scan_id,
                "target_url": request.url,
                "status": "Pending",
                "user_id": request.user_id,
                "created_at": datetime.utcnow().isoformat()
            }
        
        # Start background scan
        background_tasks.add_task(
            run_scan, 
            scan_id, 
            request.url, 
            request.max_pages, 
            request.login_url, 
            request.username, 
            request.password, 
            request.auth_mode, 
            request.stealth_mode,
            request.session_cookies
        )
        
        return {"scan_id": scan_id, "status": "Pending", "target": request.url}
    
    except Exception as e:
        import traceback
        print(f"[ERROR] Create scan failed: {e}")
        traceback.print_exc()
        return {"scan_id": "", "status": "Error", "target": request.url}

@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get scan status and results"""
    scan_id = scan_id.strip("<> \t\r\n")
    # Try in-memory first (for real-time updates)
    if scan_id in scan_results:
        data = scan_results[scan_id].copy()
        data["id"] = scan_id
        return data
    
    # Fallback to DB
    if supabase:
        try:
            res = supabase.table("scans").select("*").eq("id", scan_id).single().execute()
            data = res.data
            
            # Get vulnerabilities
            vulns_res = supabase.table("vulnerabilities").select("*").eq("scan_id", scan_id).execute()
            data['findings'] = vulns_res.data
            data['crawled_urls'] = []  # Not stored in DB
            
            return data
        except Exception as e:
            print(f"[!] Get scan error: {e}")
    
    return {"error": "Scan not found", "id": scan_id}

@app.get("/history")
async def get_history(user_id: Optional[str] = None):
    """Get scan history"""
    if supabase:
        try:
            query = supabase.table("scans").select("*").order("created_at", desc=True).limit(50)
            if user_id:
                query = query.eq("user_id", user_id)
            
            res = query.execute()
            return res.data
        except Exception as e:
            print(f"[!] History error: {e}")
            return []
    
    # Return in-memory scans
    scans = list(scan_results.values())
    if user_id:
        scans = [s for s in scans if s.get("user_id") == user_id]
    return scans

@app.get("/report/{scan_id}")
async def get_report(scan_id: str):
    """Generate and return PDF report"""
    try:
        # 1. Fetch data
        scan_data = await get_scan(scan_id)
        if not scan_data or "error" in scan_data:
            return {"error": "Scan not found"}
        
        # 2. Compute risk score
        findings = scan_data.get('findings', [])
        scan_data['risk_score'] = PDFReport.compute_risk_score(findings)

        # 3. Ensure crawled_urls is populated
        if not scan_data.get('crawled_urls'):
            scan_data['crawled_urls'] = []

        # 4. Set target field for report generator
        if not scan_data.get('target'):
            scan_data['target'] = scan_data.get('target_url', 'Unknown')
        
        # 5. Generate PDF
        pdf = PDFReport()
        filename = f"report_{scan_id}.pdf"
        
        # Clean old report if exists
        try:
            if os.path.exists(filename):
                os.remove(filename)
        except:
            pass
            
        try:
            pdf.generate(scan_data, filename)
        except Exception as e:
            # Fallback PDF on error
            print(f"[ERROR] PDF Generation Failed: {e}")
            import traceback
            traceback.print_exc()
            
            err_pdf = PDFReport()
            err_pdf.add_page()
            err_pdf.set_font('Arial', 'B', 16)
            err_pdf.cell(0, 10, "Report Generation Failed", 0, 1)
            err_pdf.set_font('Arial', '', 12)
            err_pdf.multi_cell(0, 10, f"An error occurred while generating the report:\n{str(e)}\n\nPlease check server logs.")
            err_pdf.output(filename)
        
        # 6. Form readable download name
        target_raw = scan_data.get('target', scan_data.get('target_url', 'target') or 'target')
        target = str(target_raw).replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '')
        date_str = datetime.now().strftime("%Y%m%d")
        readable_name = f"VerseScan_Report_{target}_{date_str}.pdf"
        
        return FileResponse(
            filename, 
            media_type='application/pdf', 
            filename=readable_name
        )
    except Exception as e:
        print(f"[FATAL] Report endpoint failed: {e}")
        return {"error": str(e)}

@app.get("/debug/scans")
async def debug_scans():
    """Debug endpoint to see all in-memory scans"""
    return {
        "in_memory_count": len(scan_results),
        "scans": list(scan_results.keys()),
        "supabase_connected": supabase is not None
    }

@app.get("/ping")
def ping():
    """Ultra-minimal keep-alive endpoint for cron-job.org.
    Returns plain text 'pong' to stay under response size limits."""
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("pong")

@app.get("/owasp-report/{scan_id}")
async def get_owasp_report(scan_id: str):
    """Generate and return OWASP GenAI Compliance Audit PDF report"""
    try:
        scan_data = await get_scan(scan_id)
        if not scan_data or "error" in scan_data:
            return {"error": "Scan not found"}

        findings = scan_data.get('findings', [])
        scan_data['risk_score'] = PDFReport.compute_risk_score(findings)
        if not scan_data.get('crawled_urls'):
            scan_data['crawled_urls'] = []
        if not scan_data.get('target'):
            scan_data['target'] = scan_data.get('target_url', 'Unknown')

        pdf = OWASPGenAIReport()
        filename = f"owasp_report_{scan_id}.pdf"

        try:
            if os.path.exists(filename):
                os.remove(filename)
        except:
            pass

        pdf.generate(scan_data, filename)

        target_raw = scan_data.get('target', 'target')
        target = str(target_raw).replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '')
        date_str = datetime.now().strftime("%Y%m%d")
        readable_name = f"VerseScan_OWASP_Audit_{target}_{date_str}.pdf"

        return FileResponse(
            filename,
            media_type='application/pdf',
            filename=readable_name
        )
    except Exception as e:
        print(f"[FATAL] OWASP report endpoint failed: {e}")
        return {"error": str(e)}


@app.get("/compliance/{scan_id}")
async def get_compliance(scan_id: str):
    """Get OWASP compliance check results (JSON) for a completed scan"""
    scan_data = await get_scan(scan_id)
    if not scan_data or "error" in scan_data:
        return {"error": "Scan not found"}

    findings = scan_data.get('findings', [])
    target = scan_data.get('target_url', scan_data.get('target', 'Unknown'))

    owasp_compliance = OWASPMapper.compute_owasp_compliance(findings)
    genai_compliance = OWASPMapper.compute_genai_compliance(findings)

    owasp_pass = sum(1 for c in owasp_compliance.values() if c["status"] == "PASS")
    genai_pass = sum(1 for c in genai_compliance.values() if c["status"] == "PASS")

    return {
        "scan_id": scan_id,
        "target": target,
        "risk_score": PDFReport.compute_risk_score(findings),
        "findings_count": len(findings),
        "owasp_top_10": {
            "pass": owasp_pass,
            "fail": sum(1 for c in owasp_compliance.values() if c["status"] == "FAIL"),
            "partial": sum(1 for c in owasp_compliance.values() if c["status"] == "PARTIAL"),
            "categories": {
                cat_id: {"name": info["name"], "status": info["status"], "findings": info["findings_count"]}
                for cat_id, info in owasp_compliance.items()
            },
        },
        "owasp_genai_top_10": {
            "pass": genai_pass,
            "fail": sum(1 for c in genai_compliance.values() if c["status"] == "FAIL"),
            "partial": sum(1 for c in genai_compliance.values() if c["status"] == "PARTIAL"),
            "categories": {
                cat_id: {"name": info["name"], "status": info["status"], "findings": info["findings_count"]}
                for cat_id, info in genai_compliance.items()
            },
        },
    }


# ── Sandbox Orchestrator Endpoints (Direct or Proxy) ──────────────────

@app.post("/sandbox/create")
async def create_sandbox(request: Dict[str, Any]):
    """Create a new ephemeral sandbox container (or mock)"""
    if SANDBOX_ORCHESTRATOR_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{SANDBOX_ORCHESTRATOR_URL}/sandbox/create", json=request, timeout=30) as resp:
                    return await resp.json()
        except Exception as e:
            print(f"[!] Sandbox proxy error: {e}")
    if sb_orch:
        req_obj = sb_orch.SandboxCreateRequest(**request)
        return await sb_orch.create_sandbox_container(req_obj)
    raise HTTPException(status_code=503, detail="Sandbox orchestrator not available")

@app.get("/sandbox/list")
async def list_sandboxes():
    """List all active ephemeral sandboxes"""
    if SANDBOX_ORCHESTRATOR_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{SANDBOX_ORCHESTRATOR_URL}/sandbox/list", timeout=10) as resp:
                    return await resp.json()
        except Exception as e:
            print(f"[!] Sandbox proxy error: {e}")
    if sb_orch:
        sandboxes = [
            sb_orch.SandboxResponse(
                sandbox_id=info["sandbox_id"],
                status=info["status"],
                container_name=info["container_name"],
                target_url=info["target_url"],
                internal_ip=info.get("internal_ip"),
                port=info["port"],
                created_at=info["created_at"],
                expires_at=info["expires_at"],
                memory_limit=info["memory_limit"],
                cpu_limit=info["cpu_limit"],
                image=info["image"],
                scan_id=info.get("scan_id"),
            )
            for info in sb_orch.sandbox_registry.values()
        ]
        return sb_orch.SandboxListResponse(
            total=len(sandboxes),
            max_allowed=sb_orch.MAX_SANDBOXES,
            sandboxes=sandboxes,
        )
    raise HTTPException(status_code=503, detail="Sandbox orchestrator not available")

@app.get("/sandbox/{sandbox_id}")
async def get_sandbox(sandbox_id: str):
    """Get status and details of a specific sandbox"""
    if SANDBOX_ORCHESTRATOR_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{SANDBOX_ORCHESTRATOR_URL}/sandbox/{sandbox_id}", timeout=10) as resp:
                    return await resp.json()
        except Exception as e:
            print(f"[!] Sandbox proxy error: {e}")
    if sb_orch:
        info = sb_orch.get_sandbox_status(sandbox_id)
        if not info:
            raise HTTPException(status_code=404, detail="Sandbox not found")
        return info
    raise HTTPException(status_code=503, detail="Sandbox orchestrator not available")

@app.post("/sandbox/{sandbox_id}/destroy")
@app.delete("/sandbox/{sandbox_id}")
async def destroy_sandbox_endpoint(sandbox_id: str, reason: str = "manual"):
    """Explicitly destroy a sandbox container"""
    if SANDBOX_ORCHESTRATOR_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{SANDBOX_ORCHESTRATOR_URL}/sandbox/{sandbox_id}/destroy?reason={reason}", timeout=15) as resp:
                    return await resp.json()
        except Exception as e:
            print(f"[!] Sandbox proxy error: {e}")
    if sb_orch:
        return await sb_orch.destroy_sandbox(sandbox_id, reason=reason)
    raise HTTPException(status_code=503, detail="Sandbox orchestrator not available")

@app.post("/sandbox/{sandbox_id}/extend")
async def extend_sandbox_endpoint(sandbox_id: str, extra_seconds: int = 300):
    """Extend sandbox TTL"""
    if SANDBOX_ORCHESTRATOR_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{SANDBOX_ORCHESTRATOR_URL}/sandbox/{sandbox_id}/extend?extra_seconds={extra_seconds}", timeout=10) as resp:
                    return await resp.json()
        except Exception as e:
            print(f"[!] Sandbox proxy error: {e}")
    if sb_orch:
        if sandbox_id not in sb_orch.sandbox_registry:
            raise HTTPException(status_code=404, detail="Sandbox not found")
        info = sb_orch.sandbox_registry[sandbox_id]
        current_expiry = datetime.fromisoformat(info["expires_at"])
        new_expiry = current_expiry + timedelta(seconds=extra_seconds)
        info["expires_at"] = new_expiry.isoformat()
        return {
            "sandbox_id": sandbox_id,
            "new_expires_at": new_expiry.isoformat(),
            "extended_by_seconds": extra_seconds,
        }
    raise HTTPException(status_code=503, detail="Sandbox orchestrator not available")

@app.post("/sandbox/destroy-all")
async def destroy_all_sandboxes_endpoint():
    """Emergency destroy all sandboxes"""
    if SANDBOX_ORCHESTRATOR_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{SANDBOX_ORCHESTRATOR_URL}/sandbox/destroy-all", timeout=20) as resp:
                    return await resp.json()
        except Exception as e:
            print(f"[!] Sandbox proxy error: {e}")
    if sb_orch:
        destroyed = []
        for sid in list(sb_orch.sandbox_registry.keys()):
            try:
                await sb_orch.destroy_sandbox(sid, reason="destroy_all")
                destroyed.append(sid)
            except Exception as e:
                print(f"[!] Failed to destroy {sid}: {e}")
        return {"message": f"Destroyed {len(destroyed)} sandboxes", "destroyed_ids": destroyed}
    raise HTTPException(status_code=503, detail="Sandbox orchestrator not available")

@app.get("/sandbox/health")
async def sandbox_health():
    """Check sandbox orchestrator health"""
    if SANDBOX_ORCHESTRATOR_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{SANDBOX_ORCHESTRATOR_URL}/health", timeout=5) as resp:
                    return await resp.json()
        except Exception as e:
            pass
    if sb_orch:
        client = sb_orch.get_docker_client()
        docker_connected = client != "mock"
        if docker_connected:
            try:
                client.ping()
            except Exception:
                docker_connected = False
        active_count = sum(1 for s in sb_orch.sandbox_registry.values() if s.get("status") == "running")
        return {
            "status": "healthy",
            "service": "sandbox-orchestrator (in-process)",
            "docker_connected": docker_connected,
            "active_sandboxes": active_count,
            "max_sandboxes": sb_orch.MAX_SANDBOXES,
        }
    return {"status": "unavailable", "message": "Sandbox orchestrator not configured"}


# ── LLM Gateway Endpoints (Direct or Proxy) ──────────────────────────

@app.post("/llm/analyze")
async def llm_analyze(payload: Dict[str, Any]):
    """Analyze a vulnerability using Featherless AI or fallback"""
    if LLM_SERVICE_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{LLM_SERVICE_URL}/analyze/vulnerability", json=payload, timeout=30) as resp:
                    return await resp.json()
        except Exception as e:
            print(f"[!] LLM proxy error: {e}")
    if llm_gw:
        finding = payload.get("finding", {})
        target_url = payload.get("target_url", "")
        context = payload.get("context", "")
        req = llm_gw.VulnAnalysisRequest(finding=finding, target_url=target_url, context=context)
        return await llm_gw.analyze_vulnerability(req)
    raise HTTPException(status_code=503, detail="LLM gateway not available")

@app.post("/llm/remediation")
async def llm_remediation(payload: Dict[str, Any]):
    """Generate code-level remediation patch using AI"""
    if LLM_SERVICE_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{LLM_SERVICE_URL}/analyze/remediation", json=payload, timeout=30) as resp:
                    return await resp.json()
        except Exception as e:
            print(f"[!] LLM proxy error: {e}")
    if llm_gw:
        req = llm_gw.RemediationRequest(
            vulnerability_type=payload.get("vulnerability_type", "SQL Injection"),
            language=payload.get("language", "python"),
            framework=payload.get("framework"),
            finding_details=payload.get("finding_details")
        )
        return await llm_gw.generate_remediation(req)
    raise HTTPException(status_code=503, detail="LLM gateway not available")

@app.post("/llm/threat-model")
async def llm_threat_model(payload: Dict[str, Any]):
    """Generate STRIDE/PASTA threat model from scan findings"""
    if LLM_SERVICE_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(f"{LLM_SERVICE_URL}/analyze/threat-model", json=payload, timeout=45) as resp:
                    return await resp.json()
        except Exception as e:
            print(f"[!] LLM proxy error: {e}")
    if llm_gw:
        req = llm_gw.ThreatModelRequest(
            target_url=payload.get("target_url", ""),
            findings=payload.get("findings", []),
            architecture_notes=payload.get("architecture_notes")
        )
        return await llm_gw.generate_threat_model(req)
    raise HTTPException(status_code=503, detail="LLM gateway not available")

@app.get("/llm/health")
async def llm_health():
    """Check LLM service health"""
    if LLM_SERVICE_URL:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{LLM_SERVICE_URL}/health", timeout=5) as resp:
                    return await resp.json()
        except Exception as e:
            pass
    if llm_gw:
        return {
            "status": "healthy",
            "service": "llm-gateway (in-process)",
            "api_key_configured": bool(llm_gw.FEATHERLESS_API_KEY),
            "model": llm_gw.LLM_MODEL,
        }
    return {"status": "unavailable", "message": "LLM gateway not configured"}


@app.get("/")
def health_check():
    """Health check endpoint"""
    return {
        "status": "online", 
        "version": "2.0",
        "supabase_connected": supabase is not None,
        "timestamp": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
