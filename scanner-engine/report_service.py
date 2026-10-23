"""
╔══════════════════════════════════════════════════════════════════════╗
║  VerseScan — Report Service (Dedicated Microservice)                ║
║  Handles both standard VerseScan reports and OWASP GenAI audits     ║
║  Zone: net_blue (defense/monitoring)                                ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import os
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from report_generator import PDFReport
from owasp_genai_report import OWASPGenAIReport, OWASPMapper

REPORT_DIR = os.environ.get("REPORT_OUTPUT_DIR", "./reports")
os.makedirs(REPORT_DIR, exist_ok=True)

app = FastAPI(
    title="VerseScan Report Service",
    version="1.0",
    description="PDF report generation — standard security + OWASP GenAI compliance",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Models ───────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    """Request to generate a standard security report."""
    scan_id: str
    target_url: str
    findings: List[Dict[str, Any]] = []
    crawled_urls: List[str] = []
    risk_score: Optional[float] = None
    status: str = "Completed"
    started_at: Optional[str] = None
    completed_at: Optional[str] = None

class OWASPReportRequest(BaseModel):
    """Request to generate an OWASP GenAI compliance audit report."""
    scan_id: str
    target_url: str
    findings: List[Dict[str, Any]] = []
    crawled_urls: List[str] = []
    risk_score: Optional[float] = None
    status: str = "Completed"
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    llm_analysis: Optional[str] = None  # Optional AI-generated analysis text

class ComplianceCheckRequest(BaseModel):
    """Request for a quick compliance check (JSON, no PDF)."""
    findings: List[Dict[str, Any]]
    target_url: str


# ── Routes ───────────────────────────────────────────────────────────

@app.post("/generate")
async def generate_standard_report(request: ReportRequest):
    """Generate a standard VerseScan security assessment PDF report."""
    try:
        scan_data = {
            "id": request.scan_id,
            "target": request.target_url,
            "target_url": request.target_url,
            "findings": request.findings,
            "crawled_urls": request.crawled_urls,
            "status": request.status,
            "started_at": request.started_at,
            "completed_at": request.completed_at,
        }

        if request.risk_score is not None:
            scan_data["risk_score"] = request.risk_score
        else:
            scan_data["risk_score"] = PDFReport.compute_risk_score(request.findings)

        filename = f"report_{request.scan_id}.pdf"
        filepath = os.path.join(REPORT_DIR, filename)

        pdf = PDFReport()
        pdf.generate(scan_data, filepath)

        target_clean = (
            request.target_url
            .replace("http://", "")
            .replace("https://", "")
            .replace("/", "_")
            .replace(":", "")
        )
        date_str = datetime.now().strftime("%Y%m%d")
        readable_name = f"VerseScan_Report_{target_clean}_{date_str}.pdf"

        return FileResponse(
            filepath,
            media_type="application/pdf",
            filename=readable_name,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")


@app.post("/owasp/generate")
async def generate_owasp_report(request: OWASPReportRequest):
    """Generate an OWASP GenAI compliance audit PDF report."""
    try:
        scan_data = {
            "id": request.scan_id,
            "target": request.target_url,
            "target_url": request.target_url,
            "findings": request.findings,
            "crawled_urls": request.crawled_urls,
            "status": request.status,
            "started_at": request.started_at,
            "completed_at": request.completed_at,
        }

        if request.risk_score is not None:
            scan_data["risk_score"] = request.risk_score
        else:
            scan_data["risk_score"] = PDFReport.compute_risk_score(request.findings)

        if request.llm_analysis:
            scan_data["llm_analysis"] = request.llm_analysis

        filename = f"owasp_report_{request.scan_id}.pdf"
        filepath = os.path.join(REPORT_DIR, filename)

        pdf = OWASPGenAIReport()
        pdf.generate(scan_data, filepath)

        target_clean = (
            request.target_url
            .replace("http://", "")
            .replace("https://", "")
            .replace("/", "_")
            .replace(":", "")
        )
        date_str = datetime.now().strftime("%Y%m%d")
        readable_name = f"VerseScan_OWASP_GenAI_Audit_{target_clean}_{date_str}.pdf"

        return FileResponse(
            filepath,
            media_type="application/pdf",
            filename=readable_name,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OWASP report generation failed: {e}")


@app.post("/compliance/check")
async def check_compliance(request: ComplianceCheckRequest):
    """
    Quick OWASP compliance check — returns JSON (no PDF).
    Useful for dashboard integration and real-time compliance monitoring.
    """
    owasp_compliance = OWASPMapper.compute_owasp_compliance(request.findings)
    genai_compliance = OWASPMapper.compute_genai_compliance(request.findings)

    owasp_pass = sum(1 for c in owasp_compliance.values() if c["status"] == "PASS")
    genai_pass = sum(1 for c in genai_compliance.values() if c["status"] == "PASS")

    owasp_score = ((owasp_pass * 10 + sum(5 for c in owasp_compliance.values() if c["status"] == "PARTIAL")) / 100) * 100
    genai_score = ((genai_pass * 10 + sum(5 for c in genai_compliance.values() if c["status"] == "PARTIAL")) / 100) * 100

    return {
        "target": request.target_url,
        "findings_count": len(request.findings),
        "risk_score": PDFReport.compute_risk_score(request.findings),
        "owasp_top_10": {
            "score": round(owasp_score, 1),
            "pass": owasp_pass,
            "partial": sum(1 for c in owasp_compliance.values() if c["status"] == "PARTIAL"),
            "fail": sum(1 for c in owasp_compliance.values() if c["status"] == "FAIL"),
            "categories": {
                cat_id: {
                    "name": info["name"],
                    "status": info["status"],
                    "findings": info["findings_count"],
                }
                for cat_id, info in owasp_compliance.items()
            },
        },
        "owasp_genai_top_10": {
            "score": round(genai_score, 1),
            "pass": genai_pass,
            "partial": sum(1 for c in genai_compliance.values() if c["status"] == "PARTIAL"),
            "fail": sum(1 for c in genai_compliance.values() if c["status"] == "FAIL"),
            "categories": {
                cat_id: {
                    "name": info["name"],
                    "status": info["status"],
                    "findings": info["findings_count"],
                    "risk_level": info["risk_level"],
                }
                for cat_id, info in genai_compliance.items()
            },
        },
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/reports")
async def list_reports():
    """List all generated reports."""
    reports = []
    for f in os.listdir(REPORT_DIR):
        if f.endswith(".pdf"):
            filepath = os.path.join(REPORT_DIR, f)
            stat = os.stat(filepath)
            reports.append({
                "filename": f,
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "type": "owasp" if "owasp" in f else "standard",
            })
    reports.sort(key=lambda r: r["created_at"], reverse=True)
    return {"reports": reports, "total": len(reports)}


@app.get("/report/{filename}")
async def download_report(filename: str):
    """Download a specific report by filename."""
    filepath = os.path.join(REPORT_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(filepath, media_type="application/pdf", filename=filename)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "report-generator",
        "zone": "net_blue",
        "report_dir": REPORT_DIR,
        "report_count": len([f for f in os.listdir(REPORT_DIR) if f.endswith(".pdf")]) if os.path.exists(REPORT_DIR) else 0,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/")
async def root():
    return {
        "service": "VerseScan Report Service",
        "version": "1.0",
        "zone": "net_blue",
        "endpoints": [
            "POST /generate — Standard security report",
            "POST /owasp/generate — OWASP GenAI compliance audit",
            "POST /compliance/check — Quick compliance check (JSON)",
            "GET /reports — List all reports",
            "GET /report/{filename} — Download a report",
        ],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9100)
