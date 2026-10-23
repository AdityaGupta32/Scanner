"""
╔══════════════════════════════════════════════════════════════════════╗
║  VerseScan — LLM Gateway Service                                   ║
║  Isolated proxy to Featherless AI / external LLM providers          ║
║  Zone: net_llm (inference) + net_blue (API access)                  ║
╚══════════════════════════════════════════════════════════════════════╝

Responsibilities:
  1. Proxy LLM requests to Featherless AI (or compatible OpenAI API)
  2. Provide specialized security analysis prompts
  3. Rate-limit and cache responses
  4. Sanitize inputs/outputs (prevent prompt injection from scan data)
"""

import os
import time
import hashlib
import json
from datetime import datetime
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ── Configuration ────────────────────────────────────────────────────
FEATHERLESS_API_KEY = os.environ.get("FEATHERLESS_API_KEY", "")
FEATHERLESS_API_URL = os.environ.get("FEATHERLESS_API_URL", "https://api.featherless.ai/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "meta-llama/Meta-Llama-3.1-8B-Instruct")
LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "2048"))
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.3"))
RATE_LIMIT_RPM = 30  # requests per minute

# ── Simple in-memory cache and rate limiter ──────────────────────────
response_cache: Dict[str, dict] = {}
CACHE_TTL = 300  # 5 minutes
request_timestamps: List[float] = []

app = FastAPI(
    title="VerseScan LLM Gateway",
    version="1.0",
    description="Isolated AI inference proxy for security analysis",
)


# ── Models ───────────────────────────────────────────────────────────
class LLMRequest(BaseModel):
    """Generic LLM completion request."""
    prompt: str = Field(..., max_length=8000)
    system_prompt: Optional[str] = Field(
        default="You are a cybersecurity expert analyzing web application vulnerabilities.",
        max_length=2000
    )
    max_tokens: int = Field(default=LLM_MAX_TOKENS, le=4096)
    temperature: float = Field(default=LLM_TEMPERATURE, ge=0.0, le=1.0)

class VulnAnalysisRequest(BaseModel):
    """Request to analyze a vulnerability finding."""
    finding: Dict[str, Any]
    target_url: str
    context: Optional[str] = None

class RemediationRequest(BaseModel):
    """Request to generate remediation code."""
    vulnerability_type: str
    language: str = "python"
    framework: Optional[str] = None
    finding_details: Optional[Dict[str, Any]] = None

class ThreatModelRequest(BaseModel):
    """Request to generate a threat model."""
    target_url: str
    findings: List[Dict[str, Any]]
    architecture_notes: Optional[str] = None

class OWASPAnalysisRequest(BaseModel):
    """Request for OWASP GenAI-specific analysis."""
    findings: List[Dict[str, Any]]
    target_url: str
    scan_metadata: Optional[Dict[str, Any]] = None


# ── Helper Functions ─────────────────────────────────────────────────

def _sanitize_for_prompt(text: str) -> str:
    """Sanitize scan data before including in LLM prompts to prevent prompt injection."""
    if not text:
        return ""
    # Remove potential prompt injection patterns
    sanitized = text.replace("```", "'''")
    sanitized = sanitized.replace("<|", "< |")
    sanitized = sanitized.replace("|>", "| >")
    sanitized = sanitized.replace("[INST]", "[_INST_]")
    sanitized = sanitized.replace("[/INST]", "[/_INST_]")
    # Limit length
    return sanitized[:2000]

def _check_rate_limit():
    """Simple sliding-window rate limiter."""
    global request_timestamps
    now = time.time()
    # Remove timestamps older than 1 minute
    request_timestamps = [t for t in request_timestamps if now - t < 60]
    if len(request_timestamps) >= RATE_LIMIT_RPM:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({RATE_LIMIT_RPM} requests/min)"
        )
    request_timestamps.append(now)

def _get_cache_key(prompt: str, system_prompt: str) -> str:
    """Generate a cache key from the prompt."""
    content = f"{system_prompt}:{prompt}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]

def _check_cache(key: str) -> Optional[str]:
    """Check if a response is cached and still valid."""
    if key in response_cache:
        entry = response_cache[key]
        if time.time() - entry["timestamp"] < CACHE_TTL:
            return entry["response"]
        else:
            del response_cache[key]
    return None

def _store_cache(key: str, response: str):
    """Store a response in cache."""
    response_cache[key] = {
        "response": response,
        "timestamp": time.time(),
    }
    # Evict old entries if cache is too large
    if len(response_cache) > 500:
        oldest_key = min(response_cache, key=lambda k: response_cache[k]["timestamp"])
        del response_cache[oldest_key]


async def _call_llm(prompt: str, system_prompt: str, max_tokens: int, temperature: float) -> str:
    """
    Call the LLM API (Featherless AI / OpenAI-compatible).
    Returns the generated text, or a fallback if API is unavailable.
    """
    _check_rate_limit()

    cache_key = _get_cache_key(prompt, system_prompt)
    cached = _check_cache(cache_key)
    if cached:
        return cached

    if not FEATHERLESS_API_KEY:
        # Fallback: return template-based analysis when no API key
        return _generate_fallback_analysis(prompt)

    try:
        import httpx

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{FEATHERLESS_API_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {FEATHERLESS_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": LLM_MODEL,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
            )

            if response.status_code != 200:
                print(f"[!] LLM API error: {response.status_code} — {response.text[:200]}")
                return _generate_fallback_analysis(prompt)

            data = response.json()
            result = data["choices"][0]["message"]["content"]
            _store_cache(cache_key, result)
            return result

    except ImportError:
        return _generate_fallback_analysis(prompt)
    except Exception as e:
        print(f"[!] LLM call failed: {e}")
        return _generate_fallback_analysis(prompt)


def _generate_fallback_analysis(prompt: str) -> str:
    """Generate template-based analysis when LLM API is unavailable."""
    prompt_lower = prompt.lower()

    if "remediation" in prompt_lower or "fix" in prompt_lower:
        return (
            "## Remediation Guidance\n\n"
            "1. **Input Validation**: Implement strict input validation and sanitization on all user inputs.\n"
            "2. **Parameterized Queries**: Use parameterized/prepared statements for all database queries.\n"
            "3. **Output Encoding**: Apply context-appropriate output encoding to prevent XSS.\n"
            "4. **Access Controls**: Implement proper authentication and authorization checks.\n"
            "5. **Security Headers**: Set CSP, X-Frame-Options, X-Content-Type-Options headers.\n"
            "6. **Dependency Updates**: Keep all dependencies and frameworks up to date.\n\n"
            "*Note: This is a template response. Connect an LLM API key for AI-powered analysis.*"
        )

    if "threat model" in prompt_lower or "owasp" in prompt_lower:
        return (
            "## Threat Model Summary\n\n"
            "### Attack Surface\n"
            "- Web application endpoints exposed to user input\n"
            "- API endpoints with insufficient access controls\n"
            "- Client-side code with potential injection points\n\n"
            "### Key Threats (STRIDE)\n"
            "- **Spoofing**: Session hijacking via insecure cookies\n"
            "- **Tampering**: SQL/Command injection modifying backend data\n"
            "- **Repudiation**: Insufficient logging of security events\n"
            "- **Information Disclosure**: Sensitive data exposure via LFI/error messages\n"
            "- **Denial of Service**: Resource exhaustion via unchecked inputs\n"
            "- **Elevation of Privilege**: Broken access controls, BOLA/IDOR\n\n"
            "*Note: This is a template response. Connect an LLM API key for AI-powered analysis.*"
        )

    return (
        "## Security Analysis\n\n"
        "The identified vulnerabilities indicate potential security weaknesses in the target application. "
        "Each finding should be prioritized by severity and addressed according to security best practices.\n\n"
        "*Note: This is a template response. Connect an LLM API key for AI-powered analysis.*"
    )


# ── Routes ───────────────────────────────────────────────────────────

@app.post("/analyze")
async def analyze_completion(request: LLMRequest):
    """Generic LLM completion endpoint."""
    result = await _call_llm(
        prompt=_sanitize_for_prompt(request.prompt),
        system_prompt=request.system_prompt or "",
        max_tokens=request.max_tokens,
        temperature=request.temperature,
    )
    return {"response": result, "model": LLM_MODEL}


@app.post("/analyze/vulnerability")
async def analyze_vulnerability(request: VulnAnalysisRequest):
    """Analyze a specific vulnerability finding with AI."""
    finding = request.finding
    prompt = (
        f"Analyze this web security vulnerability:\n\n"
        f"Type: {_sanitize_for_prompt(finding.get('name', 'Unknown'))}\n"
        f"Severity: {finding.get('severity', 'Unknown')}\n"
        f"URL: {_sanitize_for_prompt(request.target_url)}\n"
        f"Parameter: {_sanitize_for_prompt(finding.get('param', 'N/A'))}\n"
        f"Payload: {_sanitize_for_prompt(finding.get('payload', 'N/A'))}\n"
        f"Evidence: {_sanitize_for_prompt(finding.get('evidence', 'N/A'))}\n"
        f"CWE: {finding.get('cwe', 'N/A')}\n\n"
        f"Provide:\n"
        f"1. Exploitation risk assessment\n"
        f"2. Real-world impact analysis\n"
        f"3. Step-by-step remediation\n"
        f"4. Code fix example"
    )

    result = await _call_llm(
        prompt=prompt,
        system_prompt=(
            "You are a senior penetration tester and security consultant. "
            "Analyze the vulnerability and provide actionable remediation advice. "
            "Be specific about the risk and provide code examples for fixes."
        ),
        max_tokens=LLM_MAX_TOKENS,
        temperature=0.3,
    )

    return {
        "analysis": result,
        "finding": finding.get("name"),
        "severity": finding.get("severity"),
        "model": LLM_MODEL,
    }


@app.post("/analyze/remediation")
async def generate_remediation(request: RemediationRequest):
    """Generate targeted remediation code for a vulnerability."""
    prompt = (
        f"Generate production-ready remediation code for:\n\n"
        f"Vulnerability: {_sanitize_for_prompt(request.vulnerability_type)}\n"
        f"Language: {request.language}\n"
        f"Framework: {request.framework or 'generic'}\n\n"
        f"Requirements:\n"
        f"- Working, copy-pasteable code\n"
        f"- Follows security best practices\n"
        f"- Include input validation\n"
        f"- Include error handling\n"
        f"- Add security comments explaining each fix"
    )

    result = await _call_llm(
        prompt=prompt,
        system_prompt=(
            "You are a senior security engineer. Generate secure, production-ready code "
            "that fixes the specified vulnerability. The code must be immediately usable."
        ),
        max_tokens=LLM_MAX_TOKENS,
        temperature=0.2,
    )

    return {
        "remediation_code": result,
        "vulnerability_type": request.vulnerability_type,
        "language": request.language,
        "model": LLM_MODEL,
    }


@app.post("/analyze/threat-model")
async def generate_threat_model(request: ThreatModelRequest):
    """Generate a STRIDE threat model from scan findings."""
    findings_summary = []
    for f in request.findings[:20]:  # Limit to 20 findings
        findings_summary.append(
            f"- [{f.get('severity', '?')}] {_sanitize_for_prompt(f.get('name', 'Unknown'))} "
            f"at {_sanitize_for_prompt(f.get('url', 'N/A'))}"
        )

    prompt = (
        f"Generate a comprehensive STRIDE threat model for:\n\n"
        f"Target: {_sanitize_for_prompt(request.target_url)}\n"
        f"Architecture: {_sanitize_for_prompt(request.architecture_notes or 'Web application')}\n\n"
        f"Discovered Vulnerabilities:\n{''.join(findings_summary)}\n\n"
        f"Include:\n"
        f"1. STRIDE analysis (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, EoP)\n"
        f"2. Attack tree with exploitation paths\n"
        f"3. Risk matrix (Impact vs Likelihood)\n"
        f"4. Prioritized remediation roadmap\n"
        f"5. OWASP Top 10 (2023) mapping\n"
        f"6. OWASP GenAI Top 10 mapping (if AI/LLM components detected)"
    )

    result = await _call_llm(
        prompt=prompt,
        system_prompt=(
            "You are a threat modeling expert. Generate a professional STRIDE-based threat model. "
            "Map findings to OWASP Top 10 and OWASP GenAI Top 10 categories. "
            "Provide a clear risk matrix and prioritized remediation plan."
        ),
        max_tokens=4096,
        temperature=0.3,
    )

    return {
        "threat_model": result,
        "target": request.target_url,
        "findings_analyzed": len(request.findings),
        "model": LLM_MODEL,
    }


@app.post("/analyze/owasp-genai")
async def owasp_genai_analysis(request: OWASPAnalysisRequest):
    """
    OWASP GenAI Top 10 compliance analysis.
    Maps scan findings to the OWASP GenAI threat categories.
    """
    findings_text = "\n".join(
        f"- [{f.get('severity')}] {_sanitize_for_prompt(f.get('name', '?'))} "
        f"(CWE: {f.get('cwe', 'N/A')}) at {_sanitize_for_prompt(f.get('url', ''))}"
        for f in request.findings[:25]
    )

    prompt = (
        f"Perform OWASP GenAI Top 10 compliance analysis for:\n\n"
        f"Target: {_sanitize_for_prompt(request.target_url)}\n\n"
        f"Scan Findings:\n{findings_text}\n\n"
        f"Map each finding to the relevant OWASP GenAI Top 10 (2025) categories:\n"
        f"LLM01: Prompt Injection\n"
        f"LLM02: Insecure Output Handling\n"
        f"LLM03: Training Data Poisoning\n"
        f"LLM04: Model Denial of Service\n"
        f"LLM05: Supply Chain Vulnerabilities\n"
        f"LLM06: Sensitive Information Disclosure\n"
        f"LLM07: Insecure Plugin Design\n"
        f"LLM08: Excessive Agency\n"
        f"LLM09: Overreliance\n"
        f"LLM10: Model Theft\n\n"
        f"Also map to standard OWASP Top 10 (2021):\n"
        f"A01: Broken Access Control\n"
        f"A02: Cryptographic Failures\n"
        f"A03: Injection\n"
        f"A04: Insecure Design\n"
        f"A05: Security Misconfiguration\n"
        f"A06: Vulnerable Components\n"
        f"A07: Auth Failures\n"
        f"A08: Data Integrity Failures\n"
        f"A09: Logging Failures\n"
        f"A10: SSRF\n\n"
        f"Provide compliance status (PASS/FAIL/PARTIAL) for each category."
    )

    result = await _call_llm(
        prompt=prompt,
        system_prompt=(
            "You are an OWASP compliance auditor specializing in GenAI security. "
            "Analyze the findings against both OWASP Top 10 and OWASP GenAI Top 10 frameworks. "
            "Provide clear PASS/FAIL/PARTIAL status for each category with evidence citations."
        ),
        max_tokens=4096,
        temperature=0.2,
    )

    return {
        "owasp_genai_analysis": result,
        "target": request.target_url,
        "findings_count": len(request.findings),
        "frameworks": ["OWASP Top 10 (2021)", "OWASP GenAI Top 10 (2025)"],
        "model": LLM_MODEL,
    }


@app.get("/health")
async def health():
    """Health check."""
    return {
        "status": "healthy",
        "service": "llm-gateway",
        "zone": "net_llm",
        "model": LLM_MODEL,
        "api_configured": bool(FEATHERLESS_API_KEY),
        "cache_size": len(response_cache),
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.get("/")
async def root():
    return {
        "service": "VerseScan LLM Gateway",
        "version": "1.0",
        "zone": "net_llm + net_blue",
        "model": LLM_MODEL,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8800)
