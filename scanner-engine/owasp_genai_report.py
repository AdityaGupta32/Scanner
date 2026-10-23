"""
╔══════════════════════════════════════════════════════════════════════╗
║  VerseScan — OWASP GenAI PDF Audit Report Generator                 ║
║  Generates professional compliance reports mapped to:               ║
║    • OWASP Top 10 (2021)                                            ║
║    • OWASP GenAI Top 10 (2025) — LLM-specific threats               ║
║  Zone: net_blue (defense/monitoring)                                ║
╚══════════════════════════════════════════════════════════════════════╝
"""

from fpdf import FPDF
from datetime import datetime
from typing import List, Dict, Any, Optional

# ── Theme Colors ─────────────────────────────────────────────────────
COLOR_BG       = (255, 255, 255)
COLOR_CARD     = (245, 246, 250)
COLOR_TEXT     = (20, 20, 30)
COLOR_MUTED    = (100, 105, 120)
COLOR_ACCENT   = (15, 90, 200)
COLOR_SEC      = (100, 60, 190)
COLOR_BORDER   = (210, 215, 225)
COLOR_SUCCESS  = (16, 140, 70)
COLOR_DANGER   = (200, 40, 40)
COLOR_WARNING  = (200, 130, 0)
COLOR_PASS     = (16, 140, 70)
COLOR_FAIL     = (200, 40, 40)
COLOR_PARTIAL  = (200, 130, 0)
COLOR_NA       = (150, 155, 165)
COLOR_WATERMARK = (235, 237, 242)

# ── OWASP Definitions ───────────────────────────────────────────────

OWASP_TOP_10 = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "description": "Restrictions on what authenticated users are allowed to do are often not properly enforced.",
        "cwe_map": ["CWE-200", "CWE-284", "CWE-285", "CWE-639", "CWE-862"],
        "vuln_keywords": ["bola", "idor", "broken access", "bac", "authorization", "privilege"],
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "description": "Failures related to cryptography that often lead to sensitive data exposure.",
        "cwe_map": ["CWE-259", "CWE-327", "CWE-328", "CWE-330"],
        "vuln_keywords": ["crypto", "ssl", "tls", "certificate", "encryption", "hash", "jwt"],
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "description": "User-supplied data is not validated, filtered, or sanitized by the application.",
        "cwe_map": ["CWE-79", "CWE-89", "CWE-78", "CWE-77", "CWE-94"],
        "vuln_keywords": ["sqli", "sql injection", "xss", "cross-site scripting", "rce", "command injection", "ssti", "csti", "injection", "lfi", "path traversal"],
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "description": "Risks related to design and architectural flaws.",
        "cwe_map": ["CWE-209", "CWE-256", "CWE-501", "CWE-522"],
        "vuln_keywords": ["design", "architecture", "logic", "business logic"],
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "description": "Missing appropriate security hardening across any part of the application stack.",
        "cwe_map": ["CWE-16", "CWE-2", "CWE-388"],
        "vuln_keywords": ["misconfiguration", "cors", "headers", "cookie", "debug", "default", "config", "security header", "x-frame", "csp"],
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "description": "Using components with known vulnerabilities.",
        "cwe_map": ["CWE-1104"],
        "vuln_keywords": ["outdated", "component", "library", "dependency", "version"],
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "description": "Functions related to authentication and session management are often implemented incorrectly.",
        "cwe_map": ["CWE-287", "CWE-384", "CWE-613"],
        "vuln_keywords": ["authentication", "session", "login", "credential", "brute force", "weak password"],
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations.",
        "cwe_map": ["CWE-345", "CWE-353", "CWE-426", "CWE-494"],
        "vuln_keywords": ["integrity", "deserialization", "ci/cd", "pipeline"],
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, detection, monitoring, and active response.",
        "cwe_map": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "vuln_keywords": ["logging", "monitoring", "audit", "log"],
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "SSRF flaws when a web application fetches a remote resource without validating the URL.",
        "cwe_map": ["CWE-918"],
        "vuln_keywords": ["ssrf", "server-side request"],
    },
}

OWASP_GENAI_TOP_10 = {
    "LLM01": {
        "id": "LLM01",
        "name": "Prompt Injection",
        "description": "Manipulating LLMs through crafted inputs to cause unintended actions, bypassing safety measures or generating harmful content.",
        "risk_level": "Critical",
        "mitigations": [
            "Input sanitization and validation before LLM processing",
            "Privilege separation between LLM and system actions",
            "Human-in-the-loop for sensitive operations",
            "Prompt structure enforcement with delimiters",
        ],
        "vuln_keywords": ["ssti", "csti", "template injection", "injection", "xss"],
    },
    "LLM02": {
        "id": "LLM02",
        "name": "Insecure Output Handling",
        "description": "Insufficient validation of LLM outputs leading to downstream security issues including XSS, CSRF, SSRF, or code execution.",
        "risk_level": "High",
        "mitigations": [
            "Treat LLM output as untrusted user input",
            "Apply output encoding and sanitization",
            "Validate LLM responses before rendering",
        ],
        "vuln_keywords": ["xss", "cross-site scripting", "output", "reflection", "rce"],
    },
    "LLM03": {
        "id": "LLM03",
        "name": "Training Data Poisoning",
        "description": "Manipulation of training data to introduce vulnerabilities, backdoors, or biases into the model.",
        "risk_level": "High",
        "mitigations": [
            "Validate and curate training data sources",
            "Implement data integrity verification",
            "Regular model auditing and testing",
        ],
        "vuln_keywords": ["data", "training", "poisoning"],
    },
    "LLM04": {
        "id": "LLM04",
        "name": "Model Denial of Service",
        "description": "Attackers cause resource-heavy operations on LLMs, leading to service degradation or high costs.",
        "risk_level": "Medium",
        "mitigations": [
            "Rate limiting on LLM API endpoints",
            "Input length restrictions",
            "Resource monitoring and auto-scaling limits",
            "Request timeout enforcement",
        ],
        "vuln_keywords": ["dos", "denial of service", "rate limit", "resource"],
    },
    "LLM05": {
        "id": "LLM05",
        "name": "Supply Chain Vulnerabilities",
        "description": "Dependency on vulnerable third-party components, models, or data sources.",
        "risk_level": "Medium",
        "mitigations": [
            "Vet third-party model providers",
            "Use model signing and verification",
            "Regular dependency auditing",
        ],
        "vuln_keywords": ["supply chain", "dependency", "component", "outdated"],
    },
    "LLM06": {
        "id": "LLM06",
        "name": "Sensitive Information Disclosure",
        "description": "LLMs may inadvertently reveal sensitive information through their responses.",
        "risk_level": "High",
        "mitigations": [
            "Data sanitization in training and fine-tuning",
            "PII detection and redaction in outputs",
            "Access controls on sensitive data",
        ],
        "vuln_keywords": ["sensitive", "disclosure", "exposure", "pii", "credential", "api key", "secret", "lfi"],
    },
    "LLM07": {
        "id": "LLM07",
        "name": "Insecure Plugin Design",
        "description": "LLM plugins may have insecure input handling, insufficient access controls.",
        "risk_level": "High",
        "mitigations": [
            "Parameterized plugin inputs",
            "Strict access control on plugin actions",
            "Input validation and sanitization",
        ],
        "vuln_keywords": ["plugin", "extension", "api", "integration"],
    },
    "LLM08": {
        "id": "LLM08",
        "name": "Excessive Agency",
        "description": "LLM-based systems may take actions that lead to unintended consequences due to excessive permissions.",
        "risk_level": "Medium",
        "mitigations": [
            "Principle of least privilege for LLM actions",
            "Human approval for high-impact operations",
            "Action logging and audit trails",
        ],
        "vuln_keywords": ["privilege", "escalation", "agency", "permission", "authorization"],
    },
    "LLM09": {
        "id": "LLM09",
        "name": "Overreliance",
        "description": "Blindly trusting LLM outputs without verification can lead to security vulnerabilities.",
        "risk_level": "Medium",
        "mitigations": [
            "Human review of LLM-generated security decisions",
            "Cross-validation with multiple sources",
            "Confidence scoring and uncertainty flags",
        ],
        "vuln_keywords": ["trust", "validation", "verification"],
    },
    "LLM10": {
        "id": "LLM10",
        "name": "Model Theft",
        "description": "Unauthorized access to or extraction of proprietary LLM models.",
        "risk_level": "Medium",
        "mitigations": [
            "Network segmentation for model endpoints",
            "API authentication and rate limiting",
            "Model watermarking",
        ],
        "vuln_keywords": ["theft", "exfiltration", "unauthorized access"],
    },
}


# ══════════════════════════════════════════════════════════════════════
#  OWASP Mapper — Maps findings to OWASP categories
# ══════════════════════════════════════════════════════════════════════

class OWASPMapper:
    """Maps vulnerability findings to OWASP Top 10 and GenAI Top 10 categories."""

    @staticmethod
    def map_finding_to_owasp(finding: dict) -> List[str]:
        """Map a single finding to OWASP Top 10 category IDs."""
        matched = []
        name = (finding.get("name", "") or "").lower()
        cwe = (finding.get("cwe", "") or "").upper()
        desc = (finding.get("description", "") or "").lower()
        search_text = f"{name} {desc}"

        for cat_id, cat_info in OWASP_TOP_10.items():
            # Check CWE mapping
            if cwe and any(c.upper() in cwe for c in cat_info["cwe_map"]):
                matched.append(cat_id)
                continue
            # Check keyword matching
            if any(kw in search_text for kw in cat_info["vuln_keywords"]):
                matched.append(cat_id)

        return matched if matched else ["A04"]  # Default to Insecure Design

    @staticmethod
    def map_finding_to_genai(finding: dict) -> List[str]:
        """Map a single finding to OWASP GenAI Top 10 category IDs."""
        matched = []
        name = (finding.get("name", "") or "").lower()
        desc = (finding.get("description", "") or "").lower()
        search_text = f"{name} {desc}"

        for cat_id, cat_info in OWASP_GENAI_TOP_10.items():
            if any(kw in search_text for kw in cat_info["vuln_keywords"]):
                matched.append(cat_id)

        return matched

    @staticmethod
    def compute_owasp_compliance(findings: List[dict]) -> Dict[str, dict]:
        """Compute OWASP Top 10 compliance status from findings."""
        compliance = {}
        for cat_id, cat_info in OWASP_TOP_10.items():
            compliance[cat_id] = {
                "id": cat_info["id"],
                "name": cat_info["name"],
                "status": "PASS",
                "findings_count": 0,
                "critical_high_count": 0,
                "findings": [],
            }

        for finding in findings:
            mapped = OWASPMapper.map_finding_to_owasp(finding)
            severity = (finding.get("severity", "") or "").lower()
            for cat_id in mapped:
                if cat_id in compliance:
                    compliance[cat_id]["findings_count"] += 1
                    compliance[cat_id]["findings"].append(finding.get("name", "Unknown"))
                    if severity in ("critical", "high"):
                        compliance[cat_id]["critical_high_count"] += 1
                        compliance[cat_id]["status"] = "FAIL"
                    elif severity == "medium" and compliance[cat_id]["status"] == "PASS":
                        compliance[cat_id]["status"] = "PARTIAL"

        return compliance

    @staticmethod
    def compute_genai_compliance(findings: List[dict]) -> Dict[str, dict]:
        """Compute OWASP GenAI Top 10 compliance status from findings."""
        compliance = {}
        for cat_id, cat_info in OWASP_GENAI_TOP_10.items():
            compliance[cat_id] = {
                "id": cat_info["id"],
                "name": cat_info["name"],
                "risk_level": cat_info["risk_level"],
                "status": "PASS",
                "findings_count": 0,
                "findings": [],
                "mitigations": cat_info["mitigations"],
            }

        for finding in findings:
            mapped = OWASPMapper.map_finding_to_genai(finding)
            severity = (finding.get("severity", "") or "").lower()
            for cat_id in mapped:
                if cat_id in compliance:
                    compliance[cat_id]["findings_count"] += 1
                    compliance[cat_id]["findings"].append(finding.get("name", "Unknown"))
                    if severity in ("critical", "high"):
                        compliance[cat_id]["status"] = "FAIL"
                    elif severity == "medium" and compliance[cat_id]["status"] == "PASS":
                        compliance[cat_id]["status"] = "PARTIAL"

        return compliance


# ══════════════════════════════════════════════════════════════════════
#  OWASP GenAI PDF Report
# ══════════════════════════════════════════════════════════════════════

class OWASPGenAIReport(FPDF):
    """Professional OWASP GenAI Compliance Audit PDF Report."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)

    def sanitize(self, text):
        if text is None:
            return ""
        text = str(text).replace('—', '-').replace('–', '-').replace('•', '*').replace('“', '"').replace('”', '"').replace('‘', "'").replace('’', "'")
        return text.encode('latin-1', 'replace').decode('latin-1')

    def cell(self, w, h=0, txt='', border=0, ln=0, align='', fill=False, link=''):
        if isinstance(txt, str):
            txt = self.sanitize(txt)
        return super().cell(w, h, txt, border, ln, align, fill, link)

    def multi_cell(self, w, h, txt='', border=0, align='J', fill=False):
        if isinstance(txt, str):
            txt = self.sanitize(txt)
        return super().multi_cell(w, h, txt, border, align, fill)

    # ── Header / Footer ──────────────────────────────────────────────
    def header(self):
        self.set_fill_color(*COLOR_BG)
        self.rect(0, 0, 210, 297, 'F')

        if self.page_no() == 1:
            self._draw_watermark()
            return

        self._draw_watermark()

        self.set_fill_color(*COLOR_BG)
        self.rect(0, 0, 210, 16, 'F')
        self.set_fill_color(*COLOR_SEC)
        self.rect(0, 16, 210, 0.6, 'F')

        self.set_font('Arial', 'B', 10)
        self.set_text_color(*COLOR_SEC)
        self.set_xy(10, 3)
        self.cell(0, 10, 'OWASP GENAI COMPLIANCE AUDIT', 0, 0, 'L')

        self.set_font('Arial', '', 8)
        self.set_text_color(*COLOR_MUTED)
        self.cell(0, 10, 'VERSE SCAN', 0, 0, 'R')

        self.set_y(22)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-14)
        self.set_fill_color(*COLOR_BORDER)
        self.rect(10, 282, 190, 0.3, 'F')
        self.set_font('Arial', '', 7)
        self.set_text_color(*COLOR_MUTED)
        self.cell(0, 10, f'OWASP GenAI Audit Report  |  Page {self.page_no()}  |  Confidential', 0, 0, 'C')

    def _draw_watermark(self):
        self.set_font('Arial', 'B', 46)
        self.set_text_color(*COLOR_WATERMARK)
        self.rotate(35, 105, 148)
        self.set_xy(20, 130)
        self.cell(0, 20, 'OWASP AUDIT', 0, 0, 'C')
        self.rotate(0)

    # ── Drawing Helpers ──────────────────────────────────────────────
    def _ensure_space(self, needed):
        if self.get_y() + needed > 270:
            self.add_page()

    def _draw_section_title(self, number, title):
        self._ensure_space(22)
        self.ln(6)
        self.set_font('Arial', 'B', 14)
        self.set_text_color(*COLOR_SEC)
        self.cell(0, 10, self.sanitize(f"{number}.  {title}"), 0, 1, 'L')
        self.set_fill_color(*COLOR_SEC)
        self.rect(10, self.get_y(), 50, 0.7, 'F')
        self.set_fill_color(*COLOR_BORDER)
        self.rect(60, self.get_y(), 140, 0.3, 'F')
        self.ln(6)

    def _draw_card(self, x, y, w, h):
        self.set_fill_color(*COLOR_CARD)
        self.rect(x, y, w, h, 'F')
        self.set_draw_color(*COLOR_BORDER)
        self.rect(x, y, w, h, 'D')

    def _status_color(self, status):
        status = status.upper()
        if status == "PASS":
            return COLOR_PASS
        elif status == "FAIL":
            return COLOR_FAIL
        elif status == "PARTIAL":
            return COLOR_PARTIAL
        return COLOR_NA

    # ══════════════════════════════════════════════════════════════════
    #  GENERATE
    # ══════════════════════════════════════════════════════════════════
    def generate(self, scan_data: dict, filename: str = "owasp_genai_report.pdf"):
        findings = scan_data.get("findings", [])
        target = scan_data.get("target", scan_data.get("target_url", "Unknown"))
        risk_score = scan_data.get("risk_score", 0)

        owasp_compliance = OWASPMapper.compute_owasp_compliance(findings)
        genai_compliance = OWASPMapper.compute_genai_compliance(findings)

        # Cover page
        self._generate_cover(target, risk_score, len(findings), owasp_compliance, genai_compliance)

        # Section 1: Executive Summary
        self.add_page()
        self._generate_executive_summary(
            target, findings, risk_score, owasp_compliance, genai_compliance
        )

        # Section 2: OWASP Top 10 Compliance Matrix
        self._generate_owasp_matrix(owasp_compliance)

        # Section 3: OWASP GenAI Top 10 Compliance Matrix
        self.add_page()
        self._generate_genai_matrix(genai_compliance)

        # Section 4: Detailed Findings by OWASP Category
        self.add_page()
        self._generate_categorized_findings(findings, owasp_compliance)

        # Section 5: GenAI Threat Analysis & Mitigations
        self.add_page()
        self._generate_genai_mitigations(genai_compliance)

        # Section 6: Compliance Scorecard
        self.add_page()
        self._generate_scorecard(owasp_compliance, genai_compliance)

        # Section 7: Remediation Roadmap
        self._generate_remediation_roadmap(findings, owasp_compliance, genai_compliance)

        self.output(filename)
        return filename

    # ── Cover Page ───────────────────────────────────────────────────
    def _generate_cover(self, target, risk_score, total_findings, owasp, genai):
        self.add_page()

        # Top gradient bar
        self.set_fill_color(*COLOR_SEC)
        self.rect(0, 0, 210, 4, 'F')

        self.set_y(45)
        self.set_font('Arial', 'B', 14)
        self.set_text_color(*COLOR_SEC)
        self.cell(0, 8, 'OWASP COMPLIANCE', 0, 1, 'C')

        self.set_font('Arial', 'B', 36)
        self.set_text_color(*COLOR_TEXT)
        self.cell(0, 18, 'AUDIT REPORT', 0, 1, 'C')

        self.set_fill_color(*COLOR_SEC)
        self.rect(65, self.get_y() + 3, 80, 1.2, 'F')

        self.ln(8)
        self.set_font('Arial', '', 12)
        self.set_text_color(*COLOR_MUTED)
        self.cell(0, 8, 'GenAI Top 10 + OWASP Top 10 Security Assessment', 0, 1, 'C')

        self.ln(16)

        # Target card
        card_y = self.get_y()
        self._draw_card(25, card_y, 160, 30)
        self.set_xy(25, card_y + 5)
        self.set_font('Arial', '', 9)
        self.set_text_color(*COLOR_MUTED)
        self.cell(160, 6, 'TARGET APPLICATION', 0, 1, 'C')
        self.set_x(25)
        self.set_font('Arial', 'B', 12)
        self.set_text_color(*COLOR_TEXT)
        self.cell(160, 10, self.sanitize(str(target)[:80]), 0, 1, 'C')

        self.ln(18)

        # Stats row
        owasp_pass = sum(1 for c in owasp.values() if c["status"] == "PASS")
        genai_pass = sum(1 for c in genai.values() if c["status"] == "PASS")

        stats_y = self.get_y()
        col_w = 40
        stats = [
            ("RISK SCORE", f"{risk_score}/10", COLOR_DANGER if risk_score >= 7 else COLOR_WARNING if risk_score >= 4 else COLOR_SUCCESS),
            ("FINDINGS", str(total_findings), COLOR_ACCENT),
            ("OWASP T10", f"{owasp_pass}/10", COLOR_SUCCESS if owasp_pass >= 8 else COLOR_WARNING),
            ("GENAI T10", f"{genai_pass}/10", COLOR_SUCCESS if genai_pass >= 8 else COLOR_WARNING),
        ]
        for idx, (label, value, color) in enumerate(stats):
            x = 15 + idx * col_w
            self._draw_card(x, stats_y, col_w - 3, 30)
            self.set_xy(x, stats_y + 5)
            self.set_font('Arial', '', 7)
            self.set_text_color(*COLOR_MUTED)
            self.cell(col_w - 3, 5, label, 0, 2, 'C')
            self.set_font('Arial', 'B', 16)
            self.set_text_color(*color)
            self.cell(col_w - 3, 12, value, 0, 0, 'C')

        # Date
        self.set_y(stats_y + 42)
        self.set_font('Arial', '', 10)
        self.set_text_color(*COLOR_MUTED)
        self.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}", 0, 1, 'C')

        self.set_font('Arial', 'I', 9)
        self.cell(0, 6, 'CONFIDENTIAL — For authorized personnel only', 0, 1, 'C')

        # Bottom bar
        self.set_fill_color(*COLOR_SEC)
        self.rect(0, 293, 210, 4, 'F')

    # ── Executive Summary ────────────────────────────────────────────
    def _generate_executive_summary(self, target, findings, risk_score, owasp, genai):
        self._draw_section_title("1", "Executive Summary")

        owasp_fail = sum(1 for c in owasp.values() if c["status"] == "FAIL")
        genai_fail = sum(1 for c in genai.values() if c["status"] == "FAIL")

        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            if sev in sev_counts:
                sev_counts[sev] += 1

        self.set_font('Arial', '', 9)
        self.set_text_color(*COLOR_TEXT)

        summary_text = (
            f"This OWASP compliance audit was conducted against {str(target)[:60]}. "
            f"The assessment identified {len(findings)} security finding(s) "
            f"({sev_counts['Critical']} Critical, {sev_counts['High']} High, "
            f"{sev_counts['Medium']} Medium, {sev_counts['Low']} Low, {sev_counts['Info']} Informational). "
            f"The overall risk score is {risk_score}/10. "
            f"OWASP Top 10 compliance: {owasp_fail} categories failed. "
            f"OWASP GenAI Top 10 compliance: {genai_fail} categories failed."
        )
        self.multi_cell(0, 5, self.sanitize(summary_text))
        self.ln(8)

    # ── OWASP Top 10 Matrix ──────────────────────────────────────────
    def _generate_owasp_matrix(self, owasp_compliance):
        self._ensure_space(130)
        self._draw_section_title("2", "OWASP Top 10 (2021) Compliance")

        # Table header
        header_y = self.get_y()
        self.set_fill_color(*COLOR_ACCENT)
        self.rect(10, header_y, 190, 9, 'F')
        self.set_xy(10, header_y)
        self.set_font('Arial', 'B', 8)
        self.set_text_color(255, 255, 255)
        self.cell(22, 9, '  ID', 0, 0)
        self.cell(70, 9, 'CATEGORY', 0, 0)
        self.cell(22, 9, 'STATUS', 0, 0, 'C')
        self.cell(22, 9, 'FINDINGS', 0, 0, 'C')
        self.cell(54, 9, 'RISK LEVEL', 0, 1, 'C')

        # Table rows
        for idx, (cat_id, info) in enumerate(owasp_compliance.items()):
            self._ensure_space(10)
            row_y = self.get_y()

            # Alternating row color
            if idx % 2 == 0:
                self.set_fill_color(*COLOR_CARD)
            else:
                self.set_fill_color(*COLOR_BG)
            self.rect(10, row_y, 190, 8, 'F')
            self.set_draw_color(*COLOR_BORDER)
            self.line(10, row_y + 8, 200, row_y + 8)

            self.set_xy(10, row_y)

            # ID
            self.set_font('Arial', 'B', 8)
            self.set_text_color(*COLOR_ACCENT)
            self.cell(22, 8, f"  {info['id']}", 0, 0)

            # Category name
            self.set_font('Arial', '', 8)
            self.set_text_color(*COLOR_TEXT)
            self.cell(70, 8, self.sanitize(info['name'][:35]), 0, 0)

            # Status badge
            status_color = self._status_color(info['status'])
            self.set_fill_color(*status_color)
            badge_x = self.get_x() + 5
            self.rect(badge_x, row_y + 1.5, 12, 5, 'F')
            self.set_font('Arial', 'B', 6)
            self.set_text_color(255, 255, 255)
            self.set_x(badge_x - 5)
            self.cell(22, 8, info['status'], 0, 0, 'C')

            # Findings count
            self.set_text_color(*COLOR_TEXT)
            self.set_font('Arial', '', 8)
            self.cell(22, 8, str(info['findings_count']), 0, 0, 'C')

            # Risk level
            risk = "HIGH" if info['critical_high_count'] > 0 else ("MEDIUM" if info['findings_count'] > 0 else "LOW")
            risk_color = COLOR_DANGER if risk == "HIGH" else (COLOR_WARNING if risk == "MEDIUM" else COLOR_SUCCESS)
            self.set_text_color(*risk_color)
            self.set_font('Arial', 'B', 8)
            self.cell(54, 8, risk, 0, 1, 'C')

        self.ln(6)

    # ── GenAI Top 10 Matrix ──────────────────────────────────────────
    def _generate_genai_matrix(self, genai_compliance):
        self._draw_section_title("3", "OWASP GenAI Top 10 (2025) Compliance")

        # Table header
        header_y = self.get_y()
        self.set_fill_color(*COLOR_SEC)
        self.rect(10, header_y, 190, 9, 'F')
        self.set_xy(10, header_y)
        self.set_font('Arial', 'B', 8)
        self.set_text_color(255, 255, 255)
        self.cell(20, 9, '  ID', 0, 0)
        self.cell(60, 9, 'CATEGORY', 0, 0)
        self.cell(22, 9, 'STATUS', 0, 0, 'C')
        self.cell(22, 9, 'FINDINGS', 0, 0, 'C')
        self.cell(30, 9, 'INHERENT', 0, 0, 'C')
        self.cell(36, 9, 'MITIGATIONS', 0, 1, 'C')

        for idx, (cat_id, info) in enumerate(genai_compliance.items()):
            self._ensure_space(10)
            row_y = self.get_y()

            if idx % 2 == 0:
                self.set_fill_color(*COLOR_CARD)
            else:
                self.set_fill_color(*COLOR_BG)
            self.rect(10, row_y, 190, 8, 'F')
            self.set_draw_color(*COLOR_BORDER)
            self.line(10, row_y + 8, 200, row_y + 8)

            self.set_xy(10, row_y)

            self.set_font('Arial', 'B', 8)
            self.set_text_color(*COLOR_SEC)
            self.cell(20, 8, f"  {info['id']}", 0, 0)

            self.set_font('Arial', '', 7)
            self.set_text_color(*COLOR_TEXT)
            self.cell(60, 8, self.sanitize(info['name'][:30]), 0, 0)

            status_color = self._status_color(info['status'])
            self.set_fill_color(*status_color)
            badge_x = self.get_x() + 5
            self.rect(badge_x, row_y + 1.5, 12, 5, 'F')
            self.set_font('Arial', 'B', 6)
            self.set_text_color(255, 255, 255)
            self.set_x(badge_x - 5)
            self.cell(22, 8, info['status'], 0, 0, 'C')

            self.set_text_color(*COLOR_TEXT)
            self.set_font('Arial', '', 8)
            self.cell(22, 8, str(info['findings_count']), 0, 0, 'C')

            # Inherent risk level
            risk_color_map = {"Critical": COLOR_DANGER, "High": COLOR_FAIL, "Medium": COLOR_WARNING, "Low": COLOR_SUCCESS}
            risk_color = risk_color_map.get(info['risk_level'], COLOR_MUTED)
            self.set_text_color(*risk_color)
            self.set_font('Arial', 'B', 7)
            self.cell(30, 8, info['risk_level'].upper(), 0, 0, 'C')

            self.set_text_color(*COLOR_SUCCESS)
            self.set_font('Arial', '', 7)
            self.cell(36, 8, f"{len(info['mitigations'])} controls", 0, 1, 'C')

        self.ln(6)

    # ── Categorized Findings ─────────────────────────────────────────
    def _generate_categorized_findings(self, findings, owasp_compliance):
        self._draw_section_title("4", "Findings by OWASP Category")

        if not findings:
            self.set_font('Arial', '', 9)
            self.set_text_color(*COLOR_SUCCESS)
            self.cell(0, 8, 'No vulnerabilities detected — all categories PASS.', 0, 1)
            return

        for cat_id, info in owasp_compliance.items():
            if info["findings_count"] == 0:
                continue

            self._ensure_space(25)

            # Category header
            status_color = self._status_color(info["status"])
            self.set_fill_color(*status_color)
            self.rect(10, self.get_y(), 3, 12, 'F')

            self.set_x(17)
            self.set_font('Arial', 'B', 10)
            self.set_text_color(*COLOR_TEXT)
            self.cell(0, 6, self.sanitize(f"{info['id']} — {info['name']}"), 0, 1)
            self.set_x(17)
            self.set_font('Arial', '', 7)
            self.set_text_color(*COLOR_MUTED)
            self.cell(0, 5, f"Status: {info['status']}  |  {info['findings_count']} finding(s)", 0, 1)
            self.ln(2)

            # List matching findings
            cat_findings = [
                f for f in findings
                if cat_id in OWASPMapper.map_finding_to_owasp(f)
            ]

            for f in cat_findings[:5]:  # Limit per category
                self._ensure_space(12)
                sev = f.get("severity", "Info")
                sev_colors = {
                    "Critical": (140, 50, 210), "High": (200, 40, 40),
                    "Medium": (200, 130, 0), "Low": (30, 100, 210), "Info": (100, 115, 135)
                }
                sev_color = sev_colors.get(sev, COLOR_MUTED)

                self.set_x(20)
                self.set_fill_color(*sev_color)
                self.rect(20, self.get_y() + 1, 2, 2, 'F')
                self.set_x(25)
                self.set_font('Arial', 'B', 8)
                self.set_text_color(*sev_color)
                self.cell(0, 5, self.sanitize(f"[{sev}] {f.get('name', 'Unknown')}"), 0, 1)
                url = f.get("url", "")
                if url:
                    self.set_x(25)
                    self.set_font('Arial', '', 7)
                    self.set_text_color(*COLOR_MUTED)
                    url_display = url[:80] + "..." if len(url) > 80 else url
                    self.cell(0, 4, self.sanitize(url_display), 0, 1)

            self.ln(4)

    # ── GenAI Mitigations ────────────────────────────────────────────
    def _generate_genai_mitigations(self, genai_compliance):
        self._draw_section_title("5", "GenAI Threat Analysis & Mitigations")

        for cat_id, info in genai_compliance.items():
            self._ensure_space(40)

            card_y = self.get_y()
            card_h = 8 + len(info["mitigations"]) * 5 + 15
            self._draw_card(10, card_y, 190, min(card_h, 60))

            status_color = self._status_color(info["status"])
            self.set_fill_color(*status_color)
            self.rect(10, card_y, 3, min(card_h, 60), 'F')

            self.set_xy(17, card_y + 3)
            self.set_font('Arial', 'B', 9)
            self.set_text_color(*COLOR_SEC)
            self.cell(0, 6, self.sanitize(f"{info['id']}: {info['name']}"), 0, 0)

            # Status badge
            self.set_font('Arial', 'B', 7)
            self.set_text_color(*status_color)
            self.cell(0, 6, f"  [{info['status']}]", 0, 1)

            # Description
            desc = OWASP_GENAI_TOP_10.get(cat_id, {}).get("description", "")
            if desc:
                self.set_x(17)
                self.set_font('Arial', '', 7)
                self.set_text_color(*COLOR_MUTED)
                self.multi_cell(175, 4, self.sanitize(desc[:180]))

            # Mitigations
            self.set_x(17)
            self.set_font('Arial', 'B', 7)
            self.set_text_color(*COLOR_SUCCESS)
            self.cell(0, 5, 'Recommended Controls:', 0, 1)

            for mit in info["mitigations"][:3]:
                self.set_x(20)
                self.set_font('Arial', '', 7)
                self.set_text_color(*COLOR_TEXT)
                self.cell(0, 4, self.sanitize(f"  * {mit[:80]}"), 0, 1)

            self.set_y(max(self.get_y(), card_y + min(card_h, 60) + 3))
            self.ln(2)

    # ── Scorecard ────────────────────────────────────────────────────
    def _generate_scorecard(self, owasp, genai):
        self._draw_section_title("6", "Compliance Scorecard")

        owasp_pass = sum(1 for c in owasp.values() if c["status"] == "PASS")
        owasp_partial = sum(1 for c in owasp.values() if c["status"] == "PARTIAL")
        owasp_fail = sum(1 for c in owasp.values() if c["status"] == "FAIL")

        genai_pass = sum(1 for c in genai.values() if c["status"] == "PASS")
        genai_partial = sum(1 for c in genai.values() if c["status"] == "PARTIAL")
        genai_fail = sum(1 for c in genai.values() if c["status"] == "FAIL")

        owasp_score = ((owasp_pass * 10 + owasp_partial * 5) / 100) * 100
        genai_score = ((genai_pass * 10 + genai_partial * 5) / 100) * 100
        overall_score = (owasp_score + genai_score) / 2

        # Overall score card
        card_y = self.get_y()
        self._draw_card(10, card_y, 190, 35)

        self.set_xy(15, card_y + 5)
        self.set_font('Arial', 'B', 12)
        self.set_text_color(*COLOR_TEXT)
        self.cell(0, 8, 'Overall Compliance Score', 0, 1)

        bar_y = self.get_y() + 2
        self.set_fill_color(*COLOR_BORDER)
        self.rect(15, bar_y, 160, 10, 'F')

        bar_width = max(overall_score / 100 * 160, 0)
        score_color = COLOR_SUCCESS if overall_score >= 70 else (COLOR_WARNING if overall_score >= 40 else COLOR_DANGER)
        self.set_fill_color(*score_color)
        if bar_width > 0:
            self.rect(15, bar_y, bar_width, 10, 'F')

        self.set_xy(15, bar_y + 1)
        self.set_font('Arial', 'B', 8)
        self.set_text_color(255, 255, 255)
        self.cell(160, 8, f'{overall_score:.0f}%', 0, 0, 'C')

        self.set_y(card_y + 40)

        # Breakdown cards
        self.set_font('Arial', 'B', 10)
        self.set_text_color(*COLOR_TEXT)
        self.cell(0, 8, 'Framework Breakdown', 0, 1)
        self.ln(3)

        frameworks = [
            ("OWASP Top 10", owasp_pass, owasp_partial, owasp_fail, owasp_score, COLOR_ACCENT),
            ("OWASP GenAI Top 10", genai_pass, genai_partial, genai_fail, genai_score, COLOR_SEC),
        ]

        for name, p, par, f, score, color in frameworks:
            self._ensure_space(22)
            row_y = self.get_y()
            self._draw_card(10, row_y, 190, 18)
            self.set_fill_color(*color)
            self.rect(10, row_y, 3, 18, 'F')

            self.set_xy(17, row_y + 2)
            self.set_font('Arial', 'B', 9)
            self.set_text_color(*color)
            self.cell(60, 6, name, 0, 0)

            self.set_font('Arial', '', 8)
            self.set_text_color(*COLOR_SUCCESS)
            self.cell(25, 6, f'PASS: {p}', 0, 0)
            self.set_text_color(*COLOR_WARNING)
            self.cell(30, 6, f'PARTIAL: {par}', 0, 0)
            self.set_text_color(*COLOR_DANGER)
            self.cell(25, 6, f'FAIL: {f}', 0, 0)

            self.set_font('Arial', 'B', 9)
            score_col = COLOR_SUCCESS if score >= 70 else (COLOR_WARNING if score >= 40 else COLOR_DANGER)
            self.set_text_color(*score_col)
            self.cell(0, 6, f'{score:.0f}%', 0, 1, 'R')

            self.set_y(row_y + 20)

        self.ln(4)

    # ── Remediation Roadmap ──────────────────────────────────────────
    def _generate_remediation_roadmap(self, findings, owasp, genai):
        self._ensure_space(60)
        self._draw_section_title("7", "Remediation Roadmap")

        # Phase 1: Critical/High
        phases = [
            ("Phase 1 — Immediate (0-7 days)", "Critical and High severity findings",
             [f for f in findings if f.get("severity") in ("Critical", "High")], COLOR_DANGER),
            ("Phase 2 — Short-term (7-30 days)", "Medium severity findings and failed OWASP categories",
             [f for f in findings if f.get("severity") == "Medium"], COLOR_WARNING),
            ("Phase 3 — Long-term (30-90 days)", "Low severity, informational items, and hardening",
             [f for f in findings if f.get("severity") in ("Low", "Info")], COLOR_ACCENT),
        ]

        for phase_name, phase_desc, phase_findings, color in phases:
            self._ensure_space(25)

            self.set_font('Arial', 'B', 10)
            self.set_text_color(*color)
            self.cell(0, 8, self.sanitize(phase_name), 0, 1)
            self.set_font('Arial', '', 8)
            self.set_text_color(*COLOR_MUTED)
            self.cell(0, 5, self.sanitize(f"{phase_desc}  |  {len(phase_findings)} item(s)"), 0, 1)
            self.ln(2)

            for f in phase_findings[:5]:
                self._ensure_space(8)
                self.set_x(14)
                self.set_font('Arial', '', 7)
                self.set_text_color(*COLOR_TEXT)
                name = f.get("name", "Unknown")[:50]
                rem = f.get("remediation", "See OWASP guidelines")[:60]
                self.cell(0, 4, self.sanitize(f"  > {name}: {rem}"), 0, 1)

            self.ln(4)

        # Final note
        self._ensure_space(20)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(*COLOR_MUTED)
        self.multi_cell(0, 4, self.sanitize(
            "This report was generated by VerseScan's OWASP GenAI Audit Engine. "
            "Findings are mapped automatically using CWE and keyword analysis. "
            "For AI-enhanced analysis, connect the LLM Gateway service."
        ))
