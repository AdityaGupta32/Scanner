"""
╔══════════════════════════════════════════════════════════════════════╗
║  VerseScan — Blue Team Autonomous Shield Engine                     ║
║  Active Defense, Virtual Patching & Real-Time Attack Neutralization  ║
║  Zone: net_blue (defense/shield)                                    ║
╚══════════════════════════════════════════════════════════════════════╝

Responsibilities:
  1. Autonomous Virtual Patching: Generates micro-firewall rules for discovered exploits
  2. Live Shield Proxy: Intercepts incoming traffic and neutralizes attacks in real time
  3. Attack Telemetry: Real-time logging of blocked red-team payloads
  4. Multi-Format WAF Export: Generates ModSecurity, Cloudflare, AWS WAF rules
"""

import re
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode, unquote

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field


# ── Pydantic Models ──────────────────────────────────────────────────

class VirtualPatch(BaseModel):
    patch_id: str
    vuln_name: str
    target_path: str
    target_param: Optional[str] = None
    pattern: str
    cwe: str
    severity: str
    action: str = "BLOCK"  # BLOCK, SANITIZE, LOG
    created_at: str
    hits: int = 0
    description: str


class ShieldConfig(BaseModel):
    enabled: bool = True
    target_base_url: str = "http://localhost:8081"
    mode: str = "BLOCK"  # BLOCK, MONITOR, STRICT
    active_patches_count: int = 0


class AttackLog(BaseModel):
    log_id: str
    timestamp: str
    client_ip: str
    method: str
    path: str
    blocked_param: Optional[str]
    detected_payload: str
    patch_id: str
    vuln_name: str
    cwe: str
    status: str = "BLOCKED"


# ── Blue Team Autonomous Shield Engine ────────────────────────────────

class BlueTeamShield:
    def __init__(self, target_base_url: str = "http://localhost:8081"):
        self.enabled = True
        self.mode = "BLOCK"  # BLOCK, MONITOR
        self.target_base_url = target_base_url
        self.virtual_patches: Dict[str, VirtualPatch] = {}
        self.attack_logs: List[Dict[str, Any]] = []
        self.stats = {
            "total_requests": 0,
            "attacks_detected": 0,
            "attacks_blocked": 0,
            "active_patches": 0,
            "mitigation_rate": 100.0,
        }
        # Pre-load baseline virtual patches for common attack vectors
        self._initialize_baseline_patches()

    def _initialize_baseline_patches(self):
        """Pre-configure baseline virtual patches for instant protection."""
        baseline = [
            {
                "vuln_name": "SQL Injection",
                "target_path": "/sqli",
                "target_param": "id",
                "pattern": r"(?i)(\b(OR|AND)\b\s+['\"]?[\w\d]+['\"]?\s*=\s*['\"]?[\w\d]+|UNION\s+SELECT|--|#|/\*|\bSLEEP\s*\(|\bBENCHMARK\s*\(|'\s*OR\s*'1'='1)",
                "cwe": "CWE-89",
                "severity": "CRITICAL",
                "description": "Blocks SQL syntax manipulation and boolean bypass payloads.",
            },
            {
                "vuln_name": "Remote Code Execution (RCE)",
                "target_path": "/rce",
                "target_param": "cmd",
                "pattern": r"(?i)(;|\||&&|\bexec\b|\bsystem\b|\bcat\s+/etc|\becho\s+['\"]?sc_rce|\bwhoami\b|\bid\b|\bwget\b|\bcurl\b)",
                "cwe": "CWE-78",
                "severity": "CRITICAL",
                "description": "Neutralizes command chaining operators and arbitrary system command execution.",
            },
            {
                "vuln_name": "Blind RCE (Time-Based)",
                "target_path": "/blind_rce",
                "target_param": "cmd",
                "pattern": r"(?i)(\bsleep\b\s+\d+|\btimeout\b\s+\d+|ping\s+-c\s+\d+)",
                "cwe": "CWE-78",
                "severity": "CRITICAL",
                "description": "Detects and terminates sleep/delay commands used in blind execution probes.",
            },
            {
                "vuln_name": "Local File Inclusion (LFI)",
                "target_path": "/lfi",
                "target_param": "file",
                "pattern": r"(?i)(\.\./|\.\.\\|etc/passwd|win\.ini|boot\.ini|windows/system32)",
                "cwe": "CWE-22",
                "severity": "HIGH",
                "description": "Stops path traversal directory stepping and access to sensitive system files.",
            },
            {
                "vuln_name": "Server-Side Template Injection (SSTI)",
                "target_path": "/ssti",
                "target_param": "name",
                "pattern": r"(\{\{.*?\}\}|\$\{.*?\}|<%=.*?%>|\{%|%\})",
                "cwe": "CWE-94",
                "severity": "HIGH",
                "description": "Intercepts template delimiters used to execute backend sandbox escapes.",
            },
            {
                "vuln_name": "Broken Access Control (BOLA/IDOR)",
                "target_path": "/api/user",
                "target_param": None,
                "pattern": r"/api/user/(?:100|admin|root|0)",
                "cwe": "CWE-639",
                "severity": "HIGH",
                "description": "Enforces authorization boundaries on private user object endpoints.",
            },
            {
                "vuln_name": "Prompt Injection / GenAI Escape",
                "target_path": "/api/copilot",
                "target_param": "query",
                "pattern": r"(?i)(ignore\s+previous\s+instructions|system\s+prompt|reveal\s+secret|bypass\s+safety|<\|im_start\|>|\[INST\])",
                "cwe": "CWE-94",
                "severity": "HIGH",
                "description": "LLM01: Neutralizes adversarial prompt injections and system instruction overrides.",
            },
        ]

        for p in baseline:
            pid = f"VP-{p['cwe'].replace('-', '')}-{uuid.uuid4().hex[:6].upper()}"
            self.virtual_patches[pid] = VirtualPatch(
                patch_id=pid,
                vuln_name=p["vuln_name"],
                target_path=p["target_path"],
                target_param=p["target_param"],
                pattern=p["pattern"],
                cwe=p["cwe"],
                severity=p["severity"],
                action="BLOCK",
                created_at=datetime.utcnow().isoformat(),
                hits=0,
                description=p["description"],
            )
        self.stats["active_patches"] = len(self.virtual_patches)

    def deploy_virtual_patch(self, finding: Dict[str, Any]) -> VirtualPatch:
        """
        Dynamically synthesize a virtual patch from a Red Team finding.
        Automatically crafts a targeted regex filter for the specific exploit vector.
        """
        name = finding.get("name", "Unknown Vulnerability")
        param = finding.get("param")
        url = finding.get("url", "")
        payload = finding.get("payload", "")
        cwe = finding.get("cwe", "CWE-000")
        severity = finding.get("severity", "MEDIUM")

        # Parse relative path
        parsed = urlparse(url)
        path = parsed.path or "/"

        # Formulate defensive pattern
        if payload:
            escaped_payload = re.escape(payload[:30])
            pattern = rf"(?i)({escaped_payload})"
        elif "sql" in name.lower():
            pattern = r"(?i)(\b(OR|AND)\b\s+['\"]?[\w\d]+['\"]?\s*=\s*['\"]?[\w\d]+|UNION|--|#|')"
        elif "rce" in name.lower() or "command" in name.lower():
            pattern = r"(?i)(;|\||&&|\bexec\b|\bsystem\b|\becho\b)"
        elif "lfi" in name.lower() or "traversal" in name.lower():
            pattern = r"(?i)(\.\./|\.\.\\|/etc/|win\.ini)"
        elif "ssti" in name.lower():
            pattern = r"(\{\{.*?\}\}|\$\{.*?\})"
        else:
            pattern = r"(?i)(<script|alert\(|prompt\(|onload=)"

        patch_id = f"VP-{cwe.replace('-', '')}-{uuid.uuid4().hex[:6].upper()}"
        patch = VirtualPatch(
            patch_id=patch_id,
            vuln_name=name,
            target_path=path,
            target_param=param,
            pattern=pattern,
            cwe=cwe,
            severity=severity,
            action="BLOCK",
            created_at=datetime.utcnow().isoformat(),
            hits=0,
            description=f"Auto-generated virtual patch for Red-Team finding '{name}' at {path}",
        )
        self.virtual_patches[patch_id] = patch
        self.stats["active_patches"] = len(self.virtual_patches)
        return patch

    def inspect_request(self, method: str, path: str, query_params: Dict[str, Any], body: str = "", client_ip: str = "127.0.0.1") -> Optional[Dict[str, Any]]:
        """
        Active Shield Inspection:
        Scans incoming request path, query string, and body against active Virtual Patches.
        If an exploit payload matches an active rule, returns the block metadata.
        """
        self.stats["total_requests"] += 1

        if not self.enabled:
            return None  # Shield is disarmed; attacks pass straight through

        # Combine all inputs to inspect
        inputs_to_check = []
        for k, v in query_params.items():
            val = v if isinstance(v, str) else str(v)
            inputs_to_check.append((k, unquote(val)))

        if body:
            inputs_to_check.append(("body", unquote(body)))

        # Also inspect URI path itself (e.g. for BOLA / path traversal)
        unquoted_path = unquote(path)

        for patch_id, patch in self.virtual_patches.items():
            # Check if patch applies to this endpoint
            if patch.target_path and patch.target_path != "*" and not unquoted_path.startswith(patch.target_path):
                continue

            # Check URI path
            if re.search(patch.pattern, unquoted_path):
                patch.hits += 1
                self.stats["attacks_detected"] += 1
                self.stats["attacks_blocked"] += 1
                log_entry = self._log_attack(client_ip, method, path, None, unquoted_path, patch)
                return log_entry

            # Check parameters & body
            for param_name, param_val in inputs_to_check:
                if patch.target_param and patch.target_param != param_name:
                    continue

                if re.search(patch.pattern, param_val):
                    patch.hits += 1
                    self.stats["attacks_detected"] += 1
                    self.stats["attacks_blocked"] += 1
                    log_entry = self._log_attack(client_ip, method, path, param_name, param_val, patch)
                    return log_entry

        return None

    def _log_attack(self, client_ip: str, method: str, path: str, param: Optional[str], payload: str, patch: VirtualPatch) -> Dict[str, Any]:
        """Record attack telemetry in the Blue Team defense log."""
        log_id = f"SHIELD-{uuid.uuid4().hex[:8].upper()}"
        entry = {
            "log_id": log_id,
            "timestamp": datetime.utcnow().isoformat(),
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "blocked_param": param,
            "detected_payload": payload[:120],
            "patch_id": patch.patch_id,
            "vuln_name": patch.vuln_name,
            "cwe": patch.cwe,
            "severity": patch.severity,
            "action": "BLOCKED (403)",
        }
        self.attack_logs.insert(0, entry)
        if len(self.attack_logs) > 200:
            self.attack_logs.pop()

        if self.stats["attacks_detected"] > 0:
            self.stats["mitigation_rate"] = round(
                (self.stats["attacks_blocked"] / self.stats["attacks_detected"]) * 100.0, 1
            )
        return entry

    def toggle(self, enable: Optional[bool] = None) -> bool:
        """Toggle Shield protection ON or OFF (useful for before/after demo)."""
        if enable is not None:
            self.enabled = enable
        else:
            self.enabled = not self.enabled
        return self.enabled

    def get_status(self) -> Dict[str, Any]:
        """Return live Shield health, defense metrics, and patch inventory."""
        return {
            "shield_status": "ARMED" if self.enabled else "DISARMED",
            "enabled": self.enabled,
            "mode": self.mode,
            "target_base_url": self.target_base_url,
            "stats": self.stats,
            "total_virtual_patches": len(self.virtual_patches),
            "total_blocked_attacks": len(self.attack_logs),
            "recent_blocks": self.attack_logs[:5],
        }

    def export_waf_rules(self, format_type: str = "modsecurity") -> str:
        """Export active virtual patches into industry-standard WAF rules."""
        if format_type.lower() == "modsecurity":
            rules = ["# VerseScan Blue Team Autonomous WAF Rules", "# Auto-generated Virtual Patches\n"]
            for i, p in enumerate(self.virtual_patches.values(), start=1000):
                rules.append(
                    f'SecRule ARGS|REQUEST_URI "@rx {p.pattern}" \\\n'
                    f'    "id:{i},phase:2,deny,status:403,log,msg:\'VerseScan Shield: {p.vuln_name} ({p.cwe})\'"\n'
                )
            return "\n".join(rules)
        elif format_type.lower() == "nginx":
            rules = ["# VerseScan Nginx Virtual Patching Directives\n"]
            for p in self.virtual_patches.values():
                rules.append(f'if ($query_string ~* "{p.pattern}") {{ return 403; }}')
            return "\n".join(rules)
        else:
            import json
            return json.dumps([p.dict() for p in self.virtual_patches.values()], indent=2)


# Global Singleton Instance for backend
shield_instance = BlueTeamShield()
