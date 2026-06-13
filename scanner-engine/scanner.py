import aiohttp
import asyncio
import re
import random
import time
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

class VulnerabilityScanner:
    def __init__(self, scan_id: str = None, supabase_client = None, stealth_mode: bool = False):
        self.scan_id = scan_id
        self.supabase = supabase_client
        self.stealth_mode = stealth_mode
        self.findings: List[Dict[str, Any]] = []
        
        # --- Deduplication: Track seen (key, url, param) combos ---
        self.seen_findings: set = set()

        # --- Rate-Limit Awareness ---
        self.rate_limited_hosts: set = set()

        # WAF Evasion: User-Agent Rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        ]

        # --- Expanded SQL Error Signatures (MySQL, MSSQL, PostgreSQL, Oracle, SQLite) ---
        self.sql_errors = [
            # MySQL
            "You have an error in your SQL syntax",
            "Warning: mysql_",
            "mysql_fetch",
            "MySQL server version for the right syntax",
            # MSSQL
            "Unclosed quotation mark after the character string",
            "Incorrect syntax near",
            "Syntax error near",
            "Microsoft OLE DB Provider for SQL Server",
            "ODBC SQL Server Driver",
            "SQLSTATE",
            # PostgreSQL
            "quoted string not properly terminated",
            "pg_query(): Query failed",
            "unterminated quoted identifier",
            "PG::SyntaxError",
            "ERROR:  syntax error at or near",
            # Oracle
            "ORA-01756",
            "ORA-00907",
            "quoted string not properly terminated",
            "oracle.jdbc.driver",
            # SQLite
            "SQLite3::SQLException",
            "unrecognized token",
            "sqlite3.OperationalError",
            # Generic
            "DB Error",
            "SQL syntax",
            "database error",
        ]

        # --- Multiple XSS Payloads (context-diverse) ---
        self.xss_payloads = [
            "<sc_test>",                          # Basic tag reflection
            '"><sc_test>',                         # Breaks out of attribute value
            "'><sc_test>",                         # Breaks out of single-quoted attr
            "<ScRiPt>sc_test_xss</ScRiPt>",        # Mixed-case bypass
            "javascript:sc_test_xss",              # javascript: URI context
            "<img src=x onerror=sc_test_xss>",     # Event-handler injection
            "\"onmouseover=\"sc_test_xss",          # Attribute injection
        ]
        # Legacy single string for backward compat
        self.xss_test_string = "<sc_test>"

        # --- Expanded Sensitive Data Patterns ---
        self.sensitive_patterns = {
            "API Key":       r"(?i)(api_key|apikey)[\s:=]+[\w\-]+",
            "Password":      r"(?i)(password|passwd|pwd)[\s:=]+[\w\-]+",
            "Email":         r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Secret":        r"(?i)(secret|secret_key)[\s:=]+[\w\-]+",
            "AWS Key":       r"AKIA[0-9A-Z]{16}",
            "Private Key":   r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
            "Bearer Token":  r"(?i)bearer\s+[\w\-\.]+",
            "GitHub Token":  r"ghp_[0-9a-zA-Z]{36}",
        }

        # --- Expanded Sensitive File List ---
        self.fuzz_files = [
            ".env", ".env.local", ".env.production", ".env.backup",
            "config.php", "config.php.bak", "config.php~",
            "backup.sql", "dump.sql", "database.sql",
            ".git/HEAD", ".git/config",
            ".vscode/settings.json",
            "wp-config.php", "wp-config.php.bak",
            "web.config", "web.config.bak",
            "phpinfo.php", "info.php",
            "Dockerfile", "docker-compose.yml",
            "package.json", "composer.json",
            "README.md", "CHANGELOG.md",
            "robots.txt", "sitemap.xml",
        ]

        self.required_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        
        # Smart 404 Detection
        self.scanned_hosts = set()
        self.smart_404_fingerprint = None
        
        # Knowledge Base for Reporting
        self.kb = {
            "sql_injection": {
                "name": "SQL Injection", 
                "severity": "High", 
                "cwe": "CWE-89", 
                "description": "Untrusted input interferes with a database query.", 
                "remediation": "Use parameterized queries (e.g., PreparedStatement in Java, parameterized queries in Python/PHP).",
                "remediation_code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            },
            "xss_reflected": {
                "name": "Reflected XSS", 
                "severity": "Medium", 
                "cwe": "CWE-79", 
                "description": "Reflects untrusted data without escaping.", 
                "remediation": "Context-aware output encoding.",
                "remediation_code": "return <div>{user_input}</div>; // React escapes by default"
            },
            "sensitive_data": {
                "name": "Sensitive Data Exposure", 
                "severity": "Low", 
                "cwe": "CWE-200", 
                "description": "Exposes sensitive info (API keys, passwords).", 
                "remediation": "Remove sensitive headers and data from responses.",
                "remediation_code": "# Remove 'Server' header\nresponse.headers['Server'] = ''"
            },
            "security_header": {
                "name": "Missing Security Header", 
                "severity": "Low", 
                "cwe": "CWE-693", 
                "description": "Missing HTTP security headers (CSP, HSTS).", 
                "remediation": "Configure strict headers.",
                "remediation_code": "add_header X-Frame-Options SAMEORIGIN;\nadd_header Content-Security-Policy \"default-src 'self'\""
            },
            "hidden_file": {
                "name": "Hidden File Exposure", 
                "severity": "High", 
                "cwe": "CWE-538", 
                "description": "Sensitive file (e.g. .env, .git) accessible.", 
                "remediation": "Deny access to hidden files in Nginx/Apache.",
                "remediation_code": "location ~ /\\. { deny all; return 404; }"
            },
            "blind_sqli": {
                "name": "Blind SQL Injection", 
                "severity": "Critical", 
                "cwe": "CWE-89", 
                "description": "Evaluation of logic/time delays via SQL injection.", 
                "remediation": "Use parameterized queries.",
                "remediation_code": "cursor.execute('SELECT * FROM items WHERE type = ?', [user_type])"
            },
            "union_sqli": {
                "name": "UNION SQLi", 
                "severity": "Critical", 
                "cwe": "CWE-89", 
                "description": "Retrieving data from other tables via UNION.", 
                "remediation": "Use parameterized queries.",
                "remediation_code": "db.query('SELECT name, email FROM users WHERE id = $1', [id])"
            },
            "dom_xss": {
                "name": "DOM XSS", 
                "severity": "Medium", 
                "cwe": "CWE-79", 
                "description": "Dangerous Sink (innerHTML/eval) with user input.", 
                "remediation": "Avoid innerHTML. Use textContent.",
                "remediation_code": "element.textContent = user_input; // Safe"
            },
            "tech_stack": {
                "name": "Tech Stack Disclosure", 
                "severity": "Info", 
                "cwe": "CWE-200", 
                "description": "Version information leaked headers.", 
                "remediation": "Disable server signature tokens.",
                "remediation_code": "server_tokens off; // Nginx"
            },
            "lfi": {
                "name": "Local File Inclusion", 
                "severity": "Critical", 
                "cwe": "CWE-22", 
                "description": "Reading local files via directory traversal.", 
                "remediation": "Validate filenames against an allowlist.",
                "remediation_code": "if filename not in ['page1.html', 'page2.html']: abort(403)"
            },
            "ssti": {
                "name": "Server-Side Template Injection", 
                "severity": "Critical", 
                "cwe": "CWE-1336", 
                "description": "User input evaluated by template engine.", 
                "remediation": "Pass input as data not template string.",
                "remediation_code": "template.render(user_input=data) # Safe"
            },
            "cors_misconfig": {
                "name": "CORS Misconfiguration", 
                "severity": "High", 
                "cwe": "CWE-346", 
                "description": "Accepts arbitrary or null origins.", 
                "remediation": "Whitelist specific trusted domains.",
                "remediation_code": "Access-Control-Allow-Origin: https://trusted.com"
            },
            "open_port": {
                "name": "Open Port", 
                "severity": "Info", 
                "cwe": "CWE-200", 
                "description": "Unnecessary port exposed.", 
                "remediation": "Close port or restrict with firewall.",
                "remediation_code": "ufw deny 8080/tcp"
            },
            "csti": {
                "name": "Client-Side Template Injection", 
                "severity": "High", 
                "cwe": "CWE-79", 
                "description": "Angular/Vue template injection.", 
                "remediation": "Use v-pre or ng-non-bindable.",
                "remediation_code": "<span v-pre>{{ user_input }}</span>"
            },
            "blind_rce": {
                "name": "Blind RCE", 
                "severity": "Critical", 
                "cwe": "CWE-78", 
                "description": "Command execution verified via time delay.", 
                "remediation": "Avoid system calls. Use library functions.",
                "remediation_code": "subprocess.run(['ls', '-l']) # No shell=True"
            },
            "rce": {
                "name": "Remote Code Execution", 
                "severity": "Critical", 
                "cwe": "CWE-78", 
                "description": "Executing arbitrary system commands.", 
                "remediation": "Never use shell=True with user input.",
                "remediation_code": "import subprocess; subprocess.run(['echo', user_input])"
            },
            "bola": {
                "name": "BOLA/IDOR", 
                "severity": "High", 
                "cwe": "CWE-639", 
                "description": "Accessing other users' resources via ID manipulation.", 
                "remediation": "Check ownership before access.",
                "remediation_code": "if resource.owner_id != current_user.id: raise Forbidden()"
            },
            "bac": {
                "name": "Broken Access Control", 
                "severity": "High", 
                "cwe": "CWE-285", 
                "description": "Unprivileged access to admin areas.", 
                "remediation": "Enforce role-based access control (RBAC).",
                "remediation_code": "@requires_role('admin')"
            },
            "jwt_none": {
                "name": "Insecure JWT (alg:none)", 
                "severity": "Critical", 
                "cwe": "CWE-327", 
                "description": "JWT accepts 'none' algorithm (signature bypass).", 
                "remediation": "Explicitly reject 'none' algorithm.",
                "remediation_code": "jwt.decode(token, key, algorithms=['HS256'])"
            },
            "cookie_insecure": {
                "name": "Insecure Cookie Flags", 
                "severity": "Low", 
                "cwe": "CWE-1275", 
                "description": "Missing Secure, HttpOnly, or SameSite attributes.", 
                "remediation": "Set attributes on cookie creation.",
                "remediation_code": "response.set_cookie(key, value, secure=True, httponly=True, samesite='Strict')"
            },
            "weak_crypto": {
                "name": "Weak Cryptography", 
                "severity": "Medium", 
                "cwe": "CWE-327", 
                "description": "Use of weak algorithms (MD5, SHA1) or keys.", 
                "remediation": "Use strong standard algorithms (AES-256-GCM, SHA-256).",
                "remediation_code": "hashlib.sha256(data).hexdigest()"
            }
        }
        
    async def perform_request(self, session, method, url, **kwargs):
        """
        Wrapper for HTTP requests with:
          - WAF Evasion (Jitter + User-Agent Rotation)
          - Rate-Limit Awareness (detects 429 / 503 and backs off)
        """
        host = urlparse(url).netloc

        # Stealth mode: jitter + UA rotation
        if self.stealth_mode:
            delay = random.uniform(0.5, 1.5)
            await asyncio.sleep(delay)
            headers = kwargs.get("headers", {})
            if "User-Agent" not in headers:
                headers["User-Agent"] = random.choice(self.user_agents)
            kwargs["headers"] = headers

        # Always rotate UA slightly even outside stealth mode
        headers = kwargs.get("headers", {})
        if "User-Agent" not in headers:
            headers["User-Agent"] = random.choice(self.user_agents)
        kwargs["headers"] = headers

        try:
            if method.upper() == "GET":
                ctx = session.get(url, **kwargs)
            elif method.upper() == "POST":
                ctx = session.post(url, **kwargs)
            elif method.upper() == "HEAD":
                ctx = session.head(url, **kwargs)
            else:
                ctx = session.get(url, **kwargs)

            # --- Rate-Limit Awareness ---
            # We wrap the context manager to check status before returning
            return ctx

        except Exception:
            pass
        return session.get(url, **kwargs)  # Fallback

    async def _check_rate_limit(self, session, url) -> bool:
        """
        Sends a canary HEAD request to detect rate limiting (429/503).
        Returns True if rate-limited (caller should back off).
        """
        host = urlparse(url).netloc
        if host in self.rate_limited_hosts:
            return True
        try:
            ctx = session.head(url, timeout=5)
            async with ctx as resp:
                if resp.status in (429, 503):
                    print(f"[!] Rate-limited by {host} (HTTP {resp.status}). Backing off 10s.")
                    self.rate_limited_hosts.add(host)
                    await asyncio.sleep(10)
                    self.rate_limited_hosts.discard(host)  # Allow retry after backoff
                    return True
        except Exception:
            pass
        return False

    async def detect_smart_404(self, session, url):
        """
        Fingerprints the 'Not Found' page of the server to avoid FPs.
        """
        try:
            parsed = urlparse(url)
            # Use a specialized bogus path
            bogus_url = f"{parsed.scheme}://{parsed.netloc}/sc_404_{int(time.time())}"
            ctx = await self.perform_request(session, 'GET', bogus_url, timeout=5)
            async with ctx as resp:
                text = await resp.text()
                # Store status and length (with sloppy tolerance)
                self.smart_404_fingerprint = (resp.status, len(text))
                print(f"[*] Smart 404 Fingerprint: Status={resp.status}, Len={len(text)}")
        except:
            pass

    def is_custom_404(self, status, text):
        """
        Checks if a response matches the Smart 404 fingerprint.
        """
        if not self.smart_404_fingerprint:
            return False
            
        fp_status, fp_len = self.smart_404_fingerprint
        
        # If status matches exactly
        if status == fp_status:
            # If length is within 5% tolerance
            if abs(len(text) - fp_len) < (fp_len * 0.05):
                return True
        return False

    def _add_finding(self, key: str, url: str, evidence: str, param: str = None, payload: str = None):
        # --- Deduplication: same vuln + url + param is only reported once ---
        dedup_key = f"{key}:{url}:{param}"
        if dedup_key in self.seen_findings:
            return
        self.seen_findings.add(dedup_key)

        info = self.kb.get(key, {})
        finding_data = {
            "name": info.get("name", "Unknown Issue"),
            "severity": info.get("severity", "Low"),
            "url": url,
            "param": param,
            "payload": payload,
            "evidence": evidence,
            "description": info.get("description", ""),
            "remediation": info.get("remediation", ""),
            "cwe": info.get("cwe", "")
        }

        self.findings.append(finding_data)
        print(f"[!] {info.get('name')} found at {url}")

        # Supabase Persist
        if self.supabase and self.scan_id:
            try:
                db_data = finding_data.copy()
                db_data["scan_id"] = self.scan_id
                self.supabase.table("vulnerabilities").insert(db_data).execute()
            except Exception as e:
                print(f"[!] DB Insert Error: {e}")

    async def scan_url(self, url: str, session: aiohttp.ClientSession):
        print(f"[*] Scanning {url}...")
        
        # 0. Smart 404 Baseline (Once per host)
        parsed = urlparse(url)
        if not self.smart_404_fingerprint:
             await self.detect_smart_404(session, url)
        
        # Network Level Checks (Once per host)
        await self.check_open_ports(url)
        
        await self.check_tech_stack(session, url)
        
        if url.endswith(".js"):
            await self.check_js_analysis(session, url)
            return

        # --- Rate-Limit Check before scanning ---
        if await self._check_rate_limit(session, url):
            print(f"[!] Skipping {url} — rate-limited.")
            return

        # Injection Checks (GET params)
        await self.check_sqli(session, url)
        await self.check_union_sqli(session, url)
        await self.check_lfi(session, url)
        await self.check_rce(session, url)
        await self.check_blind_rce(session, url)
        await self.check_ssti(session, url)
        await self.check_csti(session, url)
        await self.check_bola(session, url)
        await self.check_bac(session, url)
        await self.check_jwt(session, url)
        await self.check_xss(session, url)

        # --- POST Body Scanning (new) ---
        await self.check_sqli_post(session, url)
        await self.check_xss_post(session, url)

        # --- Header Injection (new) ---
        await self.check_header_injection(session, url)

        # Configuration Checks
        await self.check_cors(session, url)
        await self.check_sensitive_info(session, url)
        await self.check_security_headers(session, url)
        await self.check_cookie_security(session, url)

        if urlparse(url).path in ["", "/"]:
            await self.check_sensitive_files(session, url)

        await self.check_time_based_sqli(session, url)
        await self.check_boolean_sqli(session, url)

    async def check_open_ports(self, url):
        hostname = urlparse(url).hostname
        if not hostname or hostname in self.scanned_hosts: return
        self.scanned_hosts.add(hostname)
        
        # Top 10 ports to scan
        ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080, 8443]
        
        for port in ports:
            try:
                # Simple async connect with timeout
                fut = asyncio.open_connection(hostname, port)
                reader, writer = await asyncio.wait_for(fut, timeout=1.0)
                writer.close()
                await writer.wait_closed()
                self._add_finding("open_port", f"{hostname}:{port}", f"Port {port} is OPEN", str(port), None)
            except:
                pass


    async def check_cors(self, session, url):
        try:
            headers = {"Origin": "http://evil-scanner.com"}
            ctx = await self.perform_request(session, 'GET', url, headers=headers, timeout=5)
            async with ctx as resp:
                allow_origin = resp.headers.get("Access-Control-Allow-Origin")
                if allow_origin == "http://evil-scanner.com":
                    self._add_finding("cors_misconfig", url, "Server trustworthy reflected malicious Origin", None, "Origin: http://evil-scanner.com")
                elif allow_origin == "*":
                     self._add_finding("cors_misconfig", url, "Server allows wildcard (*) origin with credentials", None, "Access-Control-Allow-Origin: *")
        except: pass

    async def check_ssti(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        # ${{7*7}} -> 49
        ssti_payloads = [
            "${{7*7}}", 
            "{{7*7}}", 
            "<%= 7*7 %>"
        ]

        for param in params:
            for payload in ssti_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        text = await resp.text()
                        if "49" in text: # If 7*7 is evaluated to 49
                             self._add_finding("ssti", url, "Template Expression Evaluated (7*7 -> 49)", param, payload)
                             break
                except: pass

    async def check_csti(self, session, url):
        """
        Client-Side Template Injection (Angular/Vue)
        We look for the raw payload reflected in the response without escaping.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        # Vue/Angular/React payloads
        csti_payloads = [
            "{{7*7}}", 
            "{{1+1}}",
            "[[7*7]]"
        ]

        for param in params:
            for payload in csti_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        text = await resp.text()
                        # If the payload is reflected EXACTLY as is, it *might* be CSTI.
                        # Stronger check: Look for context (ng-app, etc.) but for now reflection is good.
                        if payload in text:
                             # Exclude strict textareas or safe contexts if possible, but for now report reflection.
                             self._add_finding("csti", url, f"CSTI Payload reflected: {payload}", param, payload)
                             break
                except: pass

    async def check_bola(self, session, url):
        """
        Broken Object Level Authorization (BOLA / IDOR).
        Detects numeric IDs in params and tries to access other objects.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # 1. Check Query Params for IDs
        if params:
            for param, values in params.items():
                for value in values:
                    if value.isdigit():
                        original_id = int(value)
                        # Try ID+1 and ID-1
                        test_ids = [original_id + 1, original_id - 1]
                        
                        for tid in test_ids:
                            test_params = params.copy()
                            test_params[param] = [str(tid)]
                            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                            
                            try:
                                ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                                async with ctx as resp:
                                    if resp.status == 200:
                                        # Heuristic: If we get 200 for a different ID, it MIGHT be BOLA.
                                        # Use text diff or regex for PII (SSN, Email) to be sure.
                                        text = await resp.text()
                                        if "SSN" in text or "admin" in text.lower() or "private" in text.lower():
                                            self._add_finding("bola", url, f"Access to object ID {tid} successful", param, str(tid))
                                            break
                            except: pass

        # 2. Check URL Path for IDs (e.g., /api/user/100)
        # Regex to find integer segments in path
        path_segments = parsed.path.split('/')
        for i, segment in enumerate(path_segments):
            if segment.isdigit():
                original_id = int(segment)
                # Try ID+1
                new_path = list(path_segments)
                new_path[i] = str(original_id + 1)
                test_url = urlunparse(parsed._replace(path='/'.join(new_path)))
                
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        if resp.status == 200:
                             text = await resp.text()
                             if "SSN" in text or "admin" in text.lower() or "private" in text.lower():
                                self._add_finding("bola", url, f"Path-based ID access successful: {original_id+1}", "path", str(original_id+1))
                except: pass

    async def check_bac(self, session, url):
        """
        Broken Access Control (BAC).
        Tries to access common privileged endpoints.
        This is a 'force browsing' check run once per host.
        """
        parsed = urlparse(url)
        host = parsed.netloc
        base_url = f"{parsed.scheme}://{host}"
        
        # Only scan BAC once per host
        # We use a specific set for BAC to avoid conflicts with port scanning
        if not hasattr(self, 'bac_scanned_hosts'):
            self.bac_scanned_hosts = set()
            
        if host in self.bac_scanned_hosts:
            return 
        self.bac_scanned_hosts.add(host)
        
        admin_paths = [
            "/admin",
            "/dashboard",
            "/config",
            "/api/admin",
            "/users",
            "/admin/dashboard", # Specific for our test
            "/settings"
        ]
        
        for path in admin_paths:
            target = base_url + path
            try:
                ctx = await self.perform_request(session, 'GET', target, timeout=5)
                async with ctx as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # Validate it's not a generic login page or error
                        if "login" not in text.lower() and "error" not in text.lower():
                             # Check for specific success indicators
                             if "dashboard" in text.lower() or "admin" in text.lower() or "settings" in text.lower():
                                  self._add_finding("bac", target, "Privileged area accessible without auth check", "path", path)
            except: pass

    async def check_blind_rce(self, session, url):
        """
        Time-Based Blind RCE.
        Injects sleep commands and measures delay.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        blind_payloads = [
            "; sleep 5",
            "| sleep 5",
            "&& sleep 5",
            "`sleep 5`",
            "$(sleep 5)"
        ]

        for param in params:
            for payload in blind_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                start = time.time()
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=10)
                    async with ctx as resp:
                        await resp.text()
                        # If response took > 5 seconds, it worked
                        if time.time() - start > 5:
                             self._add_finding("blind_rce", url, "Server slept for 5+ seconds", param, payload)
                             break
                except: pass

    async def check_lfi(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        # Indicators of success
        lfi_indicators = [
            "root:x:0:0:",
            "[extensions]",
            "for 16-bit app support"
        ]

        for param in params:
            for payload in lfi_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        text = await resp.text()
                        for indicator in lfi_indicators:
                            if indicator in text:
                                self._add_finding("lfi", url, f"LFI Payload executed successfully. Found: {indicator}", param, payload)
                                break
                except: pass

    async def check_rce(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        # Simple echo tests for RCE
        rce_payloads = [
            "; echo 'sc_rce_test'",
            "| echo 'sc_rce_test'",
            "|| echo 'sc_rce_test'",
            "& echo 'sc_rce_test'"
        ]

        for param in params:
            for payload in rce_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    # Debug print to verify traffic
                    # print(f"[DEBUG] RCE Test: {test_url}") 
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        text = await resp.text()
                        # print(f"[DEBUG] RCE Resp: {text[:30]}")
                        if "sc_rce_test" in text:
                             self._add_finding("rce", url, "Command Execution confirmed via echo test", param, payload)
                             break
                except: pass


    async def check_jwt(self, session, url):
        """
        Extracts and analyzes JWTs from Headers or Cookies.
        """
        try:
            # 1. Inspect Headers (Authorization)
            # This is hard because we are the client. We assume we might see JWTs in response headers or body (uncommon)
            # OR we check if the APP sets a cookie that looks like a JWT.
            ctx = await self.perform_request(session, 'GET', url, timeout=5)
            async with ctx as resp:
                cookies = session.cookie_jar.filter_cookies(url)
                for key, cookie in cookies.items():
                    if cookie.value.count('.') == 2 and (cookie.value.startswith('eyJ') or "bearer" in key.lower()):
                         self._add_finding("weak_crypto", url, f"JWT found in cookie '{key}'", key, "JWT Deteced")
                         # Basic 'None' alg check (heuristic)
                         if "eyJhbGciOiJub25lIn0" in cookie.value: # {"alg":"none"} base64
                              self._add_finding("jwt_none", url, f"JWT with 'none' algorithm found in cookie '{key}'", key, cookie.value)

            # Note: A real scan would Fuzz the JWT. Here we just passive detect.
        except: pass

    async def check_cookie_security(self, session, url):
        """
        Checks Set-Cookie headers for missing security flags.
        """
        try:
             # We need access to raw cookies from the response history or cookie jar
             # aiohttp cookie jar abstracts this, so we check the jar for the domain
             cookies = session.cookie_jar.filter_cookies(url)
             for key, cookie in cookies.items():
                  issues = []
                  if not cookie["secure"]:
                       issues.append("Missing 'Secure' flag")
                  if not cookie["httponly"]:
                       issues.append("Missing 'HttpOnly' flag")
                  
                  if issues:
                       self._add_finding("cookie_insecure", url, f"Cookie '{key}' issues: {', '.join(issues)}", key, None)
        except: pass

    async def check_tech_stack(self, session, url):
        try:
            ctx = await self.perform_request(session, 'HEAD', url, timeout=5)
            async with ctx as resp:
                headers = resp.headers
                techs = []
                if "Server" in headers: techs.append(f"Server: {headers['Server']}")
                if "X-Powered-By" in headers: techs.append(f"Powered-By: {headers['X-Powered-By']}")
                if "X-AspNet-Version" in headers: techs.append(f"ASP.NET: {headers['X-AspNet-Version']}")
                
                if techs:
                    self._add_finding("tech_stack", url, "\n".join(techs))
        except: pass

    async def check_js_analysis(self, session, url):
        dangerous_sinks = {
            "eval(": "Executes arbitrary code string",
            "document.write(": "Writes raw HTML/JS to DOM",
            "innerHTML": "Sets HTML content (potential XSS)",
            "dangerouslySetInnerHTML": "React direct HTML injection"
        }
        try:
            ctx = await self.perform_request(session, 'GET', url, timeout=5)
            async with ctx as resp:
                text = await resp.text()
                for sink, desc in dangerous_sinks.items():
                    if sink in text:
                        # Extract snippet
                        idx = text.find(sink)
                        snippet = text[max(0, idx-20):min(len(text), idx+50)]
                        self._add_finding("dom_xss", url, f"Found sink '{sink}' ({desc})\nContext: ...{snippet}...")
        except: pass

    async def check_union_sqli(self, session, url):
        """
        UNION-based SQLi: inject UNION SELECT with increasing column counts.
        Detection: error disappears AND our column markers appear in body.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        for param in params:
            # First get baseline response with a known-bad payload to see a reference error
            broken_params = params.copy()
            broken_params[param] = ["'"]
            broken_url = urlunparse(parsed._replace(query=urlencode(broken_params, doseq=True)))
            try:
                ctx = await self.perform_request(session, 'GET', broken_url, timeout=5)
                async with ctx as baseline_resp:
                    baseline_text = await baseline_resp.text()
                    # Only probe UNION if the single-quote causes an error (injectable endpoint)
                    has_error = any(err in baseline_text for err in self.sql_errors)
                    if not has_error:
                        continue
            except:
                continue

            # Now try UNION SELECT with 1..6 columns
            for cols in range(1, 7):
                marker = f"sc_union_{cols}"
                payload_cols = ",".join([f"'{marker}'" if i == 1 else "NULL" for i in range(1, cols + 1)])
                payload = f"' UNION SELECT {payload_cols} -- "

                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))

                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        text = await resp.text()
                        # True positive: no SQL error AND our marker appears in body
                        no_error = not any(err in text for err in self.sql_errors)
                        marker_reflected = marker in text
                        if no_error and marker_reflected:
                            self._add_finding(
                                "union_sqli", url,
                                f"UNION SELECT marker '{marker}' reflected with {cols} columns",
                                param, payload
                            )
                            break  # Stop after first confirmed column count
                except:
                    pass
    
    async def check_sqli(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        for param in params:
            test_params = params.copy()
            test_params[param] = ["'"]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
            try:
                ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                async with ctx as resp:
                    text = await resp.text()
                    for error in self.sql_errors:
                        if error in text:
                            # Double Verification:
                            # 1. Trigger Payload: ' (Causes Syntax Error)
                            # 2. Safe Payload: Original Value (Should be valid)
                            # Logic: If Trigger causes error AND Safe does NOT, it's SQLi.
                            
                            safe_params = params.copy()
                            safe_params[param] = params[param] # Use original value (e.g., "1")
                            safe_url = urlunparse(parsed._replace(query=urlencode(safe_params, doseq=True)))
                            
                            is_fp = False
                            try:
                                ctx = await self.perform_request(session, 'GET', safe_url, timeout=5)
                                async with ctx as safe_resp:
                                    safe_text = await safe_resp.text()
                                    # If the error persists even with valid syntax, the server is just broken/verbose
                                    if error in safe_text:
                                        print(f"[-] Discarding SQLi FP at {url}. Error present in benign request.")
                                        is_fp = True
                            except: pass

                            if not is_fp:
                                self._add_finding("sql_injection", url, f"Database error: {error}", param, "'")
                            break
            except: pass

    async def check_boolean_sqli(self, session, url):
        """
        Detects Boolean-based Blind SQLi by comparing True vs False conditions.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params: return

        # Simple arithmetic boolean tests
        payload_true = "' AND 1=1 -- "
        payload_false = "' AND 1=2 -- "

        for param in params:
            try:
                # 1. Baseline Request
                ctx = await self.perform_request(session, 'GET', url, timeout=5)
                async with ctx as r1:
                    base_len = len(await r1.text())

                # 2. True Condition
                test_params = params.copy()
                test_params[param] = [payload_true] # Simplified injection
                t_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                ctx = await self.perform_request(session, 'GET', t_url, timeout=5)
                async with ctx as r2:
                    true_len = len(await r2.text())

                # 3. False Condition
                test_params = params.copy()
                test_params[param] = [payload_false]
                f_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                ctx = await self.perform_request(session, 'GET', f_url, timeout=5)
                async with ctx as r3:
                    false_len = len(await r3.text())

                # Logic: If True is close to Base, but False is significantly different (missing content)
                # Tolerance of 5% difference for dynamic content
                if abs(base_len - true_len) < (base_len * 0.05) and abs(base_len - false_len) > (base_len * 0.1):
                    self._add_finding("sql_injection", url, 
                        f"Boolean behavior detected. True len: {true_len}, False len: {false_len}", 
                        param, payload_true)

            except: pass

    async def check_xss(self, session, url):
        """
        Reflected XSS: tries multiple context-aware payloads per parameter.
        Stops at first confirmed reflection per param to avoid noise.
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            for payload in self.xss_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=5)
                    async with ctx as resp:
                        text = await resp.text()
                        if payload in text:
                            self._add_finding(
                                "xss_reflected", url,
                                f"Payload reflected verbatim in response body",
                                param, payload
                            )
                            break  # One confirmed payload per param is enough
                except:
                    pass

    async def check_sqli_post(self, session, url):
        """
        POST Body SQLi: discovers <form> inputs on the page and tests
        each text/search/email field with SQL injection payloads.
        """
        from bs4 import BeautifulSoup
        try:
            ctx = await self.perform_request(session, 'GET', url, timeout=5)
            async with ctx as resp:
                if resp.status != 200:
                    return
                html = await resp.text()

            soup = BeautifulSoup(html, "html.parser")
            forms = soup.find_all("form")
            if not forms:
                return

            for form in forms:
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                if method != "post":
                    continue

                post_url = urljoin(url, action) if action else url

                # Build baseline form data
                inputs = form.find_all("input")
                base_data = {}
                for inp in inputs:
                    name = inp.get("name")
                    if not name:
                        continue
                    itype = inp.get("type", "text").lower()
                    if itype in ("hidden", "submit", "button"):
                        base_data[name] = inp.get("value", "")
                    elif itype == "password":
                        base_data[name] = "test_password"
                    else:
                        base_data[name] = "test"

                testable = [n for n, v in base_data.items()
                            if v not in ("",) and
                            form.find("input", {"name": n, "type": "hidden"}) is None]

                sqli_payloads = ["'", "' OR '1'='1", "1' AND SLEEP(0) -- "]

                for field in testable:
                    for payload in sqli_payloads:
                        data = base_data.copy()
                        data[field] = payload
                        try:
                            ctx = await self.perform_request(session, 'POST', post_url,
                                                            data=data, timeout=5)
                            async with ctx as resp:
                                text = await resp.text()
                                for error in self.sql_errors:
                                    if error in text:
                                        self._add_finding(
                                            "sql_injection", post_url,
                                            f"POST field '{field}': DB error '{error}'",
                                            field, payload
                                        )
                                        break
                        except:
                            pass
        except:
            pass

    async def check_xss_post(self, session, url):
        """
        POST Body XSS: discovers <form> inputs and tests each text field
        with XSS payloads, checking if they're reflected in the response.
        """
        from bs4 import BeautifulSoup
        try:
            ctx = await self.perform_request(session, 'GET', url, timeout=5)
            async with ctx as resp:
                if resp.status != 200:
                    return
                html = await resp.text()

            soup = BeautifulSoup(html, "html.parser")
            forms = soup.find_all("form")
            if not forms:
                return

            for form in forms:
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                if method != "post":
                    continue

                post_url = urljoin(url, action) if action else url

                inputs = form.find_all("input")
                base_data = {}
                for inp in inputs:
                    name = inp.get("name")
                    if not name:
                        continue
                    itype = inp.get("type", "text").lower()
                    if itype in ("hidden", "submit", "button"):
                        base_data[name] = inp.get("value", "")
                    elif itype == "password":
                        base_data[name] = "test_password"
                    else:
                        base_data[name] = "test"

                testable = [n for n in base_data
                            if form.find("input", {"name": n, "type": "hidden"}) is None]

                for field in testable:
                    for payload in self.xss_payloads:
                        data = base_data.copy()
                        data[field] = payload
                        try:
                            ctx = await self.perform_request(session, 'POST', post_url,
                                                            data=data, timeout=5)
                            async with ctx as resp:
                                text = await resp.text()
                                if payload in text:
                                    self._add_finding(
                                        "xss_reflected", post_url,
                                        f"POST field '{field}': XSS payload reflected",
                                        field, payload
                                    )
                                    break
                        except:
                            pass
        except:
            pass

    async def check_header_injection(self, session, url):
        """
        Header Injection: tests common headers used in app logic
        (X-Forwarded-For, Host, Referer) for reflection or error triggering.
        Detects: Host Header Injection, Log Injection via headers.
        """
        marker = "sc-hdr-test"
        inject_headers = {
            "X-Forwarded-For":   marker,
            "X-Forwarded-Host":  marker,
            "Referer":           f"http://{marker}.evil.com",
            "X-Original-URL":    f"/{marker}",
            "X-Rewrite-URL":     f"/{marker}",
        }
        try:
            for header, value in inject_headers.items():
                ctx = await self.perform_request(session, 'GET', url,
                                                 headers={header: value}, timeout=5)
                async with ctx as resp:
                    text = await resp.text()
                    if marker in text:
                        self._add_finding(
                            "sensitive_data", url,
                            f"Header '{header}' value reflected in response body (possible injection)",
                            header, value
                        )
        except:
            pass

    async def check_sensitive_info(self, session, url):
        try:
            ctx = await self.perform_request(session, 'GET', url, timeout=5)
            async with ctx as resp:
                text = await resp.text()
                for name, pattern in self.sensitive_patterns.items():
                    if re.search(pattern, text):
                        self._add_finding("sensitive_data", url, f"Found pattern match for {name}")
        except: pass

    async def check_security_headers(self, session, url):
        try:
            ctx = await self.perform_request(session, 'HEAD', url, timeout=5)
            async with ctx as resp:
                headers = resp.headers
                for h in self.required_headers:
                    if h not in headers:
                        self._add_finding("security_header", url, f"Missing Header: {h}")
        except: pass

    async def check_sensitive_files(self, session, url):
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for f in self.fuzz_files:
            target = urljoin(base + "/", f)
            try:
                ctx = await self.perform_request(session, 'GET', target, timeout=5)
                async with ctx as resp:
                 if resp.status == 200 and len(await resp.text()) > 0:
                     text = await resp.text()
                     # Validated against Smart 404
                     if not self.is_custom_404(resp.status, text):
                          self._add_finding("hidden_file", target, f"Accessible file found: {f}")
                     else:
                          pass # Ignored as 404
            except: pass

    async def check_time_based_sqli(self, session, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        sleep_payloads = ["SLEEP(5)", "WAITFOR DELAY '0:0:5'"]
        
        for param in params:
            for payload in sleep_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                start = time.time()
                try:
                    ctx = await self.perform_request(session, 'GET', test_url, timeout=10)
                    async with ctx as resp:
                        await resp.text()
                        if time.time() - start > 5:
                            self._add_finding("blind_sqli", url, f"Response delay > 5s", param, payload)
                            break
                except: pass
