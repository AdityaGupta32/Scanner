# ╔══════════════════════════════════════════════════════════════╗
# ║  VerseScan — Full Docker Test Runner                        ║
# ║  Runs: Build → Start → Verify → Scan → Sandbox → PDF       ║
# ╚══════════════════════════════════════════════════════════════╝
# Usage: .\docker_test.ps1

$ErrorActionPreference = "Continue"
$COMPOSE_DIR = "$PSScriptRoot\infrastructure\docker"
$API = "http://localhost:8000"
$TARGET = "http://localhost:8081"
$ORCH = "http://localhost:9000"

function Write-Step($num, $msg) {
    Write-Host "`n[$num] $msg" -ForegroundColor Cyan
}
function Write-Pass($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  [!!] $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "  --> $msg" -ForegroundColor Yellow }

# ── Step 0: Docker sanity check ───────────────────────────────
Write-Step "0" "Checking Docker is running..."
try {
    $v = docker --version 2>&1
    Write-Pass "Docker found: $v"
    docker ps | Out-Null
    Write-Pass "Docker daemon is running"
} catch {
    Write-Fail "Docker is not running. Open Docker Desktop and wait for it to start."
    exit 1
}

# ── Step 1: Build containers ──────────────────────────────────
Write-Step "1" "Building Docker images (this takes ~3-5 min on first run)..."
Set-Location $COMPOSE_DIR
docker-compose build 2>&1 | Tail -20
Write-Pass "Build complete"

# ── Step 2: Start services ────────────────────────────────────
Write-Step "2" "Starting scanner-engine, vulnerable-app, sandbox-orchestrator..."
Write-Info "Running in background (detached mode)"
docker-compose up -d scanner-engine vulnerable-app sandbox-orchestrator

Write-Info "Waiting 15 seconds for services to be ready..."
Start-Sleep -Seconds 15

# ── Step 3: Verify all services ───────────────────────────────
Write-Step "3" "Verifying services are live..."

# Scanner
try {
    $r = Invoke-WebRequest -Uri "$API/ping" -UseBasicParsing -TimeoutSec 5
    if ($r.Content -match "pong") { Write-Pass "Scanner Engine is LIVE at $API" }
} catch {
    Write-Fail "Scanner Engine not responding at $API — check: docker logs vs-scanner-engine"
}

# Vulnerable app
try {
    $r = Invoke-WebRequest -Uri "$TARGET/" -UseBasicParsing -TimeoutSec 5
    if ($r.StatusCode -eq 200) { Write-Pass "Vulnerable App is LIVE at $TARGET" }
} catch {
    Write-Fail "Vulnerable App not responding at $TARGET"
}

# Sandbox orchestrator
try {
    $r = Invoke-WebRequest -Uri "$ORCH/health" -UseBasicParsing -TimeoutSec 5
    $data = $r.Content | ConvertFrom-Json
    Write-Pass "Sandbox Orchestrator is LIVE — docker_connected=$($data.docker_connected), active=$($data.active_sandboxes)"
} catch {
    Write-Fail "Sandbox Orchestrator not responding at $ORCH"
}

# ── Step 4: Run a scan ────────────────────────────────────────
Write-Step "4" "Launching a scan against the vulnerable app..."
$scanBody = '{"url": "http://vulnerable-app:8081", "max_pages": 5}'
try {
    $r = Invoke-RestMethod -Uri "$API/scan" -Method POST `
         -ContentType "application/json" -Body $scanBody -TimeoutSec 10
    $scanId = $r.scan_id
    Write-Pass "Scan started! scan_id = $scanId"
    Write-Info "Waiting 30 seconds for scan to complete..."
    Start-Sleep -Seconds 30

    # Check scan result
    $result = Invoke-RestMethod -Uri "$API/scan/$scanId" -TimeoutSec 10
    $count = $result.findings.Count
    Write-Pass "Scan complete — $count vulnerabilities found (status: $($result.status))"
} catch {
    Write-Fail "Scan failed: $_"
    $scanId = $null
}

# ── Step 5: Test Sandbox lifecycle ────────────────────────────
Write-Step "5" "Testing Sandbox Orchestrator — create → list → destroy..."
$sandboxBody = '{"image": "versescan/vulnerable-app:latest", "ttl_seconds": 120, "name": "demo-box"}'
try {
    $s = Invoke-RestMethod -Uri "$API/sandbox/create" -Method POST `
         -ContentType "application/json" -Body $sandboxBody -TimeoutSec 15
    $sid = $s.sandbox_id
    Write-Pass "Sandbox created: ID=$sid, target=$($s.target_url), status=$($s.status)"

    $list = Invoke-RestMethod -Uri "$API/sandbox/list" -TimeoutSec 5
    Write-Pass "Active sandboxes: $($list.total) / $($list.max_allowed)"

    Invoke-RestMethod -Uri "$API/sandbox/$sid/destroy" -Method POST -TimeoutSec 10 | Out-Null
    Write-Pass "Sandbox $sid destroyed cleanly"
} catch {
    Write-Fail "Sandbox test failed: $_"
}

# ── Step 6: OWASP GenAI PDF ───────────────────────────────────
Write-Step "6" "Testing OWASP GenAI Compliance Report..."
if ($scanId) {
    try {
        $comp = Invoke-RestMethod -Uri "$API/compliance/$scanId" -TimeoutSec 10
        $owaspPass = $comp.owasp_top_10.pass
        $genaiPass = $comp.owasp_genai_top_10.pass
        Write-Pass "Compliance JSON: OWASP=$owaspPass PASS, GenAI=$genaiPass PASS, Risk=$($comp.risk_score)"
        Write-Info "Open PDF in browser: $API/owasp-report/$scanId"
        Write-Info "Open Standard PDF:   $API/report/$scanId"
    } catch {
        Write-Fail "Compliance report failed: $_"
    }
} else {
    Write-Info "Skipped (no scan_id — scan in step 4 failed)"
}

# ── Summary ───────────────────────────────────────────────────
Write-Host "`n======================================================" -ForegroundColor Cyan
Write-Host "  DOCKER TEST COMPLETE" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Scanner API:     $API"
Write-Host "  Vulnerable App:  $TARGET"
Write-Host "  Sandbox API:     $ORCH"
Write-Host ""
Write-Host "  Useful commands:"
Write-Host "    docker-compose logs -f              (live logs)"
Write-Host "    docker ps                           (running containers)"
Write-Host "    docker-compose down                 (stop everything)"
Write-Host "    docker exec -it vs-scanner-engine bash  (shell into scanner)"
Write-Host "======================================================`n" -ForegroundColor Cyan
