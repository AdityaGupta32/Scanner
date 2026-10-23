# Scancrypt / VerseScan Startup Script for Windows
# Run this in PowerShell from any location

$rootDir = $PSScriptRoot
Write-Host "[*] Starting VerseScan System from $rootDir..." -ForegroundColor Cyan

# 1. Start Vulnerable App
Write-Host "[*] Launching Vulnerable App on http://localhost:8081..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd `"$rootDir`"; python vulnerable_app.py"

# 2. Start Scanner Backend
Write-Host "[*] Launching Backend API on http://localhost:8000..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd `"$rootDir\scanner-engine`"; python main.py"

# 3. Start Dashboard
Write-Host "[*] Launching Dashboard on http://localhost:3000..." -ForegroundColor Magenta
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd `"$rootDir\dashboard`"; npm run dev"

Write-Host "`n[DONE] All components launched in separate windows!" -ForegroundColor Green
Write-Host "[INFO] Backend API:       http://localhost:8000" -ForegroundColor White
Write-Host "[INFO] Vulnerable App:    http://localhost:8081" -ForegroundColor White
Write-Host "[INFO] Dashboard:         http://localhost:3000" -ForegroundColor White
Write-Host "[INFO] Run Local Tests:   python test_backend_local.py" -ForegroundColor Cyan

