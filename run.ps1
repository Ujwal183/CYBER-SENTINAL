# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 🛡️ Cyber Sentinel - PowerShell Launcher
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$Host.UI.RawUI.WindowTitle = "Cyber Sentinel - AI Network IDS"

Write-Host ""
Write-Host "  ===================================================" -ForegroundColor Cyan
Write-Host "    CYBER SENTINEL - AI Network Intrusion Detection" -ForegroundColor Green
Write-Host "  ===================================================" -ForegroundColor Cyan
Write-Host ""

# Navigate to script directory
Set-Location $PSScriptRoot

# Check/Create virtual environment
if (-not (Test-Path ".venv\Scripts\Activate.ps1")) {
    Write-Host "[!] Virtual environment not found. Creating one..." -ForegroundColor Yellow
    python -m venv .venv
    Write-Host "[+] Virtual environment created." -ForegroundColor Green
}

# Activate virtual environment
& .\.venv\Scripts\Activate.ps1
Write-Host "[+] Virtual environment activated." -ForegroundColor Green

# Check if dependencies are installed
try {
    python -c "import fastapi" 2>$null
    Write-Host "[+] Dependencies already installed." -ForegroundColor Green
} catch {
    Write-Host "[*] Installing dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt
    Write-Host "[+] Dependencies installed." -ForegroundColor Green
}

Write-Host ""
Write-Host "[*] Starting Cyber Sentinel server..." -ForegroundColor Cyan
Write-Host "[*] Dashboard: http://localhost:8000" -ForegroundColor White
Write-Host "[*] API Docs:  http://localhost:8000/docs" -ForegroundColor White
Write-Host "[*] Press Ctrl+C to stop the server." -ForegroundColor Yellow
Write-Host ""

# Run the backend from the project root
python -m backend.app
