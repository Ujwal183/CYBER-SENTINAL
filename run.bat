@echo off
title Cyber Sentinel - AI Network IDS
color 0A

echo.
echo  ===================================================
echo    CYBER SENTINEL - AI Network Intrusion Detection
echo  ===================================================
echo.

:: Navigate to project directory
cd /d "%~dp0"

:: Check if virtual environment exists
if not exist ".venv\Scripts\activate.bat" (
    echo [!] Virtual environment not found. Creating one...
    python -m venv .venv
    echo [+] Virtual environment created.
)

:: Activate virtual environment
call .venv\Scripts\activate.bat
echo [+] Virtual environment activated.

:: Check if dependencies are installed (check for fastapi as a quick test)
python -c "import fastapi" 2>nul
if errorlevel 1 (
    echo [*] Installing dependencies...
    pip install -r requirements.txt
    echo [+] Dependencies installed.
) else (
    echo [+] Dependencies already installed.
)

echo.
echo [*] Starting Cyber Sentinel server on http://localhost:8000
echo [*] Press Ctrl+C to stop the server.
echo.

:: Run the backend from the project root
python -m backend.app

:: Keep window open if there's an error
if errorlevel 1 (
    echo.
    echo [!] Server stopped with an error. See above for details.
    pause
)
