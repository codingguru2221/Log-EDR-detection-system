@echo off
setlocal
cd /d "%~dp0"

title Trinetra Sentinel
echo.
echo  ==========================================
echo            TRINETRA SENTINEL
echo       Local Threat Intelligence System
echo  ==========================================
echo.

if exist ".env" (
    echo [SETUP] Loading local .env settings...
    for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env") do (
        if not "%%A"=="" set "%%A=%%B"
    )
)

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is not installed or not available in PATH.
    echo Install Python 3.10 or newer, then run this file again.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [SETUP] Creating local Python environment...
    python -m venv .venv
    if errorlevel 1 goto :failed
)

echo [SETUP] Checking required packages...
".venv\Scripts\python.exe" -c "import fastapi, uvicorn, psutil, sklearn, numpy, watchdog, wmi, win32evtlog" >nul 2>nul
if errorlevel 1 (
    echo [SETUP] Installing required packages. This is needed only once...
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 goto :failed
)

where npm >nul 2>nul
if errorlevel 1 (
    echo [WARN] Node.js/npm not found. Install Node.js 18+ to build the React dashboard.
    echo [WARN] Skipping frontend build. Dashboard may not load without a prior build.
    goto :skip_frontend
)

if not exist "frontend\node_modules" (
    echo [SETUP] Installing frontend dependencies...
    pushd frontend
    call npm install
    if errorlevel 1 (
        popd
        goto :failed
    )
    popd
)

echo [BUILD] Building React dashboard...
pushd frontend
call npm run build
if errorlevel 1 (
    popd
    goto :failed
)
popd

:skip_frontend

powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing 'http://127.0.0.1:8000/api/overview' -TimeoutSec 1 ^| Out-Null; exit 0 } catch { exit 1 }"
if not errorlevel 1 (
    echo [READY] Trinetra Sentinel is already running.
    start "" "http://127.0.0.1:8000"
    exit /b 0
)

echo [START] Dashboard: http://127.0.0.1:8000
echo [INFO] Keep this window open while using Trinetra Sentinel.
echo [INFO] Press Ctrl+C to stop monitoring.
echo [DEV]  Frontend dev server: cd frontend ^&^& npm run dev
echo.

start "" "http://127.0.0.1:8000"
".venv\Scripts\python.exe" -m backend
exit /b 0

:failed
echo.
echo [ERROR] Setup failed. Check your internet connection and Python/Node installation.
pause
exit /b 1
