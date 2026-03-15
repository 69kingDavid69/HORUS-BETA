@echo off
setlocal EnableDelayedExpansion
REM =============================================================================
REM  HORUS – Installation Script  (Windows – Command Prompt)
REM  Run as Administrator if Docker/service issues arise.
REM =============================================================================

title HORUS Installer

echo.
echo   ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗
echo   ██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔════╝
echo   ███████║██║   ██║██████╔╝██║   ██║███████╗
echo   ██╔══██║██║   ██║██╔══██╗██║   ██║╚════██║
echo   ██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║
echo   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
echo.
echo [HORUS] Automated Installer  (Windows)
echo.

REM ── Locate project root (same folder as this script) ─────────────────────────
set "PROJECT_ROOT=%~dp0"
REM Remove trailing backslash
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"
echo [HORUS] Project root: %PROJECT_ROOT%

REM =============================================================================
REM  Step 1 – Check prerequisites
REM =============================================================================
echo.
echo [HORUS] --- Step 1/5: Checking prerequisites ---

REM ── Node.js ──────────────────────────────────────────────────────────────────
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo [X] Node.js NOT found. Install from: https://nodejs.org
  pause & exit /b 1
)
for /f "tokens=*" %%v in ('node --version') do echo [OK] Node.js: %%v

REM ── npm ──────────────────────────────────────────────────────────────────────
where npm >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo [X] npm NOT found. Re-install Node.js from: https://nodejs.org
  pause & exit /b 1
)
for /f "tokens=*" %%v in ('npm --version') do echo [OK] npm: %%v

REM ── Docker ───────────────────────────────────────────────────────────────────
where docker >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo [X] Docker NOT found. Install from: https://docs.docker.com/get-docker/
  pause & exit /b 1
)
for /f "tokens=*" %%v in ('docker --version') do echo [OK] %%v

REM ── Docker Compose ───────────────────────────────────────────────────────────
docker compose version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
  for /f "tokens=*" %%v in ('docker compose version') do echo [OK] %%v
  set "COMPOSE_CMD=docker compose"
) else (
  where docker-compose >nul 2>&1
  if %ERRORLEVEL% NEQ 0 (
    echo [X] Docker Compose NOT found. Install from: https://docs.docker.com/compose/install/
    pause & exit /b 1
  )
  for /f "tokens=*" %%v in ('docker-compose --version') do echo [OK] %%v
  set "COMPOSE_CMD=docker-compose"
)

REM ── Python (optional) ────────────────────────────────────────────────────────
set "PYTHON_AVAILABLE=false"
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
  for /f "tokens=*" %%v in ('python --version') do echo [OK] %%v
  set "PYTHON_AVAILABLE=true"
) else (
  where python3 >nul 2>&1
  if %ERRORLEVEL% EQU 0 (
    for /f "tokens=*" %%v in ('python3 --version') do echo [OK] %%v
    set "PYTHON_AVAILABLE=true"
  ) else (
    echo [!] Python 3 not found. Python services will run inside Docker.
  )
)

REM =============================================================================
REM  Step 2 – Install Node.js dependencies
REM =============================================================================
echo.
echo [HORUS] --- Step 2/5: Installing Node.js dependencies (BACKEND\api) ---

set "API_DIR=%PROJECT_ROOT%\BACKEND\api"
if not exist "%API_DIR%\package.json" (
  echo [X] Cannot find %API_DIR%\package.json — run this script from the HORUS root.
  pause & exit /b 1
)

pushd "%API_DIR%"
call npm install
if %ERRORLEVEL% NEQ 0 (
  echo [X] npm install failed.
  popd & pause & exit /b 1
)
echo [OK] Node.js dependencies installed.
popd

REM =============================================================================
REM  Step 3 – Install Python dependencies (if Python available)
REM =============================================================================
echo.
echo [HORUS] --- Step 3/5: Installing Python dependencies ---

set "REQ_FILE=%PROJECT_ROOT%\BACKEND\api\requirements-unified.txt"
set "VENV_DIR=%PROJECT_ROOT%\BACKEND\api\.venv"
if "%PYTHON_AVAILABLE%"=="true" (
  if exist "%REQ_FILE%" (
    REM Detect python command
    set "PY_CMD=python"
    where python3 >nul 2>&1 && set "PY_CMD=python3"

    REM Create virtual environment to avoid PEP 668 externally-managed errors
    if not exist "%VENV_DIR%\Scripts\activate.bat" (
      echo [HORUS] Creating Python virtual environment at BACKEND\api\.venv ...
      %PY_CMD% -m venv "%VENV_DIR%"
    ) else (
      echo [HORUS] Reusing existing virtual environment at BACKEND\api\.venv
    )
    echo [HORUS] Installing Python packages inside venv ...
    "%VENV_DIR%\Scripts\pip" install --upgrade pip --quiet
    "%VENV_DIR%\Scripts\pip" install -r "%REQ_FILE%"
    if %ERRORLEVEL% NEQ 0 (
      echo [!] pip install had issues (likely platform/Python version mismatch).
      echo [!] Non-fatal - Python services will run correctly inside Docker.
    ) else (
      echo [OK] Python dependencies installed inside BACKEND\api\.venv
      echo [HORUS]   To activate locally: %VENV_DIR%\Scripts\activate
    )
  ) else (
    echo [!] requirements-unified.txt not found — skipping.
  )
) else (
  echo [!] Skipping Python install (Python not available locally).
)

REM =============================================================================
REM  Step 4 – Set up .env file
REM =============================================================================
echo.
echo [HORUS] --- Step 4/5: Setting up environment file ---

set "ENV_FILE=%PROJECT_ROOT%\BACKEND\api\.env"
set "ENV_EXAMPLE=%PROJECT_ROOT%\BACKEND\api\.env.example"

if exist "%ENV_FILE%" (
  echo [!] .env already exists — leaving it untouched.
) else (
  if exist "%ENV_EXAMPLE%" (
    copy "%ENV_EXAMPLE%" "%ENV_FILE%" >nul
    echo [OK] Copied .env.example to .env
  ) else (
    (
      echo # ── Scanning ──────────────────────────────────────────────
      echo SKIP_AUTHORIZATION=true
      echo KALI_CONTAINER=kali-redteam
      echo SCANNER_DOCKER_NETWORK=lab_net
      echo ALLOW_PUBLIC_TARGETS=false
      echo AUTHORIZED_TARGETS=192.168.1.0/24
      echo SCAN_PROFILE=balanced
      echo.
      echo # ── Hydra ─────────────────────────────────────────────────
      echo HYDRA_ENABLED=true
      echo HYDRA_MAX_ATTEMPTS=112
      echo HYDRA_MAX_DURATION_SEC=20
      echo HYDRA_COOLDOWN_SEC=120
      echo HYDRA_TASKS=4
      echo HYDRA_STOP_ON_LOCKOUT=true
      echo HYDRA_STOP_ON_RATE_LIMIT=true
      echo.
      echo # ── MySQL Database ─────────────────────────────────────────
      echo DB_ENABLED=true
      echo DB_HOST=127.0.0.1
      echo DB_PORT=3309
      echo DB_USER=horus_app
      echo DB_PASSWORD=CHANGE_ME
      echo DB_NAME=horus_db
      echo.
      echo # ── OpenAI (optional) ─────────────────────────────────────
      echo OPENAI_API_KEY=
      echo OPENAI_MODEL=gpt-4o-mini
      echo.
      echo # ── AI Provider (optional) ───────────────────────────────
      echo AI_PROVIDER=openai
      echo OLLAMA_BASE_URL=http://host.docker.internal:11434
      echo OLLAMA_MODEL=llama3.1:8b
      echo.
      echo # ── Email / SMTP (optional) ────────────────────────────────
      echo SMTP_HOST=smtp.gmail.com
      echo SMTP_PORT=587
      echo SMTP_SECURE=false
      echo SMTP_USER=your_email@gmail.com
      echo SMTP_PASSWORD=your_app_password
      echo SMTP_FROM=your_email@gmail.com
    ) > "%ENV_FILE%"
    echo [OK] Created default .env template at BACKEND\api\.env
    echo [!] Edit BACKEND\api\.env with your real credentials before starting.
  )
)

REM =============================================================================
REM  Step 5 – Build and start Docker services
REM =============================================================================
echo.
echo [HORUS] --- Step 5/5: Building and starting Docker services ---

pushd "%PROJECT_ROOT%\docker"
call %COMPOSE_CMD% up --build -d
if %ERRORLEVEL% NEQ 0 (
  echo [X] Docker Compose failed to start services.
  popd & pause & exit /b 1
)
echo [OK] All Docker services started.
popd

REM =============================================================================
REM  Done
REM =============================================================================
echo.
echo ============================================================
echo   [SUCCESS]  HORUS installed successfully!
echo ============================================================
echo   Frontend / API  --^>  http://localhost:3000
echo   Health check    --^>  http://localhost:3000/api/health
echo   Security API    --^>  http://localhost:8001
echo ============================================================
echo.
echo [!] Remember to review BACKEND\api\.env with your credentials.
echo.
pause
endlocal
