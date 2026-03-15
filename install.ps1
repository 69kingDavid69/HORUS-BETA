#Requires -Version 5.1
<#
.SYNOPSIS
    HORUS – Cross-Platform Installer (Windows PowerShell / PowerShell Core)
.DESCRIPTION
    Installs all dependencies for the HORUS application:
      • Node.js packages  (npm install)
      • Python packages   (pip install)
      • Docker services   (docker compose up --build -d)
.NOTES
    Run from the HORUS project root.  If execution policy blocks the script:
      Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colours ───────────────────────────────────────────────────────────────────
function Write-Info    { param($msg) Write-Host "[HORUS] $msg" -ForegroundColor Cyan   }
function Write-Ok      { param($msg) Write-Host "[OK] $msg"    -ForegroundColor Green  }
function Write-Warn    { param($msg) Write-Host "[!]  $msg"    -ForegroundColor Yellow }
function Write-Fail    { param($msg) Write-Host "[X]  $msg"    -ForegroundColor Red    }

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host @"

  ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗
  ██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔════╝
  ███████║██║   ██║██████╔╝██║   ██║███████╗
  ██╔══██║██║   ██║██╔══██╗██║   ██║╚════██║
  ██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

"@ -ForegroundColor Cyan

Write-Info "HORUS – Automated Installer  (Windows PowerShell)"
Write-Host ""

# ── Project root ─────────────────────────────────────────────────────────────
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Info "Project root: $ProjectRoot"

# ── Helper: require a command ─────────────────────────────────────────────────
function Require-Command {
    param(
        [string]$Command,
        [string]$Label,
        [string]$Url = ""
    )
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        Write-Fail "$Label is NOT installed."
        if ($Url) { Write-Warn "Install from: $Url" }
        throw "Missing required dependency: $Label"
    }
    $ver = & $Command --version 2>&1 | Select-Object -First 1
    Write-Ok "$Label : $ver"
}

# =============================================================================
#  Step 1 – Check prerequisites
# =============================================================================
Write-Host ""
Write-Info "━━━ Step 1/5 — Checking prerequisites ━━━"

Require-Command "node"   "Node.js (v18+)" "https://nodejs.org"
Require-Command "npm"    "npm (v9+)"       "https://nodejs.org"
Require-Command "docker" "Docker (v20+)"   "https://docs.docker.com/get-docker/"

# Docker Compose – v2 plugin or v1 standalone
$ComposeCmd = $null
try {
    $null = docker compose version 2>&1
    Write-Ok "Docker Compose plugin: $(docker compose version)"
    $ComposeCmd = @("docker", "compose")
} catch {
    if (Get-Command "docker-compose" -ErrorAction SilentlyContinue) {
        Write-Ok "Docker Compose standalone: $(docker-compose --version)"
        $ComposeCmd = @("docker-compose")
    } else {
        Write-Fail "Docker Compose NOT found. Install from: https://docs.docker.com/compose/install/"
        throw "Missing Docker Compose"
    }
}

# Python – optional
$PythonCmd = $null
foreach ($py in @("python3", "python")) {
    if (Get-Command $py -ErrorAction SilentlyContinue) {
        $pyVer = & $py --version 2>&1 | Select-Object -First 1
        Write-Ok "Python: $pyVer"
        $PythonCmd = $py
        break
    }
}
if (-not $PythonCmd) {
    Write-Warn "Python 3 not found — Python services will run inside Docker."
}

# =============================================================================
#  Step 2 – Install Node.js dependencies
# =============================================================================
Write-Host ""
Write-Info "━━━ Step 2/5 — Installing Node.js dependencies (BACKEND/api) ━━━"

$ApiDir = Join-Path $ProjectRoot "BACKEND\api"
if (-not (Test-Path (Join-Path $ApiDir "package.json"))) {
    throw "Cannot find $ApiDir\package.json — run this script from the HORUS project root."
}

Push-Location $ApiDir
try {
    npm install
    if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
    Write-Ok "Node.js dependencies installed."
} finally {
    Pop-Location
}

# =============================================================================
#  Step 3 – Install Python dependencies
# =============================================================================
Write-Host ""
Write-Info "━━━ Step 3/5 — Installing Python dependencies ━━━"

$ReqFile  = Join-Path $ProjectRoot "BACKEND\api\requirements-unified.txt"
$VenvDir  = Join-Path $ProjectRoot "BACKEND\api\.venv"
if ($PythonCmd -and (Test-Path $ReqFile)) {
    # Use a virtual environment to avoid PEP 668 "externally-managed" errors
    $venvPip = Join-Path $VenvDir "Scripts\pip"           # Windows path
    if ($IsLinux -or $IsMacOS) { $venvPip = Join-Path $VenvDir "bin/pip" }

    if (-not (Test-Path $VenvDir)) {
        Write-Info "Creating Python virtual environment at BACKEND/api/.venv ..."
        & $PythonCmd -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
    } else {
        Write-Info "Reusing existing virtual environment at BACKEND/api/.venv"
    }
    Write-Info "Installing Python packages inside venv ..."
    & $venvPip install --upgrade pip --quiet
    & $venvPip install -r $ReqFile
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "pip install had issues (likely a platform/Python version mismatch)."
        Write-Warn "Non-fatal — Python services will run correctly inside Docker."
    } else {
        Write-Ok "Python dependencies installed inside BACKEND/api/.venv"
        Write-Info "  → To activate locally: $VenvDir\Scripts\Activate.ps1"
    }
} elseif (-not $PythonCmd) {
    Write-Warn "Skipping Python install (Python not available locally)."
} else {
    Write-Warn "requirements-unified.txt not found — skipping."
}

# =============================================================================
#  Step 4 – Set up .env file
# =============================================================================
Write-Host ""
Write-Info "━━━ Step 4/5 — Setting up environment file ━━━"

$EnvFile    = Join-Path $ProjectRoot "BACKEND\api\.env"
$EnvExample = Join-Path $ProjectRoot "BACKEND\api\.env.example"

if (Test-Path $EnvFile) {
    Write-Warn ".env already exists — leaving it untouched."
} elseif (Test-Path $EnvExample) {
    Copy-Item $EnvExample $EnvFile
    Write-Ok "Copied .env.example → .env"
} else {
    $envTemplate = @"
# ── Scanning ──────────────────────────────────────────────
SKIP_AUTHORIZATION=true
KALI_CONTAINER=kali-redteam
SCANNER_DOCKER_NETWORK=lab_net
ALLOW_PUBLIC_TARGETS=false
AUTHORIZED_TARGETS=192.168.1.0/24
SCAN_PROFILE=balanced

# ── Hydra ─────────────────────────────────────────────────
HYDRA_ENABLED=true
HYDRA_MAX_ATTEMPTS=112
HYDRA_MAX_DURATION_SEC=20
HYDRA_COOLDOWN_SEC=120
HYDRA_TASKS=4
HYDRA_STOP_ON_LOCKOUT=true
HYDRA_STOP_ON_RATE_LIMIT=true

# ── MySQL Database ─────────────────────────────────────────
DB_ENABLED=true
DB_HOST=127.0.0.1
DB_PORT=3309
DB_USER=horus_app
DB_PASSWORD=CHANGE_ME
DB_NAME=horus_db

# ── OpenAI (optional) ─────────────────────────────────────
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini

# ── AI Provider (optional) ───────────────────────────────
AI_PROVIDER=openai
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=llama3.1:8b

# ── Email / SMTP (optional) ────────────────────────────────
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_FROM=your_email@gmail.com
"@
    $envTemplate | Set-Content -Encoding UTF8 $EnvFile
    Write-Ok "Created default .env template at BACKEND\api\.env"
    Write-Warn "Edit BACKEND\api\.env with your real credentials before starting."
}

# =============================================================================
#  Step 5 – Build and start Docker services
# =============================================================================
Write-Host ""
Write-Info "━━━ Step 5/5 — Building and starting Docker services ━━━"

$DockerDir = Join-Path $ProjectRoot "docker"
Push-Location $DockerDir
try {
    & $ComposeCmd[0] ($ComposeCmd[1..($ComposeCmd.Length - 1)] + @("up", "--build", "-d"))
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed to start services." }
    Write-Ok "All Docker services started."
} finally {
    Pop-Location
}

# =============================================================================
#  Done
# =============================================================================
Write-Host ""
Write-Host "╔══════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║    🎉  HORUS installed successfully!         ║" -ForegroundColor Green
Write-Host "╠══════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║  Frontend / API  →  http://localhost:3000    ║" -ForegroundColor Green
Write-Host "║  Health check    →  http://localhost:3000/   ║" -ForegroundColor Green
Write-Host "║                      api/health              ║" -ForegroundColor Green
Write-Host "║  Security API    →  http://localhost:8001    ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Warn "Remember to review BACKEND\api\.env with your real credentials."
