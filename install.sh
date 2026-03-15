#!/usr/bin/env bash
# =============================================================================
#  HORUS – Installation Script  (Linux & macOS)
# =============================================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[HORUS]${RESET} $*"; }
success() { echo -e "${GREEN}[✔]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✘]${RESET} $*"; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
cat << 'EOF'
  ██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗███████╗
  ██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔════╝
  ███████║██║   ██║██████╔╝██║   ██║███████╗
  ██╔══██║██║   ██║██╔══██╗██║   ██║╚════██║
  ██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
EOF
echo -e "${RESET}"
info "HORUS – Automated Installer  (Linux / macOS)"
echo ""

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS="$(uname -s)"
case "$OS" in
  Linux*)  PLATFORM="Linux"  ;;
  Darwin*) PLATFORM="macOS"  ;;
  *)       error "Unsupported OS: $OS. Please use Linux, macOS, or Windows." ;;
esac
info "Detected platform: ${BOLD}$PLATFORM${RESET}"

# ── Helper: check if command exists ──────────────────────────────────────────
require() {
  local cmd="$1"; local label="${2:-$1}"; local url="${3:-}"
  if ! command -v "$cmd" &>/dev/null; then
    warn "$label is NOT installed."
    if [[ -n "$url" ]]; then
      warn "Please install it from: ${url}"
    fi
    error "Missing required dependency: $label  — aborting."
  fi
  success "$label found: $(${cmd} --version 2>&1 | head -1)"
}

# ── 1. Check Prerequisites ────────────────────────────────────────────────────
echo ""
info "━━━ Step 1/5 — Checking prerequisites ━━━"

require node  "Node.js (v18+)"    "https://nodejs.org"
require npm   "npm (v9+)"         "https://nodejs.org"
require docker "Docker (v20+)"    "https://docs.docker.com/get-docker/"

# Docker Compose v2 (plugin) or v1 standalone
if docker compose version &>/dev/null 2>&1; then
  success "Docker Compose (plugin) found: $(docker compose version)"
elif command -v docker-compose &>/dev/null; then
  success "Docker Compose (standalone) found: $(docker-compose --version)"
else
  warn "Docker Compose is NOT installed."
  warn "Install it from: https://docs.docker.com/compose/install/"
  error "Missing required dependency: Docker Compose — aborting."
fi

# Python is optional (only needed for local FastAPI dev without Docker)
if command -v python3 &>/dev/null; then
  success "Python 3 found: $(python3 --version)"
  PYTHON_AVAILABLE=true
else
  warn "Python 3 not found – Python deps will only be installed inside Docker."
  PYTHON_AVAILABLE=false
fi

# ── 2. Locate project root ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
info "Project root: ${BOLD}$PROJECT_ROOT${RESET}"

# ── 3. Install Node.js dependencies ──────────────────────────────────────────
echo ""
info "━━━ Step 2/5 — Installing Node.js dependencies (BACKEND/api) ━━━"
API_DIR="$PROJECT_ROOT/BACKEND/api"
if [[ ! -f "$API_DIR/package.json" ]]; then
  error "Cannot find $API_DIR/package.json — is this the HORUS project root?"
fi
cd "$API_DIR"
npm install
success "Node.js dependencies installed."
cd "$PROJECT_ROOT"

# ── 4. Install Python dependencies (if Python is available) ──────────────────
echo ""
info "━━━ Step 3/5 — Installing Python dependencies (BACKEND/api) ━━━"
REQ_FILE="$PROJECT_ROOT/BACKEND/api/requirements-unified.txt"
VENV_DIR="$PROJECT_ROOT/BACKEND/api/.venv"

if $PYTHON_AVAILABLE && [[ -f "$REQ_FILE" ]]; then
  # ── Ensure python3-venv (ensurepip) is present ──────────────────────────────
  # Debian/Ubuntu ship python3 and python3-venv as separate packages.
  # Test quietly; if venv creation fails, try to install the missing package.
  if ! python3 -m ensurepip --version &>/dev/null 2>&1; then
    if [[ "$PLATFORM" == "Linux" ]] && command -v apt-get &>/dev/null; then
      warn "python3-venv not found — installing it now (requires sudo) …"
      # Detect the exact Python version to install the matching venv package
      PY_VER="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
      sudo apt-get install -y "python${PY_VER}-venv" python3-pip --quiet \
        || sudo apt-get install -y python3-venv python3-pip --quiet
      success "python3-venv installed."
    else
      warn "python3-venv / ensurepip is not available and cannot be auto-installed on $PLATFORM."
      warn "Python services will run inside the Docker container instead."
      PYTHON_AVAILABLE=false
    fi
  fi

  if $PYTHON_AVAILABLE; then
    # Create (or reuse) the virtual environment
    if [[ ! -d "$VENV_DIR" ]]; then
      info "Creating Python virtual environment at BACKEND/api/.venv …"
      python3 -m venv "$VENV_DIR"
    else
      info "Reusing existing virtual environment at BACKEND/api/.venv"
    fi
    info "Installing Python packages inside venv …"
    "$VENV_DIR/bin/pip" install --upgrade pip --quiet
    if "$VENV_DIR/bin/pip" install -r "$REQ_FILE" 2>/dev/null; then
      success "Python dependencies installed inside BACKEND/api/.venv"
      info "  → To activate locally: source BACKEND/api/.venv/bin/activate"
    else
      warn "pip install encountered issues (likely a platform/Python version mismatch)."
      warn "This is non-fatal — Python services will run correctly inside Docker."
      warn "To debug: source BACKEND/api/.venv/bin/activate && pip install -r BACKEND/api/requirements-unified.txt"
    fi
  fi

elif ! $PYTHON_AVAILABLE; then
  warn "Skipping Python install (Python 3 not available locally)."
  warn "Python services will run inside the Docker container."
else
  warn "requirements-unified.txt not found – skipping."
fi

# ── 5. Set up .env file ───────────────────────────────────────────────────────
echo ""
info "━━━ Step 4/5 — Setting up environment file ━━━"
ENV_FILE="$PROJECT_ROOT/BACKEND/api/.env"
ENV_EXAMPLE="$PROJECT_ROOT/BACKEND/api/.env.example"
if [[ -f "$ENV_FILE" ]]; then
  warn ".env already exists – leaving it untouched."
else
  if [[ -f "$ENV_EXAMPLE" ]]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    success "Copied .env.example → .env"
  else
    # Create a minimal template
    cat > "$ENV_FILE" << 'ENVEOF'
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
ENVEOF
    success "Created default .env template at BACKEND/api/.env"
    warn "⚠  Edit BACKEND/api/.env and set your real credentials before starting."
  fi
fi

# ── 6. Build & start Docker services ─────────────────────────────────────────
echo ""
info "━━━ Step 5/5 — Building and starting Docker services ━━━"
DOCKER_DIR="$PROJECT_ROOT/docker"
cd "$DOCKER_DIR"

# Determine compose command
COMPOSE_CMD="docker compose"
command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1 && \
  COMPOSE_CMD="docker-compose"

info "Running: $COMPOSE_CMD up --build -d"
$COMPOSE_CMD up --build -d
success "All Docker services started."
cd "$PROJECT_ROOT"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════╗"
echo -e "║    🎉  HORUS installed successfully!         ║"
echo -e "╠══════════════════════════════════════════════╣"
echo -e "║  Frontend / API  →  http://localhost:3000    ║"
echo -e "║  Health check    →  http://localhost:3000/   ║"
echo -e "║                      api/health              ║"
echo -e "║  Security API    →  http://localhost:8001    ║"
echo -e "╚══════════════════════════════════════════════╝${RESET}"
echo ""
warn "Remember to review and update BACKEND/api/.env with your real credentials."
