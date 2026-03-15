# HORUS — Quick Start Guide (English)

This guide covers three ways to get HORUS running: via the installer script (fastest), manually step by step, and via the packaged executable. All three paths end at the same result: all services running and the UI accessible at `http://localhost:3000`.

---

## Prerequisites

The following tools must be installed before starting.

| Tool | Minimum version | Check command |
|---|---|---|
| Git | any | `git --version` |
| Node.js | 18.x | `node --version` |
| npm | 9.x | `npm --version` |
| Docker | 20.x | `docker --version` |
| Docker Compose | v2 plugin or v1 standalone | `docker compose version` |
| Python 3 | 3.9+ (optional, only for local FastAPI dev) | `python3 --version` |

### Installing prerequisites

**Node.js (recommended via nvm):**
```bash
# Linux / macOS
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc   # or ~/.zshrc
nvm install 18
nvm use 18
node --version     # should print v18.x.x
```

**Node.js (Windows — via nvm-windows):**
Download the installer from https://github.com/coreybutler/nvm-windows/releases, then:
```powershell
nvm install 18
nvm use 18
node --version
```

**Docker:**
- Linux: follow https://docs.docker.com/engine/install/
- macOS / Windows: install Docker Desktop from https://www.docker.com/products/docker-desktop/

After installing Docker on Linux, add your user to the docker group to avoid needing sudo:
```bash
sudo usermod -aG docker $USER
newgrp docker       # apply without logging out
docker run hello-world   # verify
```

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/69kingDavid69/back-integrative-project.git
cd back-integrative-project
```

Verify you are on the correct branch:
```bash
git branch       # should show * develop or * main
git log --oneline -5
```

---

## Step 2 — Configure Environment

Copy the environment template and fill in the required values:

```bash
cp BACKEND/api/.env.example BACKEND/api/.env
```

Open `BACKEND/api/.env` in any text editor and set at minimum:

```env
# ── Database ──────────────────────────────────────────────────────────────────
DB_HOST=127.0.0.1
DB_PORT=3309          # Docker maps MySQL to this host port
DB_USER=horus_app
DB_PASSWORD=CHANGE_ME # use a strong password
DB_NAME=horus_db

# ── AI Provider (choose one block) ────────────────────────────────────────────
# Option A — OpenAI (cloud, requires API key):
AI_PROVIDER=openai
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-4o-mini

# Option B — Ollama (local, no API key needed):
# AI_PROVIDER=ollama
# OLLAMA_BASE_URL=http://host.docker.internal:11434
# OLLAMA_MODEL=llama3.1:8b

# ── Email (optional, needed only for report email delivery) ───────────────────
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASSWORD=your-gmail-app-password
SMTP_FROM=your@gmail.com
```

> To generate a Gmail App Password: Google Account → Security → 2-Step Verification → App Passwords.

---

## Option A — Installer Script (Recommended)

The installer script handles all remaining steps automatically: it checks prerequisites, installs Node and Python dependencies, and starts all Docker services.

**Linux or macOS:**
```bash
chmod +x install.sh
./install.sh
```

**Windows PowerShell:**
```powershell
# If execution policy blocks the script, run this first (once):
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

.\install.ps1
```

**Windows Command Prompt (CMD):**
```cmd
install.bat
```

### What the installer does, step by step

| Step | What happens |
|---|---|
| Step 1/5 — Prerequisite check | Verifies Node.js, npm, Docker, Docker Compose are installed and meet minimum versions |
| Step 2/5 — Node dependencies | Runs `npm install` inside `BACKEND/api/` — installs Express, MySQL2, OpenAI, PDFKit, Puppeteer, etc. |
| Step 3/5 — Python environment | Creates a virtualenv at `BACKEND/api/.venv` and installs `requirements-unified.txt` (FastAPI, pydantic, scikit-learn, etc.) |
| Step 4/5 — Docker build | Runs `docker compose -f docker/docker-compose.yml build` — builds the Kali scanner image and the FastAPI image |
| Step 5/5 — Docker start | Runs `docker compose -f docker/docker-compose.yml up -d` — starts all services in the background |

The script prints colored status for each step. A green `[✔]` means success; a red `[✘]` means the step failed and the script exits with the error message.

---

## Option B — Manual Step by Step

Use this path if you want full control over each step, or if the installer script fails and you need to debug.

### B1. Install Node dependencies

```bash
cd BACKEND/api
npm install
cd ../..
```

This installs (among others):
- `express` — web framework and HTTP server
- `mysql2` — MySQL database driver
- `openai` — OpenAI SDK
- `pdfkit` + `puppeteer` — PDF generation
- `nodemailer` — email delivery
- `cors`, `dotenv`, `ip-cidr`, `xml2js` — utility libraries

### B2. Install Python dependencies (optional — only for local FastAPI dev)

If you plan to run FastAPI outside of Docker:
```bash
cd BACKEND/api
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows
pip install -r requirements-unified.txt
cd ../..
```

If you only use Docker (default), skip this step — Python deps are installed inside the container automatically.

### B3. Build Docker images

```bash
docker compose -f docker/docker-compose.yml build
```

This builds:
- `scanner-api` — Node.js Express API (Dockerfile.scanner)
- `security-api` — FastAPI + ML engine (Dockerfile.fastapi)
- `kali-scanner` — Kali Linux scanning runtime (BACKEND/labs/kali/Dockerfile)

Images are cached after the first build. Subsequent builds only rebuild changed layers.

### B4. Start all services

```bash
docker compose -f docker/docker-compose.yml up -d
```

Services started:
| Container | Role | Port |
|---|---|---|
| `scanner-api` | Node.js Express API + static UI | 3000 |
| `kali-scanner` | Nmap / Hydra scan runner | internal only |
| `mysql-db` | MySQL 8 database | 3309 |
| `security-api` | FastAPI security engine | 8001 |
| `db` | PostgreSQL auxiliary database | 5433 |

MySQL initialization takes 20–30 seconds on first run (schema import). Wait before hitting the health endpoint.

### B5. Verify all containers are healthy

```bash
docker compose -f docker/docker-compose.yml ps
```

All containers should show `Up` or `healthy`. Then check API health:
```bash
curl -sS http://localhost:3000/api/health
# Expected: {"status":"ok"}

curl -sS http://localhost:3000/api/v2/risk-score
# Expected: JSON with risk data or empty state
```

---

## Option C — Packaged Executable

The installer scripts (`install.sh`, `install.ps1`, `install.bat`) are self-contained executables that fully provision HORUS from zero. They are the distributed executable form of the application.

### Linux / macOS

```bash
# Make executable (only needed once):
chmod +x install.sh

# Run:
./install.sh
```

The script is a standalone bash program — no dependencies beyond bash itself (which is pre-installed on all Linux and macOS systems).

### Windows — PowerShell executable

Right-click `install.ps1` and select **"Run with PowerShell"**, or from a PowerShell terminal:

```powershell
.\install.ps1
```

If Windows blocks execution due to security policy, run this once in an administrator PowerShell:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Windows — CMD executable

Double-click `install.bat` in File Explorer, or from a Command Prompt:
```cmd
install.bat
```

### What happens after the executable runs

1. All Docker images are built and cached locally
2. All containers start in the background
3. The database schema is initialized
4. The terminal prints: `HORUS is running at http://localhost:3000`

### Updating to a new version

```bash
git pull origin develop        # or main
./install.sh                   # re-run the executable — it will rebuild changed images
```

The installer is idempotent: re-running it on an existing installation rebuilds only what changed and restarts affected services.

---

## Step 3 — Open the Application

Navigate to: **http://localhost:3000**

You will see the HORUS landing page. Click **Prueba Gratis** or **Iniciar Sesión** to enter the application.

---

## Step 4 — Configure AI Provider (Optional)

To switch AI provider after initial setup, edit `BACKEND/api/.env` and then restart the API container:

```bash
docker compose -f docker/docker-compose.yml up -d --force-recreate scanner-api
```

To use Ollama (local, no API cost):
```bash
# Start Ollama profile:
docker compose -f docker/docker-compose.yml --profile ollama up -d

# Pull a model inside the Ollama container:
docker exec -it $(docker compose -f docker/docker-compose.yml ps -q ollama) ollama pull llama3.1:8b
```

---

## Step 5 — First Functional Check

Run through these actions in order to verify all subsystems are working:

1. Register a new user account (or log in with existing credentials)
2. Navigate to **Discover Network** → enter a target CIDR (e.g. `172.28.10.0/24` for the lab network)
3. Wait for scan completion → verify hosts appear in the results table
4. Select one host → click **Deep Scan** → wait for port/service results
5. Click **AI Analysis** → verify a risk score is returned
6. Open the **AI Chat** → ask "What are the critical findings?" and verify a response
7. Click **Generate Report** → verify a PDF is created and downloadable

---

## Stop Services

```bash
docker compose -f docker/docker-compose.yml down
```

To also remove persisted data volumes (full reset):
```bash
docker compose -f docker/docker-compose.yml down -v
```

---

## Troubleshooting

### Port already in use

```
Error: address already in use :::3000
```

Find and stop the conflicting process:
```bash
# Linux / macOS:
lsof -i :3000
kill -9 <PID>

# Windows:
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

Affected ports: 3000 (UI/API), 3309 (MySQL), 8001 (FastAPI), 5433 (PostgreSQL), 11434 (Ollama).

### Docker permission denied (Linux)

```
permission denied while trying to connect to the Docker daemon socket
```

```bash
sudo usermod -aG docker $USER
newgrp docker
```

Log out and back in if `newgrp` is not enough.

### MySQL not ready yet

If `GET /api/health` returns `500` or connection errors right after startup, MySQL is still initializing:
```bash
docker compose -f docker/docker-compose.yml logs mysql-db | tail -20
# Wait until you see: ready for connections
```

Then retry the health endpoint.

### AI not responding / 503 on /api/v2

```bash
docker compose -f docker/docker-compose.yml logs security-api | tail -30
```

Common causes:
- Missing Python dependency inside the container (rebuild: `docker compose build security-api`)
- `OPENAI_API_KEY` not set or invalid
- Ollama container not running (if `AI_PROVIDER=ollama`)

### Windows PowerShell execution policy blocked

```
.\install.ps1 cannot be loaded because running scripts is disabled on this system
```

Open PowerShell **as Administrator** and run:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then re-run `.\install.ps1`.
