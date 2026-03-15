# HORUS — Full Documentation (English)

## 1. What is HORUS

HORUS is an autonomous offensive cybersecurity platform designed for controlled network assessment. It combines automated network discovery, deep port scanning, credential testing, AI-powered risk analysis, real-time event streaming, auto-remediation, and executive PDF reporting in a single deployable stack.

**Use HORUS only on networks and assets you own or have explicit written authorization to test. Unauthorized scanning or credential testing is illegal.**

---

## 2. Features

| Feature | Description |
|---|---|
| Network Discovery | Enumerate all live hosts in a CIDR range using Nmap |
| Deep Scan | Full port/service/OS fingerprinting on a specific host via Nmap NSE scripts |
| Credential Testing | Brute-force common services (SSH, FTP, HTTP) with Hydra — rate-limited and lockout-aware |
| AI Risk Scoring | Automatic risk score (0–100) and prioritized remediation list via OpenAI or Ollama |
| Real-time Streaming | WebSocket-based event hub pushes scan progress and alerts live to the browser |
| Auto-Remediation | Container-scoped automated fixes on whitelisted lab targets |
| PDF Reports | Executive-grade PDF generation with findings, risk scores, and recommendations |
| Role-Based Access | Three roles: admin, analyst, viewer — each with scoped permissions |
| Audit Log | Every user action and system event is persisted in the AuditLog table |
| 3D Globe Visualization | Interactive Three.js globe showing network topology and scan activity |
| AI Chat Assistant | Contextual Q&A interface to query findings, ask for explanations, and get recommendations |
| Email Delivery | Send reports directly via SMTP (Gmail, SendGrid, or any provider) |

---

## 3. How it Works (End-to-End Flow)

```
User action            HORUS layer              What happens
─────────────────────────────────────────────────────────────────────────────
1. Register / Login  → Express auth.routes.js → JWT issued, roles loaded from DB
2. Submit CIDR       → simulation.routes.js   → Job queued, docker exec → Kali/Nmap
                     → MySQL                  → Simulation + Hosts rows created
3. Deep Scan         → simulation.routes.js   → Nmap NSE + Hydra on target host
                     → MySQL                  → Ports, Vulnerabilities, CredentialTests rows
4. AI Analysis       → ai.routes.js           → OpenAI / Ollama called with findings context
                     → MySQL                  → AIAnalysisResults row (score + recommendations)
5. WebSocket push    → FastAPI EventHub        → Real-time events broadcast to all open tabs
6. Globe update      → globe.js (Three.js)     → Nodes and links rendered on 3D globe
7. Generate report   → ai.routes.js / PDFKit   → PDF artifact created, optionally emailed
                     → MySQL                  → Reports row created
8. Remediation       → FastAPI /api/v2/remediate → docker exec on lab container → AuditLog row
```

---

## 4. Software Architecture

### Communication diagram

```
[Browser]
    │
    ├── HTTP  ──────────────────────────────> [Express  :3000]
    │                                              │
    │   /api/auth          → auth.routes.js        │
    │   /api/simulations   → simulation.routes.js  ├── docker exec ──> [Kali container]
    │   /api/ai            → ai.routes.js          │                       ├── nmap
    │   /api/admin         → admin.routes.js       │                       └── hydra
    │   /api/v2/*  proxy   ──────────────────────> │
    │                                         [FastAPI  :8001]
    │                                              │
    │                                              ├── AnalysisEngine
    │                                              ├── RiskScorer
    │                                              ├── RemediationEngine
    │                                              ├── CorrelationRules
    │                                              └── WebSocket EventHub
    │
    └── WebSocket ──────────────────────────> [FastAPI EventHub  :8001/ws]

[Express / FastAPI]
    ├── mysql2  ──────────────────────────── [MySQL 8  :3309]
    └── psycopg ──────────────────────────── [PostgreSQL 16  :5433]

[FastAPI]
    └── HTTP ─────────────────────────────── [Ollama  :11434]  (optional profile)

[Express / FastAPI]
    └── HTTPS ────────────────────────────── [OpenAI API]      (optional)
```

### Architectural layers

| Layer | Technology | Location |
|---|---|---|
| Presentation | Vanilla JS SPA + Three.js | `FRONTED/frontend/` |
| API Gateway | Node.js + Express | `BACKEND/api/server.js` + `routes/` |
| Security Engine | Python + FastAPI | `BACKEND/api/main.py` |
| AI Orchestrator | Python module | `BACKEND/ai-orchestrator/` |
| Scanner runtime | Kali Linux container | `BACKEND/labs/kali/Dockerfile` |
| Primary database | MySQL 8 | Docker service `mysql-db` |
| Auxiliary database | PostgreSQL 16 | Docker service `db` |
| Local AI runtime | Ollama | Docker service `ollama` (optional profile) |

**Presentation layer** — no build step required. Pure HTML/CSS/JS served as static files from Express. Three.js handles the 3D WebGL globe.

**API Gateway (Express)** — handles JWT authentication, role enforcement middleware, request routing, static file serving, and HTTP proxy forwarding of `/api/v2/*` requests to FastAPI.

**Security Engine (FastAPI)** — orchestrates long-running scan jobs, hosts the ML inference pipeline, manages the WebSocket event hub for real-time broadcasting, and executes auto-remediation commands.

**AI Orchestrator** — standalone Python package (`ai-orchestrator/engine/`) containing `AnalysisEngine`, `RiskScorer`, `RemediationEngine`, and `CorrelationRules`. Imported by FastAPI at startup.

**Scanner runtime** — a Kali Linux Docker container with Nmap, Hydra, and NSE scripts. Express triggers scans via `docker exec`. Isolated from the host network; only reachable through the Docker Compose internal network `lab_net`.

---

## 5. Technology Stack and Justification

| Technology | Version | Why it was chosen |
|---|---|---|
| **Node.js + Express** | 18+ / 5.x | I/O-bound workload (proxying, JWT, DB queries) is Node's strength. Shared JS context with the frontend team. Rich npm ecosystem covers PDF, email, and OpenAI SDK needs. |
| **Python + FastAPI** | 3.9+ / 0.x | Async-native framework ideal for long-running scan coordination. Python dominates the ML/security tooling ecosystem (scikit-learn, pydantic, paramiko). Pydantic enforces strict request validation at the boundary. |
| **MySQL 8** | 8.0 | ACID compliance is critical for audit logs and scan records. Mature tooling for schema migrations. Efficient multi-table JOINs for correlating hosts, ports, vulnerabilities, and findings. |
| **PostgreSQL 16** | 16 | FastAPI/SQLAlchemy native pairing. Used by ML components for structured auxiliary queries. Provides future extension support (JSONB, partial indexes). |
| **Kali Linux container** | rolling | Industry-standard offensive security OS. Pre-packages Nmap, Hydra, NSE scripts, and wordlists. Container isolation keeps tools away from the host OS and provides clean reproducibility across machines. |
| **Docker Compose** | v2 plugin | Single command brings up 6+ services with correct networking, volumes, and dependency ordering. Profile system (`--profile ollama`, `--profile training`) keeps optional services out of the default stack. |
| **Three.js** | r128 | Hardware-accelerated WebGL 3D rendering without a heavyweight framework. Small bundle, sufficient for network topology globe. No build pipeline required. |
| **OpenAI / Ollama abstraction** | — | Air-gapped or cost-sensitive deployments switch to Ollama; production defaults to OpenAI. The same code path is used for both — only the `AI_PROVIDER` environment variable changes. |
| **PDFKit + Puppeteer** | latest | PDFKit for programmatic low-level PDF construction. Puppeteer for HTML-to-PDF rendering when rich layout is needed. Both run inside Docker to avoid host binary dependencies. |
| **Nodemailer** | 6.x | Battle-tested SMTP client. Works with Gmail app passwords, SendGrid, and any SMTP relay without additional infrastructure. |
| **Vanilla HTML/CSS/JS frontend** | — | Zero build toolchain (no Webpack, Vite, or bundler). Instant iteration, trivial deployment, and no transitive dependency vulnerabilities from frontend frameworks. |

---

## 6. System Scope

### What HORUS covers
- **Controlled penetration testing** of internal networks in lab or authorized enterprise environments
- **Vulnerability discovery** through active scanning (Nmap NSE, version detection, OS fingerprinting)
- **Credential exposure assessment** on services like SSH, FTP, and HTTP basic auth
- **Risk prioritization** using AI-generated scores and remediation recommendations
- **Security awareness training** in isolated lab environments with intentionally vulnerable containers
- **Audit and compliance documentation** via the AuditLog table and PDF report artifacts

### What HORUS does NOT cover
- Real-time intrusion detection (IDS) or prevention (IPS) — HORUS is an offensive assessment tool, not a defensive monitor
- Web application security testing (no DAST/SAST, no SQL injection scanner)
- Cloud infrastructure scanning (AWS, GCP, Azure APIs)
- Continuous production monitoring — scans are on-demand, not passive
- Compliance frameworks mapping (PCI-DSS, SOC 2, ISO 27001) — reports are informational, not compliance-certified

### Target audience
- SMBs that need enterprise-grade security assessment without dedicated security teams
- Cybersecurity students and trainers working in controlled lab environments
- Pentesters running structured engagements on authorized targets

---

## 7. Database Model

Schema: `BACKEND/database/schema.mysql.sql`

| Table | Purpose |
|---|---|
| `Users` | Accounts (email, username, hashed password) |
| `UserProfiles` | Extended info (ID, phone, country, city) |
| `Roles` | Role definitions (admin, analyst, viewer) |
| `UserRoles` | Many-to-many user/role assignments |
| `Simulations` | Scan jobs (type, target, status, Nmap command) |
| `Hosts` | Discovered hosts (IP, MAC, hostname, OS) |
| `Ports` | Open ports per host (port, protocol, service, version) |
| `Vulnerabilities` | CVEs and issues found per port/host |
| `CredentialTests` | Hydra results (service, username, password, success) |
| `Reports` | Generated PDF artifacts (path, created_at) |
| `AuditLog` | Full action trail (user, action, target, timestamp) |
| `AIAnalysisResults` | Risk scores and AI recommendations per simulation |

---

## 8. Installation

Detailed step-by-step instructions: `docs/english/QUICK_START.md`

Quick reference:
- Linux / macOS: `./install.sh`
- Windows PowerShell: `.\install.ps1`
- Windows CMD: `install.bat`

---

## 9. Essential Configuration

File: `BACKEND/api/.env` (copy from `BACKEND/api/.env.example`)

```env
# Database
DB_HOST=127.0.0.1
DB_PORT=3309
DB_USER=horus_app
DB_PASSWORD=CHANGE_ME
DB_NAME=horus_db

# AI provider — choose one
AI_PROVIDER=openai
OPENAI_API_KEY=sk-your-key
OPENAI_MODEL=gpt-4o-mini

# AI provider — local alternative
# AI_PROVIDER=ollama
# OLLAMA_BASE_URL=http://host.docker.internal:11434
# OLLAMA_MODEL=llama3.1:8b

# Email (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your@email.com
```

Default service ports:

| Service | Port |
|---|---|
| UI + Node API | 3000 |
| FastAPI security engine | 8001 |
| MySQL | 3309 |
| PostgreSQL | 5433 |
| Ollama (optional) | 11434 |

---

## 10. Production Checklist

- Never commit `.env` files or API keys to version control
- Set `ALLOW_PUBLIC_TARGETS=false` and define `AUTHORIZED_TARGETS` for production
- Place all services behind an HTTPS reverse proxy (nginx, Caddy)
- Monitor `GET /api/health` and the `AuditLog` table
- Back up the MySQL volume (`mysql_data`) and report artifacts volume (`workspace`)
- Rotate `OPENAI_API_KEY` and database passwords regularly
- Keep Docker images updated: `docker compose pull && docker compose up -d`

---

## 11. Troubleshooting

| Problem | Solution |
|---|---|
| `GET /api/health` returns 502 | FastAPI not ready yet — wait 15s and retry, or check `docker compose logs security-api` |
| `GET /api/v2/risk-score` returns 503 | AnalysisEngine failed to load — check Python deps inside container |
| Compose config error | Run `docker compose -f docker/docker-compose.yml config` to validate YAML |
| AI not responding | Verify `AI_PROVIDER`, `OPENAI_API_KEY`, or Ollama container status |
| After changing AI provider | `docker compose -f docker/docker-compose.yml up -d --force-recreate scanner-api` |

---

## 12. Legal and Safety

HORUS includes controlled offensive security capabilities (active scanning, credential brute-force, auto-remediation). Use is permitted only on:
- Networks and systems you own
- Systems for which you hold explicit written authorization

Unauthorized use may violate the Computer Fraud and Abuse Act (USA), the Budapest Convention on Cybercrime, and equivalent national laws.
