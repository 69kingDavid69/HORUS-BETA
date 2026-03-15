# HORUS — Documentación Completa (Español)

## 1. Qué es HORUS

HORUS es una plataforma de ciberseguridad ofensiva autónoma diseñada para la evaluación controlada de redes. Integra descubrimiento automatizado de red, escaneo profundo de puertos, pruebas de credenciales, análisis de riesgo con IA, transmisión de eventos en tiempo real, remediación automática y reportes ejecutivos en PDF, todo en un solo stack desplegable.

**Usar HORUS únicamente sobre redes y activos propios o con autorización escrita explícita. El escaneo o la prueba de credenciales no autorizados es ilegal.**

---

## 2. Características

| Característica | Descripción |
|---|---|
| Descubrimiento de Red | Enumera todos los hosts activos en un rango CIDR usando Nmap |
| Escaneo Profundo | Fingerprinting completo de puertos, servicios y sistema operativo vía scripts NSE de Nmap |
| Prueba de Credenciales | Fuerza bruta sobre servicios comunes (SSH, FTP, HTTP) con Hydra — con límite de tasa y detección de bloqueo |
| Puntuación de Riesgo IA | Puntaje de riesgo (0–100) y lista de remediación priorizada vía OpenAI u Ollama |
| Streaming en Tiempo Real | Hub de eventos WebSocket que transmite progreso de escaneos y alertas en vivo al navegador |
| Remediación Automática | Correcciones automatizadas con alcance a contenedores en objetivos de laboratorio en lista blanca |
| Reportes PDF | Generación de PDF de nivel ejecutivo con hallazgos, puntajes de riesgo y recomendaciones |
| Control de Acceso por Roles | Tres roles: admin, analyst, viewer — cada uno con permisos delimitados |
| Registro de Auditoría | Cada acción de usuario y evento del sistema se persiste en la tabla AuditLog |
| Visualización Globo 3D | Globo interactivo Three.js que muestra la topología de red y la actividad de escaneo |
| Asistente de Chat IA | Interfaz de preguntas y respuestas contextuales para consultar hallazgos y obtener recomendaciones |
| Entrega por Email | Envío de reportes directamente vía SMTP (Gmail, SendGrid o cualquier proveedor) |

---

## 3. Cómo Funciona (Flujo Completo)

```
Acción del usuario       Capa HORUS                  Qué ocurre
──────────────────────────────────────────────────────────────────────────────
1. Registro / Login    → auth.routes.js (Express)  → JWT emitido, roles cargados de BD
2. Enviar CIDR         → simulation.routes.js      → Trabajo encolado, docker exec → Kali/Nmap
                       → MySQL                     → Filas en Simulations + Hosts creadas
3. Escaneo Profundo    → simulation.routes.js      → Nmap NSE + Hydra sobre el host objetivo
                       → MySQL                     → Filas en Ports, Vulnerabilities, CredentialTests
4. Análisis IA         → ai.routes.js              → OpenAI / Ollama invocado con contexto de hallazgos
                       → MySQL                     → Fila en AIAnalysisResults (puntaje + recomendaciones)
5. Push WebSocket      → FastAPI EventHub          → Eventos en tiempo real a todas las pestañas abiertas
6. Actualización globo → globe.js (Three.js)       → Nodos y enlaces renderizados en el globo 3D
7. Generar reporte     → ai.routes.js / PDFKit     → PDF creado, opcionalmente enviado por email
                       → MySQL                     → Fila en Reports creada
8. Remediación         → FastAPI /api/v2/remediate → docker exec en contenedor de lab → fila en AuditLog
```

---

## 4. Arquitectura del Software

### Diagrama de comunicaciones

```
[Navegador]
    │
    ├── HTTP  ──────────────────────────────> [Express  :3000]
    │                                              │
    │   /api/auth          → auth.routes.js        │
    │   /api/simulations   → simulation.routes.js  ├── docker exec ──> [Contenedor Kali]
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
    └── HTTP ─────────────────────────────── [Ollama  :11434]  (perfil opcional)

[Express / FastAPI]
    └── HTTPS ────────────────────────────── [OpenAI API]      (opcional)
```

### Capas arquitectónicas

| Capa | Tecnología | Ubicación |
|---|---|---|
| Presentación | Vanilla JS SPA + Three.js | `FRONTED/frontend/` |
| API Gateway | Node.js + Express | `BACKEND/api/server.js` + `routes/` |
| Motor de Seguridad | Python + FastAPI | `BACKEND/api/main.py` |
| Orquestador IA | Módulo Python | `BACKEND/ai-orchestrator/` |
| Runtime de escaneo | Contenedor Kali Linux | `BACKEND/labs/kali/Dockerfile` |
| Base de datos primaria | MySQL 8 | Servicio Docker `mysql-db` |
| Base de datos auxiliar | PostgreSQL 16 | Servicio Docker `db` |
| Runtime IA local | Ollama | Servicio Docker `ollama` (perfil opcional) |

**Capa de presentación** — no requiere proceso de construcción (build). HTML/CSS/JS puro servido como archivos estáticos desde Express. Three.js gestiona el globo WebGL 3D.

**API Gateway (Express)** — gestiona autenticación JWT, middleware de aplicación de roles, enrutamiento de solicitudes, servicio de archivos estáticos y proxy HTTP hacia FastAPI para las rutas `/api/v2/*`.

**Motor de Seguridad (FastAPI)** — orquesta trabajos de escaneo de larga duración, aloja la cadena de inferencia ML, gestiona el hub de eventos WebSocket para difusión en tiempo real y ejecuta comandos de remediación automática.

**Orquestador IA** — paquete Python autónomo (`ai-orchestrator/engine/`) con `AnalysisEngine`, `RiskScorer`, `RemediationEngine` y `CorrelationRules`. Importado por FastAPI al inicio.

**Runtime de escaneo** — contenedor Docker Kali Linux con Nmap, Hydra y scripts NSE. Express activa escaneos vía `docker exec`. Aislado de la red del host; accesible solo a través de la red interna `lab_net` de Docker Compose.

---

## 5. Stack Tecnológico y Justificación

| Tecnología | Versión | Por qué se eligió |
|---|---|---|
| **Node.js + Express** | 18+ / 5.x | Las operaciones I/O-bound (proxy, JWT, consultas BD) son la fortaleza de Node. Contexto JS compartido con el equipo de frontend. El ecosistema npm cubre necesidades de PDF, email y SDK de OpenAI. |
| **Python + FastAPI** | 3.9+ | Framework async-nativo ideal para coordinación de escaneos de larga duración. Python domina el ecosistema de herramientas ML y seguridad (scikit-learn, pydantic, paramiko). Pydantic aplica validación estricta de solicitudes en la frontera. |
| **MySQL 8** | 8.0 | El cumplimiento ACID es crítico para registros de auditoría y escaneos. Herramientas maduras para migraciones de esquema. JOINs eficientes entre hosts, puertos, vulnerabilidades y hallazgos. |
| **PostgreSQL 16** | 16 | Pairing nativo con FastAPI/SQLAlchemy. Usado por componentes ML para consultas auxiliares estructuradas. Soporte futuro de extensiones (JSONB, índices parciales). |
| **Contenedor Kali Linux** | rolling | SO de seguridad ofensiva estándar de la industria. Incluye Nmap, Hydra, scripts NSE y listas de palabras. El aislamiento en contenedor mantiene las herramientas alejadas del host y garantiza reproducibilidad en cualquier máquina. |
| **Docker Compose** | plugin v2 | Un solo comando levanta 6+ servicios con red, volúmenes y orden de dependencias correctos. El sistema de perfiles (`--profile ollama`, `--profile training`) mantiene los servicios opcionales fuera del stack predeterminado. |
| **Three.js** | r128 | Renderizado 3D WebGL acelerado por hardware sin framework pesado. Bundle pequeño, suficiente para el globo de topología de red. No requiere pipeline de construcción. |
| **Abstracción OpenAI / Ollama** | — | Despliegues sin acceso a internet o con restricciones de costo usan Ollama; producción usa OpenAI. La misma ruta de código se usa para ambos — solo cambia la variable de entorno `AI_PROVIDER`. |
| **PDFKit + Puppeteer** | latest | PDFKit para construcción programática de PDF de bajo nivel. Puppeteer para renderizado HTML-a-PDF cuando se necesita una maquetación rica. Ambos corren dentro de Docker para evitar dependencias binarias en el host. |
| **Nodemailer** | 6.x | Cliente SMTP probado en producción. Funciona con contraseñas de aplicación Gmail, SendGrid y cualquier relay SMTP sin infraestructura adicional. |
| **Frontend Vanilla HTML/CSS/JS** | — | Sin toolchain de construcción (sin Webpack, Vite ni bundler). Iteración instantánea, despliegue trivial y sin vulnerabilidades por dependencias transitivas de frameworks frontend. |

---

## 6. Alcance del Sistema

### Lo que HORUS cubre
- **Pruebas de penetración controladas** en redes internas en laboratorios o entornos empresariales autorizados
- **Descubrimiento de vulnerabilidades** mediante escaneo activo (Nmap NSE, detección de versiones, fingerprinting de SO)
- **Evaluación de exposición de credenciales** en servicios como SSH, FTP y autenticación básica HTTP
- **Priorización de riesgos** usando puntajes generados por IA y recomendaciones de remediación
- **Formación en concienciación de seguridad** en entornos de laboratorio aislados con contenedores vulnerables intencionalmente
- **Documentación de auditoría y cumplimiento** vía la tabla AuditLog y artefactos de reportes PDF

### Lo que HORUS NO cubre
- Detección (IDS) o prevención (IPS) de intrusiones en tiempo real — HORUS es una herramienta de evaluación ofensiva, no un monitor defensivo pasivo
- Pruebas de seguridad de aplicaciones web (sin DAST/SAST, sin escáner de inyección SQL)
- Escaneo de infraestructura en la nube (APIs de AWS, GCP, Azure)
- Monitoreo continuo en producción — los escaneos son bajo demanda, no pasivos
- Mapeo de frameworks de cumplimiento (PCI-DSS, SOC 2, ISO 27001) — los reportes son informativos, no certificados de cumplimiento

### Audiencia objetivo
- PyMEs que necesitan evaluación de seguridad de nivel enterprise sin equipos de seguridad dedicados
- Estudiantes y formadores en ciberseguridad que trabajan en entornos de laboratorio controlados
- Pentesters ejecutando compromisos estructurados sobre objetivos autorizados

---

## 7. Modelo de Datos

Esquema: `BACKEND/database/schema.mysql.sql`

| Tabla | Propósito |
|---|---|
| `Users` | Cuentas (email, nombre de usuario, contraseña hasheada) |
| `UserProfiles` | Información extendida (cédula, teléfono, país, ciudad) |
| `Roles` | Definiciones de rol (admin, analyst, viewer) |
| `UserRoles` | Asignaciones muchos-a-muchos usuario/rol |
| `Simulations` | Trabajos de escaneo (tipo, objetivo, estado, comando Nmap) |
| `Hosts` | Hosts descubiertos (IP, MAC, hostname, SO) |
| `Ports` | Puertos abiertos por host (puerto, protocolo, servicio, versión) |
| `Vulnerabilities` | CVEs y problemas encontrados por puerto/host |
| `CredentialTests` | Resultados de Hydra (servicio, usuario, contraseña, éxito) |
| `Reports` | Artefactos PDF generados (ruta, created_at) |
| `AuditLog` | Rastro completo de acciones (usuario, acción, objetivo, timestamp) |
| `AIAnalysisResults` | Puntajes de riesgo y recomendaciones de IA por simulación |

---

## 8. Instalación

Instrucciones detalladas paso a paso: `docs/español/INICIO_RAPIDO.md`

Referencia rápida:
- Linux / macOS: `./install.sh`
- Windows PowerShell: `.\install.ps1`
- Windows CMD: `install.bat`

---

## 9. Configuración Esencial

Archivo: `BACKEND/api/.env` (copiar desde `BACKEND/api/.env.example`)

```env
# Base de datos
DB_HOST=127.0.0.1
DB_PORT=3309
DB_USER=horus_app
DB_PASSWORD=CAMBIAR_ESTO
DB_NAME=horus_db

# Proveedor IA — elegir uno
AI_PROVIDER=openai
OPENAI_API_KEY=sk-tu-clave
OPENAI_MODEL=gpt-4o-mini

# Proveedor IA — alternativa local
# AI_PROVIDER=ollama
# OLLAMA_BASE_URL=http://host.docker.internal:11434
# OLLAMA_MODEL=llama3.1:8b

# Email (opcional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu@email.com
SMTP_PASSWORD=tu-contrasena-de-aplicacion
SMTP_FROM=tu@email.com
```

Puertos por defecto:

| Servicio | Puerto |
|---|---|
| UI + API Node | 3000 |
| Motor de seguridad FastAPI | 8001 |
| MySQL | 3309 |
| PostgreSQL | 5433 |
| Ollama (opcional) | 11434 |

---

## 10. Checklist de Producción

- Nunca hacer commit de archivos `.env` ni claves API al repositorio
- Establecer `ALLOW_PUBLIC_TARGETS=false` y definir `AUTHORIZED_TARGETS` en producción
- Publicar todos los servicios detrás de un proxy inverso HTTPS (nginx, Caddy)
- Monitorear `GET /api/health` y la tabla `AuditLog`
- Respaldar el volumen MySQL (`mysql_data`) y el volumen de artefactos (`workspace`)
- Rotar `OPENAI_API_KEY` y contraseñas de base de datos periódicamente
- Mantener imágenes Docker actualizadas: `docker compose pull && docker compose up -d`

---

## 11. Solución de Problemas

| Problema | Solución |
|---|---|
| `GET /api/health` retorna 502 | FastAPI aún no está listo — esperar 15s y reintentar, o revisar `docker compose logs security-api` |
| `GET /api/v2/risk-score` retorna 503 | AnalysisEngine falló al cargar — revisar dependencias Python dentro del contenedor |
| Error de configuración Compose | Ejecutar `docker compose -f docker/docker-compose.yml config` para validar el YAML |
| IA no responde | Verificar `AI_PROVIDER`, `OPENAI_API_KEY` o estado del contenedor Ollama |
| Tras cambiar proveedor IA | `docker compose -f docker/docker-compose.yml up -d --force-recreate scanner-api` |

---

## 12. Seguridad y Uso Legal

HORUS incluye capacidades de seguridad ofensiva controladas (escaneo activo, fuerza bruta de credenciales, remediación automática). Su uso está permitido únicamente en:
- Redes y sistemas propios
- Sistemas sobre los cuales se cuenta con autorización escrita explícita

El uso no autorizado puede violar la Ley 1273 de 2009 (Colombia), el Convenio de Budapest sobre Ciberdelincuencia y legislación equivalente en otros países.
