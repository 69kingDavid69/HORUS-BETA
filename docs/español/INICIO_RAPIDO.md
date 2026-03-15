# HORUS — Guía de Inicio Rápido (Español)

Esta guía cubre tres formas de poner HORUS en funcionamiento: mediante el script instalador (más rápido), manualmente paso a paso, y mediante el ejecutable empaquetado. Las tres opciones llevan al mismo resultado: todos los servicios activos y la interfaz accesible en `http://localhost:3000`.

---

## Requisitos Previos

Las siguientes herramientas deben estar instaladas antes de comenzar.

| Herramienta | Versión mínima | Comando de verificación |
|---|---|---|
| Git | cualquiera | `git --version` |
| Node.js | 18.x | `node --version` |
| npm | 9.x | `npm --version` |
| Docker | 20.x | `docker --version` |
| Docker Compose | plugin v2 o v1 standalone | `docker compose version` |
| Python 3 | 3.9+ (opcional, solo para desarrollo local de FastAPI) | `python3 --version` |

### Instalar los requisitos previos

**Node.js (recomendado vía nvm):**
```bash
# Linux / macOS
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc   # o ~/.zshrc
nvm install 18
nvm use 18
node --version     # debe mostrar v18.x.x
```

**Node.js (Windows — vía nvm-windows):**
Descargar el instalador desde https://github.com/coreybutler/nvm-windows/releases, luego:
```powershell
nvm install 18
nvm use 18
node --version
```

**Docker:**
- Linux: seguir https://docs.docker.com/engine/install/
- macOS / Windows: instalar Docker Desktop desde https://www.docker.com/products/docker-desktop/

Tras instalar Docker en Linux, agregar el usuario al grupo docker para evitar usar sudo:
```bash
sudo usermod -aG docker $USER
newgrp docker               # aplicar sin cerrar sesión
docker run hello-world      # verificar
```

---

## Paso 1 — Clonar el Repositorio

```bash
git clone https://github.com/69kingDavid69/back-integrative-project.git
cd back-integrative-project
```

Verificar que estás en la rama correcta:
```bash
git branch       # debe mostrar * develop o * main
git log --oneline -5
```

---

## Paso 2 — Configurar el Entorno

Copiar la plantilla de entorno y completar los valores requeridos:

```bash
cp BACKEND/api/.env.example BACKEND/api/.env
```

Abrir `BACKEND/api/.env` en cualquier editor de texto y establecer como mínimo:

```env
# ── Base de datos ──────────────────────────────────────────────────────────────
DB_HOST=127.0.0.1
DB_PORT=3309          # Docker mapea MySQL a este puerto del host
DB_USER=horus_app
DB_PASSWORD=CAMBIAR_ESTO   # usar una contraseña fuerte
DB_NAME=horus_db

# ── Proveedor IA (elegir un bloque) ───────────────────────────────────────────
# Opción A — OpenAI (nube, requiere clave API):
AI_PROVIDER=openai
OPENAI_API_KEY=sk-tu-clave-aqui
OPENAI_MODEL=gpt-4o-mini

# Opción B — Ollama (local, sin clave API):
# AI_PROVIDER=ollama
# OLLAMA_BASE_URL=http://host.docker.internal:11434
# OLLAMA_MODEL=llama3.1:8b

# ── Email (opcional, solo para entrega de reportes por correo) ─────────────────
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu@gmail.com
SMTP_PASSWORD=tu-contrasena-de-aplicacion-gmail
SMTP_FROM=tu@gmail.com
```

> Para generar una Contraseña de Aplicación de Gmail: Cuenta de Google → Seguridad → Verificación en 2 pasos → Contraseñas de aplicaciones.

---

## Opción A — Script Instalador (Recomendado)

El script instalador automatiza todos los pasos restantes: verifica requisitos, instala dependencias de Node y Python, y levanta todos los servicios Docker.

**Linux o macOS:**
```bash
chmod +x install.sh
./install.sh
```

**Windows PowerShell:**
```powershell
# Si la política de ejecución bloquea el script, ejecutar esto una vez:
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

.\install.ps1
```

**Windows Símbolo del sistema (CMD):**
```cmd
install.bat
```

### Qué hace el instalador, paso a paso

| Paso | Qué ocurre |
|---|---|
| Paso 1/5 — Verificación de requisitos | Verifica que Node.js, npm, Docker y Docker Compose estén instalados y cumplan las versiones mínimas |
| Paso 2/5 — Dependencias Node | Ejecuta `npm install` dentro de `BACKEND/api/` — instala Express, MySQL2, OpenAI, PDFKit, Puppeteer, etc. |
| Paso 3/5 — Entorno Python | Crea un virtualenv en `BACKEND/api/.venv` e instala `requirements-unified.txt` (FastAPI, pydantic, scikit-learn, etc.) |
| Paso 4/5 — Build de Docker | Ejecuta `docker compose -f docker/docker-compose.yml build` — construye la imagen del escáner Kali y la imagen de FastAPI |
| Paso 5/5 — Inicio de Docker | Ejecuta `docker compose -f docker/docker-compose.yml up -d` — levanta todos los servicios en segundo plano |

El script muestra estado con colores. Un `[✔]` verde indica éxito; un `[✘]` rojo indica que el paso falló y el script termina con el mensaje de error.

---

## Opción B — Manual Paso a Paso

Usar esta opción si se desea control total sobre cada paso, o si el script instalador falla y es necesario depurar.

### B1. Instalar dependencias Node

```bash
cd BACKEND/api
npm install
cd ../..
```

Esto instala (entre otros):
- `express` — framework web y servidor HTTP
- `mysql2` — driver de base de datos MySQL
- `openai` — SDK de OpenAI
- `pdfkit` + `puppeteer` — generación de PDF
- `nodemailer` — entrega de email
- `cors`, `dotenv`, `ip-cidr`, `xml2js` — librerías utilitarias

### B2. Instalar dependencias Python (opcional — solo para desarrollo local de FastAPI)

Si se planea ejecutar FastAPI fuera de Docker:
```bash
cd BACKEND/api
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows
pip install -r requirements-unified.txt
cd ../..
```

Si solo se usa Docker (opción por defecto), omitir este paso — las dependencias Python se instalan dentro del contenedor automáticamente.

### B3. Construir las imágenes Docker

```bash
docker compose -f docker/docker-compose.yml build
```

Esto construye:
- `scanner-api` — API Express Node.js (Dockerfile.scanner)
- `security-api` — FastAPI + motor ML (Dockerfile.fastapi)
- `kali-scanner` — Runtime de escaneo Kali Linux (BACKEND/labs/kali/Dockerfile)

Las imágenes se almacenan en caché tras la primera construcción. Las siguientes construcciones solo reconstruyen las capas que cambiaron.

### B4. Iniciar todos los servicios

```bash
docker compose -f docker/docker-compose.yml up -d
```

Servicios iniciados:
| Contenedor | Rol | Puerto |
|---|---|---|
| `scanner-api` | API Express Node.js + UI estático | 3000 |
| `kali-scanner` | Runner de escaneo Nmap / Hydra | solo interno |
| `mysql-db` | Base de datos MySQL 8 | 3309 |
| `security-api` | Motor de seguridad FastAPI | 8001 |
| `db` | Base de datos auxiliar PostgreSQL | 5433 |

La inicialización de MySQL tarda 20–30 segundos en el primer arranque (importación del esquema). Esperar antes de hacer consultas al endpoint de salud.

### B5. Verificar que todos los contenedores están activos

```bash
docker compose -f docker/docker-compose.yml ps
```

Todos los contenedores deben mostrar `Up` o `healthy`. Luego verificar el API:
```bash
curl -sS http://localhost:3000/api/health
# Esperado: {"status":"ok"}

curl -sS http://localhost:3000/api/v2/risk-score
# Esperado: JSON con datos de riesgo o estado vacío
```

---

## Opción C — Ejecutable Empaquetado

Los scripts instaladores (`install.sh`, `install.ps1`, `install.bat`) son ejecutables autocontenidos que aprovisionan HORUS completamente desde cero. Son la forma distribuible ejecutable de la aplicación.

### Linux / macOS

```bash
# Dar permisos de ejecución (solo la primera vez):
chmod +x install.sh

# Ejecutar:
./install.sh
```

El script es un programa bash autónomo — sin dependencias más allá de bash, que viene preinstalado en todos los sistemas Linux y macOS.

### Windows — Ejecutable PowerShell

Clic derecho sobre `install.ps1` y seleccionar **"Ejecutar con PowerShell"**, o desde una terminal PowerShell:

```powershell
.\install.ps1
```

Si Windows bloquea la ejecución por política de seguridad, ejecutar esto una vez en una PowerShell de administrador:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Windows — Ejecutable CMD

Doble clic en `install.bat` desde el Explorador de Archivos, o desde el Símbolo del sistema:
```cmd
install.bat
```

### Qué ocurre tras ejecutar el instalador

1. Todas las imágenes Docker se construyen y quedan en caché localmente
2. Todos los contenedores se inician en segundo plano
3. El esquema de base de datos se inicializa
4. La terminal muestra: `HORUS is running at http://localhost:3000`

### Actualizar a una nueva versión

```bash
git pull origin develop        # o main
./install.sh                   # volver a ejecutar el instalador — reconstruirá solo lo que cambió
```

El instalador es idempotente: volver a ejecutarlo sobre una instalación existente reconstruye solo lo que cambió y reinicia los servicios afectados.

---

## Paso 3 — Abrir la Aplicación

Navegar a: **http://localhost:3000**

Se verá la landing page de HORUS. Hacer clic en **Prueba Gratis** o **Iniciar Sesión** para entrar a la aplicación.

---

## Paso 4 — Configurar Proveedor IA (Opcional)

Para cambiar el proveedor de IA tras la instalación inicial, editar `BACKEND/api/.env` y luego reiniciar el contenedor API:

```bash
docker compose -f docker/docker-compose.yml up -d --force-recreate scanner-api
```

Para usar Ollama (local, sin costo de API):
```bash
# Iniciar perfil Ollama:
docker compose -f docker/docker-compose.yml --profile ollama up -d

# Descargar un modelo dentro del contenedor Ollama:
docker exec -it $(docker compose -f docker/docker-compose.yml ps -q ollama) ollama pull llama3.1:8b
```

---

## Paso 5 — Primera Verificación Funcional

Ejecutar estas acciones en orden para verificar que todos los subsistemas funcionan:

1. Registrar una nueva cuenta de usuario (o iniciar sesión con credenciales existentes)
2. Navegar a **Descubrir Red** → ingresar un CIDR objetivo (ej. `172.28.10.0/24` para la red del laboratorio)
3. Esperar la finalización del escaneo → verificar que los hosts aparecen en la tabla de resultados
4. Seleccionar un host → clic en **Escaneo Profundo** → esperar resultados de puertos/servicios
5. Clic en **Análisis IA** → verificar que se retorna un puntaje de riesgo
6. Abrir el **Chat IA** → preguntar "¿Cuáles son los hallazgos críticos?" y verificar respuesta
7. Clic en **Generar Reporte** → verificar que se crea un PDF descargable

---

## Detener Servicios

```bash
docker compose -f docker/docker-compose.yml down
```

Para también eliminar los volúmenes de datos persistidos (reset completo):
```bash
docker compose -f docker/docker-compose.yml down -v
```

---

## Solución de Problemas

### Puerto ya en uso

```
Error: address already in use :::3000
```

Encontrar y detener el proceso que ocupa el puerto:
```bash
# Linux / macOS:
lsof -i :3000
kill -9 <PID>

# Windows:
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

Puertos afectados: 3000 (UI/API), 3309 (MySQL), 8001 (FastAPI), 5433 (PostgreSQL), 11434 (Ollama).

### Permiso denegado en Docker (Linux)

```
permission denied while trying to connect to the Docker daemon socket
```

```bash
sudo usermod -aG docker $USER
newgrp docker
```

Cerrar sesión y volver a entrar si `newgrp` no es suficiente.

### MySQL aún no está listo

Si `GET /api/health` retorna `500` o errores de conexión justo después del inicio, MySQL todavía está inicializando:
```bash
docker compose -f docker/docker-compose.yml logs mysql-db | tail -20
# Esperar hasta ver: ready for connections
```

Luego reintentar el endpoint de salud.

### IA no responde / 503 en /api/v2

```bash
docker compose -f docker/docker-compose.yml logs security-api | tail -30
```

Causas comunes:
- Dependencia Python faltante dentro del contenedor (reconstruir: `docker compose build security-api`)
- `OPENAI_API_KEY` no configurada o inválida
- Contenedor Ollama no activo (si `AI_PROVIDER=ollama`)

### PowerShell de Windows bloquea la ejecución

```
.\install.ps1 no se puede cargar porque la ejecución de scripts está deshabilitada en este sistema
```

Abrir PowerShell **como Administrador** y ejecutar:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Luego volver a ejecutar `.\install.ps1`.
