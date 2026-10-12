# Developer Getting Started & Local Environment Setup

This guide takes a new engineer from a fresh repository clone to a fully operating local development environment running the frontend, backend, PostgreSQL database, and Dockerized security scanners.

---

## 1. System Prerequisites

Ensure your host machine satisfies these baseline requirements:

| Tool | Minimum Version | Verification Command | Purpose |
| :--- | :--- | :--- | :--- |
| **Rust** | `1.85.0+` (stable) | `rustc --version` | Compiling Axum backend & agents |
| **Cargo** | `1.85.0+` | `cargo --version` | Rust dependency management & builds |
| **Node.js** | `20.18.0+` (LTS) | `node --version` | Running frontend dev server & tests |
| **npm** | `10.8.0+` | `npm --version` | Managing frontend npm dependencies |
| **Docker** | `24.0.0+` | `docker --version` | Executing sandboxed scanner containers |
| **PostgreSQL**| `16.0+` | `psql --version` | Relational database (or use Docker) |
| **Git** | `2.40.0+` | `git --version` | Version control & repo clone operations |

> [!IMPORTANT]
> **Docker Daemon Permission**: The user running FireCrow must have permission to interact with the Docker daemon without `sudo` (i.e. your user must belong to the `docker` group, or Docker Desktop must be running). Verify with `docker ps`.

---

## 2. Automated Quickstart (`./scripts/dev.sh`)

FireCrow provides an automated developer launcher script at `scripts/dev.sh` that checks system prerequisites, configures local environment variables, initializes the PostgreSQL container, applies migrations, pulls scanner images, and boots both frontend and backend services in parallel.

```bash
# 1. Clone repository
git clone https://github.com/johan-droid/Fire-Crow-.git
cd Fire-Crow-

# 2. Make script executable and run launcher
chmod +x scripts/dev.sh
./scripts/dev.sh
```

### Dev Launcher Flags
- `./scripts/dev.sh`: Starts Postgres, Backend (port 8080), and Frontend (port 5173).
- `./scripts/dev.sh --skip-pull`: Skips pulling scanner Docker images if already cached locally.
- `./scripts/dev.sh --clean`: Cleans existing Docker containers and temporary `/tmp/firecrow` workspaces before launching.

To verify the developer launcher non-interactively, run the test script:
```bash
./scripts/test-dev.sh
```

---

## 3. Manual Step-by-Step Setup

If you prefer to configure and launch each subsystem independently:

### Step A: Configure PostgreSQL
Start a local PostgreSQL 16 instance (via Docker or local package manager):
```bash
docker run -d \
  --name firecrow-postgres \
  -e POSTGRES_DB=firecrow \
  -e POSTGRES_USER=firecrow_user \
  -e POSTGRES_PASSWORD=firecrow_secret \
  -p 5432:5432 \
  postgres:16-alpine
```

Apply database migrations:
```bash
# Apply schema and lifecycle triggers
psql postgresql://firecrow_user:firecrow_secret@localhost:5432/firecrow \
  -f backend/migrations/001_initial_schema.sql
```

### Step B: Cache Scanner Docker Images
Pull the exact pinned versions of the tri-engine scanner suite:
```bash
docker pull ghcr.io/gitleaks/gitleaks:v8.18.4
docker pull semgrep/semgrep:1.96.0
docker pull ghcr.io/google/osv-scanner:v2.2.4
```

### Step C: Configure Backend Environment
Create `backend/.env`:
```env
PORT=8080
HOST=127.0.0.1
DATABASE_URL=postgresql://firecrow_user:firecrow_secret@localhost:5432/firecrow
SESSION_SECRET=dev-session-secret-must-be-at-least-32-chars-long-abc123
JWT_SECRET=dev-jwt-secret-must-be-at-least-32-chars-long-xyz789
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
DOCKER_SOCKET=/var/run/docker.sock
WORK_DIR=/tmp/firecrow
LOG_LEVEL=info
```

Run the backend:
```bash
cd backend
cargo run
```

### Step D: Configure Frontend Environment
Create `frontend/.env.development`:
```env
VITE_API_URL=http://localhost:8080
```

Install packages and run Vite dev server:
```bash
cd frontend
npm install
npm run dev
```

---

## 4. Verifying the Local Environment

### 1. Health Endpoint Check
Verify backend API is responsive:
```bash
curl -i http://localhost:8080/health
```
Expected response:
```http
HTTP/1.1 200 OK
content-type: application/json

{"status":"ok","version":"0.1.0","timestamp":"2026-10-13T00:00:00Z"}
```

### 2. Database Connectivity Check
```bash
curl -i http://localhost:8080/healthz/db
```
Expected response:
```http
HTTP/1.1 200 OK
content-type: application/json

{"database":"healthy","connected_clients":1}
```

### 3. Frontend Web Verification
Open `http://localhost:5173` in your browser. You should see the FireCrow landing page with:
- Top navigation and brand identity
- System status: `FLEET ONLINE`
- Interactive walkthrough preview
- Sign In modal accessible via the top-right button

---

## 5. First-Run Troubleshooting & Common Traps

| Symptom | Root Cause | Remediation Command |
| :--- | :--- | :--- |
| `permission denied while trying to connect to Docker daemon` | User not in `docker` group | `sudo usermod -aG docker $USER && newgrp docker` |
| `failed to connect to postgresql://...: Connection refused` | PostgreSQL container stopped | `docker start firecrow-postgres` or check `docker ps` |
| `Address already in use (os error 98)` | Port 8080 or 5173 occupied | `lsof -i :8080` and `kill -9 <PID>` |
| `error: package '...' requires rustc 1.85 or newer` | Rust toolchain outdated | `rustup update stable && rustup default stable` |
| `tsc -b: EACCES permission denied` | Vite build cache in read-only sandbox | Run `./node_modules/.bin/tsc -p tsconfig.app.json --noEmit` |
| Semgrep container fails with `Rule file not found` | Semgrep rules path not relative to backend | Ensure working dir is root or backend has `scanners/semgrep/firecrow-sast.yml` present |
