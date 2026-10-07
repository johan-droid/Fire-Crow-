# FireCrow — Developer & Deployment Guide

---

## 1. Overview & System Architecture

FireCrow is an enterprise-grade automated repository security auditing and vulnerability scanning platform.

```text
       ┌───────────────────────────────┐
       │   Vercel Frontend (React)     │
       └───────────────┬───────────────┘
                       │ HTTPS / Cookie Auth
                       ▼
       ┌───────────────────────────────┐
       │   Render Backend (Rust/Axum)  │
       └───────────────┬───────────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
┌───────────────────┐     ┌─────────────────────┐
│ PostgreSQL Store  │     │ Ephemeral Scanners  │
│ (Render Postgres) │     │ (Docker Sandboxes)  │
└───────────────────┘     └─────────────────────┘
```

---

## 2. Directory Structure & Core Modules

```text
Fire-Crow-/
├── backend/                  # Rust Axum Backend Service
│   ├── src/
│   │   ├── agents/           # Vulnerability Analysis & Acquisition Agents
│   │   │   ├── fetch.rs      # Stream-bounded repository intake agent
│   │   │   ├── scanner.rs    # Gitleaks / OSV / Semgrep scanner orchestration
│   │   │   └── mod.rs        # Analysis engine declarations
│   │   ├── api/              # REST Endpoints (Auth, Audit, System, Health)
│   │   ├── middleware/       # Cookie auth, strict CSRF, security headers, rate limits
│   │   ├── models/           # Schema entities, canonical finding models
│   │   ├── orchestrator/     # Execution worker, lifecycle guards, delivery
│   │   ├── services/         # Sandbox isolation, egress policy, storage, telemetry
│   │   └── main.rs           # Startup sequence & migration runner
│   ├── migrations/           # PostgreSQL Schema Migrations
│   ├── Cargo.toml            # Backend dependencies
│   └── Dockerfile            # Containerized backend build (rust:1.85-bookworm)
├── frontend/                 # Vercel-Ready Vite + React + TypeScript Frontend
│   ├── src/                  # React UI components & state hooks
│   ├── package.json          # Node dependencies & Vite scripts
│   ├── vercel.json           # Frontend Vercel configuration
│   └── vite.config.ts        # Vite dev server & proxy settings
├── render.yaml               # Render Infrastructure-as-Code manifest
├── vercel.json               # Root Vercel deployment manifest
└── documentation/
    ├── DEVELOPER_GUIDE.md               # Unified Developer & Deployment Guide
    ├── FINAL_SECURITY_HARDENING_REPORT.md # Final Security Audit & Remediation Report
    └── INTERNAL_SECURITY_AUDIT.md       # Frozen Historical Security Audit Baseline
```

---

## 3. Deployment Configuration

### A. Deploying Frontend to Vercel

The frontend is fully configured for deployment on **Vercel**.

1. Connect the GitHub repository to **Vercel**.
2. Set **Root Directory** to `./` (or `frontend`).
3. Set **Framework Preset** to `Vite`.
4. Configure Environment Variables in Vercel Dashboard:
   - `VITE_API_URL`: Your deployed Render backend URL (e.g. `https://firecrow-backend.onrender.com`).
5. **Vercel Rewrites (`vercel.json`)**:
   All `/api/*` routes are automatically proxied to the Render backend, preventing CORS and cookie-domain friction.

### B. Deploying Backend to Render

The backend runs as a Docker Web Service on **Render** paired with a Render PostgreSQL database.

1. Create a **New Blueprint Instance** on Render selecting `render.yaml` OR create a **Web Service**:
   - **Environment**: `Docker`
   - **Dockerfile Path**: `backend/Dockerfile`
   - **Context**: `.` (Root)
2. **Environment Variables for Render**:
   - `DATABASE_URL`: `postgres://user:pass@render-db-hostname:5432/firecrow`
   - `SECRET_KEY`: `openssl rand -base64 48` (Minimum 32 bytes secret)
   - `ENCRYPTION_KEY`: `openssl rand -base64 48`
   - `FRONTEND_URL`: `https://your-app.vercel.app`
   - `CORS_ORIGINS`: `https://your-app.vercel.app`
   - `PORT`: `8080`

---

## 4. Agents & Subsystem Architecture

### Vulnerability Analysis Agents (`backend/src/agents/`)
- **Repository Fetch Agent (`fetch.rs`)**: Performs stream-bounded repository retrieval, verifying commit SHAs, branch names, pax archive headers, and total decompressed bounds (max 50MB).
- **Scanner Agent (`scanner.rs`)**: Controls containerized scanner execution (Gitleaks, OSV, Semgrep). Enforces container isolation, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `pids-limit=100`, read-only repo mounts, and network egress rules.
- **AI Narrative Agent (`src/services/llm_provider.rs`)**: Generates executive narrative summaries from canonical audit reports. Strictly isolated so AI output can never mutate scores, severities, or finding counts.

---

## 5. API Endpoints Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Deep health probe (Database connectivity check) | No |
| `POST` | `/api/v1/auth/register` | User registration | No |
| `POST` | `/api/v1/auth/login` | Authenticate & receive HttpOnly session cookie | No |
| `POST` | `/api/v1/auth/logout` | Revoke session cookie | Yes |
| `GET` | `/api/v1/auth/me` | Return current authenticated user | Yes |
| `POST` | `/api/v1/audits` | Submit repository audit job | Yes |
| `GET` | `/api/v1/audits` | List user audit jobs | Yes |
| `GET` | `/api/v1/audits/:id` | Get job status & canonical report | Yes |
| `GET` | `/api/v1/audits/:id/executions/:exec_id` | Get specific attempt report & findings | Yes |

---

## 6. Local Development Setup

```bash
# 1. Start PostgreSQL (Port 55433)
docker run -d --name firecrow-postgres \
  -e POSTGRES_DB=firecrow_dev \
  -e POSTGRES_USER=firecrow \
  -e POSTGRES_PASSWORD=firecrow_pass \
  -p 55433:5432 postgres:16-alpine

# 2. Run Backend
cd backend
export DATABASE_URL="postgres://firecrow:firecrow_pass@127.0.0.1:55433/firecrow_dev"
export SECRET_KEY="local_development_secret_key_32_bytes_long_min!"
export ENCRYPTION_KEY="local_development_encryption_key_32_bytes_long!"
export FRONTEND_URL="http://localhost:5173"
export CORS_ORIGINS="http://localhost:5173"
cargo run

# 3. Run Frontend
cd ../frontend
npm install
npm run dev
```

---

## 7. Security Invariants

1. **Failure != Clean**: Scanner errors, timeouts, or cancellations set score to `NULL` and status to incomplete.
2. **AI Isolation**: AI responses describe audit facts but cannot create, modify, or delete findings.
3. **Session Cookies**: Tokens are passed exclusively via HttpOnly, Secure, SameSite cookies. Bearer tokens in URL parameters are rejected.
4. **Host Mount Boundary**: `/var/run/docker.sock` and dangerous host paths are strictly prohibited in sandbox configurations.
