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
   - `VITE_API_URL`: Your API base **including** the version prefix (e.g. `https://firecrow-backend.onrender.com/api/v1`). A bare origin without `/api/v1` makes every API call 404.
5. **Vercel routing isolation (fail-closed)**: the committed `vercel.json` files (repo root and `frontend/`) intentionally declare **no** `/api` rewrite — only the SPA fallback. Vercel rewrites do not interpolate environment variables, so any committed external upstream would silently route every Preview deployment to the written host. API traffic is instead wired per environment through the `VITE_API_URL` dashboard variable (set separately for Production and Preview, or leave Preview unset so calls fail loudly against nothing). Guarded statically by `frontend/src/api/deploy.ts` (`preview` mode) and `frontend/tests/routing.test.ts` + `health.test.ts`.

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
   - `PORT`: **do not set** — Render injects the runtime port and the Rust service reads it (config-crate `Environment` source over the 8000 default; `backend/src/config.rs`). The Dockerfile healthcheck probes `${PORT:-8000}` so it follows the platform.

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

Prerequisites: `node` + `npm`, `cargo`, `docker` (daemon running), `openssl`, `curl`. No root needed.

```bash
# First-time setup (safe: never overwrites existing *.env.local)
./scripts/dev.sh check
./scripts/dev.sh setup

# Start: isolated postgres container (loopback 55433 only) + backend (:8000) + frontend (:3000)
./scripts/dev.sh start

# Inspect
./scripts/dev.sh status
./scripts/dev.sh logs [backend|frontend|db]   # secrets redacted

# Safe smoke tests (no scans, no deliveries; integration without staging is BLOCKED, never faked)
./scripts/dev.sh smoke

# Stop only what the launcher started (process groups + its own container).
# A foreign container holding the same name is left running, never stopped.
./scripts/dev.sh stop
```

How it works:

* Backend runs via the repo's own `npm run backend` (`cd backend && cargo run`). It reads `backend/.env.local` (dotenvy) and applies embedded SQLx migrations itself at startup — fatal without a reachable DB. `/api/v1/health/ready` returns 200 only after `SELECT 1` succeeds, so `ready` proves DB + migrations.
* Frontend runs via `npm run frontend` (vite `:3000`, `/api` proxied to `:8000`). `VITE_API_URL="/api/v1"` keeps cookies first-party; the value must include the `/api/v1` prefix (bare origin 404s everything).
* PostgreSQL runs in the `firecrow-dev-postgres` container (`postgres:16-alpine`, `-p 127.0.0.1:55433:5432`). The tracked `docker-compose.yml` publishes no host ports, so it cannot serve a local cargo backend; the launcher container is separate and compose services are never touched. Data persists in the stopped container; `docker rm firecrow-dev-postgres` resets it (destroys local data only).
* Runtime state (process-group ids, logs) lives in `$TMPDIR/firecrow-dev-$UID` (per-user, default `/tmp/firecrow-dev-$UID`), never in the repo.
* Env files: `setup` creates `backend/.env.local` (mode 600, `openssl`-generated `SECRET_KEY`/`ENCRYPTION_KEY`) and `frontend/.env.local` only when missing, and tightens an existing `backend/.env.local` to mode 600. Templates `backend/.env.example` / `frontend/.env.example` are secret-free. Refusal messages never echo back the parsed database host (it can carry password fragments from crafted URLs). Local, staging, and production settings are never copied between environments by the script.

Port conflicts: `check`/`start` report occupied `:3000`/`:8000` and refuse to kill anything. Identify the owner with `ss -ltnp`, stop it yourself, re-run.

Authentication locally: GitHub OAuth needs a GitHub OAuth App with callback `http://localhost:3000/auth/callback` plus `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` in `backend/.env.local`. Without it, login stays BLOCKED — no bypass is provided, by design.

Scanner/integration limits: without scan engines, jobs finish as `engine_unavailable` (honest signal, not clean). `GEMINI_*`, email, and Telegram keys stay empty, so narrative/delivery report unconfigured errors instead of sending anything. Never point `DATABASE_URL` at shared/production hosts — `start` refuses non-loopback targets.

Tests/build/lint: `./scripts/dev.sh smoke` runs `npm test` + `npm run build` in `frontend/`; run `npm run lint` there any time (7 pre-existing warnings at last check).

Switching to staging: staging needs its own backend env + `VITE_API_URL=<staging-origin>/api/v1`; never copy `.env.local` there. Direct (non-proxied) split-origin staging additionally needs `CORS_ORIGINS`/`FRONTEND_URL` set to the frontend origin and `AUTH_COOKIE_SAMESITE=lax|none` (+ secure), because cookies default to `SameSite=Strict`.

Common failures:

| Symptom | Remedy |
|---|---|
| `DATABASE_URL host ... is not loopback` | Point it at `127.0.0.1` for local work; remote DBs are out of scope for `dev.sh`. |
| Backend exits: `SECRET_KEY is required` | Re-run `setup`, or add keys from `backend/.env.example` (generate with `openssl rand -base64 48`). |
| `/health/ready` never 200 | `logs db` (container down?) then `logs backend` (migrations fatal without DB). |
| Port occupied | `ss -ltnp`, stop the owner, re-run. `dev.sh` never kills by port. |
| First `cargo run` slow | Expected: full workspace compile, several minutes, once. |
| `vite` 404s `/api/*` | `VITE_API_URL` must be `/api/v1`; restart vite after changing it. |

---

## 7. Security Invariants

1. **Failure != Clean**: Scanner errors, timeouts, or cancellations set score to `NULL` and status to incomplete.
2. **AI Isolation**: AI responses describe audit facts but cannot create, modify, or delete findings.
3. **Session Cookies**: Tokens are passed exclusively via HttpOnly, Secure, SameSite cookies. Bearer tokens in URL parameters are rejected.
4. **Host Mount Boundary**: `/var/run/docker.sock` and dangerous host paths are strictly prohibited in sandbox configurations.
