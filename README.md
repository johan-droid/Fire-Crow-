<div align="center">

# 🦅 Fire Crow

### Security Scanning Backend

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Axum](https://img.shields.io/badge/Axum-0.7-blue.svg?style=for-the-badge&logo=tokio)](https://github.com/tokio-rs/axum)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon-336791.svg?style=for-the-badge&logo=postgresql)](https://neon.tech/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg?style=for-the-badge&logo=react)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-5.0-646CFF.svg?style=for-the-badge&logo=vite)](https://vitejs.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

*Fire Crow fetches a GitHub repository, scans it for committed secrets with
gitleaks inside a locked-down container, and writes a Markdown report. Nothing is
reported that did not come out of the scanner.*

</div>

---

## What this actually does

The audit pipeline is a Rust state machine with seven phases. Each phase writes a
row to `phase_ledger`, and a phase that did not run is never reported as a result.

| Phase | What runs |
|---|---|
| `intake` | Resolve `owner`/`name` from the submitted URL. |
| `fetch` | Confirm the token can read the repo, download the GitHub tarball, extract it into a temp dir with byte/file caps and no symlinks or `..`. The temp dir is always removed. |
| `scan` | Run **gitleaks** over the source, mounted read-only, with `--network=none`, a read-only rootfs, `--pids-limit`, `--cap-drop=ALL`, `no-new-privileges`, an unprivileged user, and cpu/memory limits. |
| `normalize` | Deduplicate findings by a fingerprint of rule + file + line. |
| `score` | Compute a score **only** if the scan actually completed (see below). |
| `report` | Generate Markdown and persist it to `audit_reports`. |
| `deliver` | Assert the report exists. Delivery itself is on demand via the email endpoint. |

Every finding carries a **file path, a line number, and an evidence snippet taken
from the scanner**, with the secret value redacted. The score is `NULL` if no
analysis ran or any scanner failed; a scan never reports a perfect `10/10`, and
zero findings yields `9.0`, not `10.0`.

### Findings and scoring rules

- A `Finding` must carry `file_path`, `line_number`, and an evidence snippet.
- The stored snippet has the exact secret value replaced with `[REDACTED]` and is
  passed through the shared redactor.
- The LLM helper (`services/llm.rs`) may only explain or prioritise findings that
  already exist; it never creates one, and it is not on the scan path.
- Terminal job statuses are never overwritten: every status `UPDATE` is guarded on
  a non-terminal status.

## Not implemented in this build

The following are deliberately absent and are **not** claimed by the API or UI:

- LLM code analysis, exploit simulation, and automated patch generation.
- Vulnerability scanners other than gitleaks (osv-scanner, semgrep).
- Telegram delivery. Report email is SMTP-only, and the endpoint returns `501`
  when SMTP is not configured.
- Attack-chain edges. `/audit/job/:id/graph` returns nodes with an empty `edges`
  array, because nothing discovers real links between findings.

---

## 🏗️ Architecture

```mermaid
graph TD
    Client[Operator Browser / SPA] -->|HTTPS / Bearer / Cookie| Axum[Axum Rust Web Server]
    Axum -->|Session & Auth| AuthMiddleware[Auth Middleware]
    Axum -->|SQL Queries| Postgres[(PostgreSQL)]
    Axum -->|Job Queue| Worker[Worker Pool]
    Worker -->|Fetch tarball| GitHub[(GitHub API)]
    Worker -->|Read-only mount| Sandbox[gitleaks in a hardened container]
    Worker -->|Findings + report| Postgres
```

---

## 🚀 Getting Started

### Prerequisites

- **Rust** (cargo `1.75+`)
- **Node.js** (`v18+`) & `npm`
- **PostgreSQL**
- **Docker** (the scan phase runs gitleaks in a container)

### 1. Clone the repository

```bash
git clone https://github.com/johan-droid/Fire-Crow-.git
cd Fire-Crow-
```

### 2. Install dependencies

```bash
cd frontend
npm install
cd ..
```

### 3. Configure environment variables

Create or edit `backend/.env.local`:

```env
# Database & core security keys
DATABASE_URL="postgresql://user:password@host/db?sslmode=require"
SECRET_KEY="your-min-32-character-random-secret-key"
ENCRYPTION_KEY="your-min-32-character-data-encryption-key"

# GitHub: OAuth login and the platform token used to read repositories
GITHUB_CLIENT_ID="your_github_client_id"
GITHUB_CLIENT_SECRET="your_github_client_secret"
GITHUB_TOKEN="ghp_your_personal_access_token"

# Service URLs
FRONTEND_URL="http://localhost:5173"
BACKEND_BASE_URL="http://localhost:8000"

# Optional: only required to deliver the report by email
# SMTP_HOST="smtp.example.com"
# SMTP_PORT=587
# SMTP_USER="apikey"
# SMTP_PASSWORD="secret"
# SENDER_EMAIL="reports@example.com"
```

### 4. Run

```bash
npm run dev
```

or the backend alone:

```bash
cd backend
cargo run
```

The dashboard is served at `http://localhost:5173`.

---

## 📁 Repository structure

```text
Fire-Crow-/
├── backend/                  # Rust Axum web server & scan orchestrator
│   ├── migrations/           # SQLx schema migrations
│   ├── scripts/              # test.sh and developer utilities
│   ├── src/
│   │   ├── agents/           # fetch (GitHub tarball) and scanner (gitleaks)
│   │   ├── api/              # REST route handlers
│   │   ├── middleware/       # Auth, CORS, request id, rate limiting
│   │   ├── models/           # SQLx FromRow structs
│   │   ├── orchestrator/     # Scan state machine
│   │   ├── services/         # Domain logic (auth, crypto, sandbox, reporter...)
│   │   └── workers/          # Job queue workers and the orphan reaper
│   └── Cargo.toml
├── documentation/            # Deployment and integration guides
└── frontend/                 # React 18 + Vite control panel
```

---

## Testing

```bash
cd backend
./scripts/test.sh          # brings up PostgreSQL + Redis, runs, tears down
./scripts/test.sh --unit   # database-free tests only
```

Database-backed tests use `#[sqlx::test(migrations = "./migrations")]`, so each
test gets a freshly migrated database. See `backend/TESTING.md`.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
