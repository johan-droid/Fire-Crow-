<div align="center">

# 🦅 Fire Crow

### Security Scanning Backend

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Axum](https://img.shields.io/badge/Axum-0.7-blue.svg?style=for-the-badge&logo=tokio)](https://github.com/tokio-rs/axum)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon-336791.svg?style=for-the-badge&logo=postgresql)](https://neon.tech/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg?style=for-the-badge&logo=react)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-5.0-646CFF.svg?style=for-the-badge&logo=vite)](https://vitejs.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

*Fire Crow fetches a GitHub repository, scans it for committed secrets,
dependency advisories, and source weaknesses with Gitleaks, OSV-Scanner and
Semgrep inside locked-down containers, and writes a deterministic report.
Nothing is reported that did not come out of a scanner.*

**Status:** backend **frozen** · release: **controlled-beta candidate**
(`documentation/RELEASE_CANDIDATE.md`).

**Start here:**

- Canonical backend reference → `documentation/FIRECROW_BACKEND.md`
- Frontend API contract → `documentation/FRONTEND_CONTRACT.md`
- Running it in production → `documentation/PRODUCTION_DEPLOYMENT.md`

</div>

---

## What this actually does

The audit pipeline is a Rust state machine with seven phases. Each phase writes a
row to `phase_ledger`, and a phase that did not run is never reported as a result.

| Phase | What runs |
|---|---|
| `intake` | Resolve `owner`/`name` from the submitted URL. |
| `fetch` | Confirm the token can read the repo, download the GitHub tarball, extract it into a temp dir with byte/file caps and no symlinks or `..`. The temp dir is always removed. Every execution pins an immutable commit SHA. |
| `scan` | Run **gitleaks**, **osv-scanner**, and **semgrep** over the source, each in its own container mounted read-only, with `--network=none` (osv alone gets a declared `bridge` network for its vulnerability database), a read-only rootfs, `--pids-limit`, `--cap-drop=ALL`, `no-new-privileges`, an unprivileged user, and cpu/memory limits. |
| `normalize` | Canonicalize to **Canonical Audit v1**: dedupe by scanner + rule + native fingerprint + normalized location + evidence digest. |
| `score` | Compute a score **only** if the scan actually completed (see below). |
| `report` | Build Canonical Audit v1 and render deterministic Markdown, JSON, and HTML, persisted against the execution. |
| `deliver` | Assert the report exists. Delivery (email, Telegram) is on demand, downstream, and execution-scoped. |

An **optional** validated AI narrative may explain the deterministic report. It
is an explanation layer only: it can never create, alter, or remove a finding,
and any AI failure leaves the deterministic report exactly as it was. The audit
survives with Gemini, email, Telegram, Redis, or the UI entirely absent.

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
- Inline PR annotations, security gates, or required checks. The GitHub App
  reports a single status Check Run per completed audit.
- Attack-chain edges. `/audit/job/:id/graph` returns nodes with an empty `edges`
  array, because nothing discovers real links between findings.

---

## 🏗️ Architecture

The canonical backend description lives in
[`documentation/FIRECROW_BACKEND.md`](documentation/FIRECROW_BACKEND.md).
Overview:

```mermaid
graph TD
    Client[Operator Browser / SPA] -->|HTTPS / Bearer / Cookie| Axum[Axum Rust Web Server]
    Axum -->|Session & Auth| AuthMiddleware[Auth Middleware]
    Axum -->|SQL Queries| Postgres[(PostgreSQL)]
    Axum -->|Job Queue| Worker[Worker Pool]
    Worker -->|Fetch tarball| GitHub[(GitHub API)]
    Worker -->|Read-only mount| Sandbox[gitleaks / osv-scanner / semgrep in hardened containers]
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

# Optional: GitHub App identity + webhooks. Set BOTH app values or NEITHER —
# half an identity (an ID with no key, or a key with no ID) refuses startup.
# GITHUB_APP_ID="123456"
# GITHUB_APP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
# GITHUB_APP_WEBHOOK_SECRET="your_webhook_secret"

# Service URLs
FRONTEND_URL="http://localhost:5173"
BACKEND_BASE_URL="http://localhost:8000"

# Optional: only required to deliver the report by email (SMTP transport).
# NOTE: RESEND_API_KEY (app.json) and brevo/resend fields (config.rs) are
# DEAD: the transport is SMTP-only via lettre (services/email.rs). Do not set
# them expecting effect. See documentation/PRODUCTION_DEPLOYMENT.md.
# SMTP_HOST="smtp.example.com"
# SMTP_PORT=587
# SMTP_USER="apikey"
# SMTP_PASSWORD="secret"
# SENDER_EMAIL="reports@example.com"

# Optional AI narrative (Gemini). Absent key/model = NotConfigured, audit unaffected.
# GEMINI_API_KEY=""
# GEMINI_MODEL="gemini-2.0-flash"
# GEMINI_TIMEOUT_SECONDS=30
# GEMINI_MAX_ATTEMPTS=2
# GEMINI_MAX_PROMPT_CHARS=60000
# Optional: only required to deliver the report to Telegram. The chat is fixed
# here on purpose — no request can choose where a security report is sent.
# TELEGRAM_BOT_TOKEN="123456:your-bot-token"
# TELEGRAM_CHAT_ID="-1001234567890"
# TELEGRAM_MESSAGE_LIMIT_CHARS=4096  # lowered to 4096 automatically if set higher
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
