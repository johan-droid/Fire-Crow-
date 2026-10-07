<div align="center">

# 🦅 Fire Crow

### Scanner-Backed Security Auditing Backend & Deterministic Reporting Engine

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Axum](https://img.shields.io/badge/Axum-0.7-blue.svg?style=for-the-badge&logo=tokio)](https://github.com/tokio-rs/axum)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15%2B-336791.svg?style=for-the-badge&logo=postgresql)](https://www.postgresql.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg?style=for-the-badge&logo=react)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8.1-646CFF.svg?style=for-the-badge&logo=vite)](https://vitejs.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

*Fire Crow fetches an immutable GitHub repository snapshot, executes real security scanners inside hardened containers, normalizes findings into Canonical Audit v1, persists an immutable execution record, and renders byte-deterministic reports. An optional AI narrative layer explains the findings without ever deciding security truth.*

> **Nothing is reported that did not originate from a scanner.**

**Release Status:** Backend **Architecture Frozen** · **Controlled-Beta Candidate**
([`RELEASE_CANDIDATE.md`](documentation/RELEASE_CANDIDATE.md) / [`RELEASE_GATE.md`](documentation/RELEASE_GATE.md)).

**Essential References:**
- [Canonical Backend Reference](documentation/FIRECROW_BACKEND.md)
- [Frontend API Contract v1](documentation/FRONTEND_CONTRACT.md)
- [Threat Model & Security Boundaries](documentation/THREAT_MODEL.md)
- [Production Deployment Guide](documentation/PRODUCTION_DEPLOYMENT.md)
- [Deterministic Reporting](documentation/DETERMINISTIC_REPORT.md)
- [Atomic Audit Commit & Lifecycle](documentation/ATOMIC_AUDIT_COMMIT.md)

</div>

---

## 1. What Fire Crow Is

Fire Crow is an automated GitHub security auditing backend built with Rust (Axum) and PostgreSQL. It audits repositories for committed secrets, dependency vulnerabilities, and source-code weaknesses through real, sandboxed security tools, producing reproducible, evidence-backed security reports:

```text
GitHub repository snapshot (pinned 40-hex commit SHA)
        ↓
Hardened container execution (one container per scanner)
  ├── Gitleaks v8.18.4 (committed secrets, network: none)
  ├── OSV-Scanner v2.2.4 (dependencies, network: bridge [sole exception])
  └── Semgrep 1.96.0 (SAST, network: none, pinned local ruleset)
        ↓
Parser adapters → Validated & redacted findings
        ↓
Exact-identity deduplication & provenance tracking
        ↓
Canonical Audit v1 (authoritative normalized representation)
        ↓
Atomic persistence to PostgreSQL (findings, runs, coverage, report in 1 transaction)
        ↓
Deterministic Report generation (byte-identical JSON, Markdown, HTML)
        ↓
Optional AI Narrative (Gemini explanation layer; cannot forge findings)
        ↓
Downstream Delivery (execution-scoped SMTP email & Telegram) + GitHub Check Run
```

### Facts vs. Optional AI Explanation

Fire Crow enforces a strict, architectural separation between **security facts** and **optional AI explanations**:

| Dimension | Scanner Pipeline (Facts) | AI Narrative Layer (Optional Explanation) |
|---|---|---|
| **Source of Truth** | Scanners (**Gitleaks**, **OSV-Scanner**, **Semgrep**) | None (reads only the finalized deterministic report) |
| **Can Create Findings?** | **Yes** (when a scanner emits valid evidence) | **NEVER** (invented finding IDs are rejected by validator) |
| **Can Alter Severity?** | **Yes** (native scanner severity mapped) | **NEVER** (severity mismatches trigger validation failure) |
| **Can Alter Score?** | Calculated deterministically | **NEVER** (tampering with score is rejected) |
| **Failure Impact** | Scanner failure = incomplete coverage (`score = null`) | AI failure = report served without narrative; audit succeeds |
| **Network Egress** | Offline default (OSV live DB sole exception) | Talks exclusively to Gemini API; prompt contains no raw code/secrets |

---

## 2. Audit Execution Pipeline

The audit pipeline is a Rust state machine with seven execution phases. Each phase records its start and end timestamps into `phase_ledger`:

| Phase | Description & Enforcement |
|---|---|
| `intake` | Validates and normalizes the GitHub URL (`https://github.com/{owner}/{repo}`). Enforces per-user concurrency backpressure via advisory transaction lock. |
| `fetch` | Verifies repository read access, resolves the default branch or requested SHA, pins an immutable 40-hex commit SHA, downloads the tarball with strict caps (100MB download, 150MB extracted, 20MB file, 20,000 files), rejects symlinks, hardlinks, and traversal paths (`..`), and stages the snapshot in a private temp directory cleaned up on drop. |
| `scan` | Executes **gitleaks**, **osv-scanner**, and **semgrep**, each in its own hardened Docker container. Every container runs with read-only rootfs, unprivileged user, dropped capabilities, memory/CPU/PID limits, and isolated stdout/stderr stream caps. |
| `normalize` | Normalizes scanner output into **Canonical Audit v1**. Validates evidence text, enforces line bounds, redacts secrets, strips credential shapes, and deduplicates identical findings by exact canonical identity (`scanner + rule + native fingerprint + location + evidence digest`). |
| `score` | Computes the security score `[0.0, 9.0]` **only** if all scanners completed successfully. Score is `NULL` for partial or failed scans. Zero findings yields `9.0`, never `10.0`. |
| `report` | Derives the deterministic report model (`CanonicalAuditReport`) and produces byte-identical Markdown, JSON, and HTML. Persisted atomically alongside the execution. |
| `deliver` | Asserts the finalized report exists. Downstream delivery (SMTP email and Telegram) is execution-scoped and idempotent. |

---

## 3. Scanner Inventory & Container Isolation

Every scanner execution is governed by `docker_argv` in [`backend/src/services/sandbox.rs`](backend/src/services/sandbox.rs):

| Tool | Pinned Image Reference | Domain | Network Mode | Output Handshake | Failure Semantics |
|---|---|---|---|---|---|
| **Gitleaks** | `ghcr.io/gitleaks/gitleaks:v8.18.4` | Committed secrets | `--network=none` | JSON artifact (`/work/gitleaks.json`) streamed with `cat` | Exit 1 + valid report = success; broken/missing report = FAILED |
| **OSV-Scanner** | `ghcr.io/google/osv-scanner:v2.2.4` | Dependency vulnerabilities | `--network=bridge` *(sole declared exception)* | JSON artifact (`/work/osv.json`) streamed with `cat` | Missing lockfile = clean; unparseable output = FAILED, never clean |
| **Semgrep** | `semgrep/semgrep:1.96.0` | Source-code SAST | `--network=none` | JSON artifact (`/work/semgrep.json`) streamed with `cat` | `no_files_analyzed` or syntax errors = FAILED, never clean |

### Sandbox Security Hardening

- **Filesystem Isolation:** Repository snapshot mounted read-only at `/scan`. Container root filesystem is `--read-only`. Writable scratch is an in-memory `tmpfs` (`/work` capped at 64MB; `/tmp` capped at 32MB). Writes never touch the host filesystem and evaporate when the container terminates.
- **Network Isolation:** `--network=none` by default. OSV-Scanner is the sole scanner granted `--network=bridge` to query Google's live advisory database.
- **Least Privilege:** Runs as `--user=65534:65534` (`nobody:nogroup`). All capabilities dropped (`--cap-drop=ALL`), and `--security-opt=no-new-privileges` prevents privilege escalation.
- **Resource Ceilings:** Process ceilings via `--pids-limit`, CPU ceilings via `--cpus`, and memory ceilings via `-m` with `--memory-swap` pinned equal to memory (preventing swap evasion).
- **Process Supervision:** `--init` runs `tini` as PID 1 to reap orphaned child processes. Containers are automatically cleaned up (`--rm`), with explicit `docker rm -f` on timeout or cancellation.
- **Streaming Bounds:** Standard output is capped at 16MB; standard error is capped at 1MB and redacted before logging.

---

## 4. Key Architectural Guarantees

### 1. Failure Is Never Reported as Clean
A crashed, timed-out, cancelled, or unparseable scanner produces **unknown coverage**, never "zero findings". Incomplete or partial scans keep successful scanners' findings but leave the security score as `NULL`.

### 2. Immutable Execution History & Retries
Every audit job has one or more attempts stored in `audit_executions`:
- Retries create a new attempt record (attempt $N+1$) with a distinct `execution_id`.
- A retry **never overwrites or mutates** a previous attempt's findings, reports, or logs.
- Database triggers reject updates to terminal execution and report rows.

### 3. Atomic Finalization
Findings, scanner runs, aggregate coverage, deterministic reports, and execution status commit in **one single PostgreSQL transaction**. Crashes cannot produce half-finalized audits or orphaned findings.

### 4. Deterministic Reporting
Reports are rendered directly from `CanonicalAuditReport` as a pure function. Report regeneration performs **zero I/O** (no filesystem reads, no scanner execution, no LLM queries, and no database queries). The exact same report can be reconstructed from persisted database state years later.

### 5. Scoring Transparency
- Perfect `10.0` is never awarded: zero findings yields `9.0/10` because "no vulnerabilities detected" is not equivalent to "proven secure".
- Each finding incurs a `1.5` penalty: `score = (10.0 - findings * 1.5).clamp(0.0, 9.0)`.
- The score is strictly `NULL` whenever coverage is partial, failed, or absent.

### 6. GitHub Integration
- **GitHub OAuth:** User authentication, identity bound to provider subject ID.
- **GitHub App:** Organization installations, installation-token exchange (tokens kept in memory only, never persisted), HMAC-SHA256 verified webhooks (`POST /api/v1/github/webhook`), and a status Check Run (`firecrow-security-audit`) on the pinned commit SHA.
- **No Inline PR Annotations:** Status, counts, and coverage only.

---

## 5. What Is Deliberately NOT Implemented

To ensure architectural honesty, Fire Crow explicitly declares the following features as **absent**:

- ❌ **No AI-generated security findings:** The AI explains; scanners detect.
- ❌ **No automatic exploit simulation or code patching.**
- ❌ **No inline GitHub PR annotations or merge-blocking security gates.**
- ❌ **No attack-chain graph edges:** `/audit/job/:id/graph` returns vulnerability nodes with an empty `edges: []` array because findings are not correlated across attack chains.
- ❌ **No full public beta claim:** The system is in **controlled beta**. Multi-user sustained soak and credential-gated Gemini smoke tests remain recorded operational gates.

---

## 6. Getting Started

### Prerequisites

- **Rust** `1.75+` (tested with Rust `1.85+` / `1.98+`)
- **Node.js** `v18+` & `npm`
- **PostgreSQL** `14+`
- **Docker** (with permissions to run `gitleaks`, `osv-scanner`, `semgrep` containers)

### 1. Clone the repository

```bash
git clone https://github.com/johan-droid/Fire-Crow-.git
cd Fire-Crow-
```

### 2. Install dependencies

```bash
# Install frontend workspace dependencies
npm --prefix frontend install
```

### 3. Configure backend environment

Create `backend/.env.local`:

```env
# Server & Network Configuration
PORT=8000
HOST="0.0.0.0"
FRONTEND_URL="http://localhost:3000"
BACKEND_BASE_URL="http://localhost:8000"
CORS_ORIGINS="http://localhost:3000"

# Core Secrets (Must be at least 32 characters, never identical)
SECRET_KEY="replace-with-a-random-32-char-secret-key-for-jwt"
ENCRYPTION_KEY="replace-with-a-different-32-char-encryption-key"

# Database (PostgreSQL with 28 migrations)
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/firecrow?sslmode=disable"

# GitHub OAuth (Optional for local testing, required for OAuth login)
GITHUB_CLIENT_ID=""
GITHUB_CLIENT_SECRET=""
GITHUB_TOKEN=""

# GitHub App Integration (Optional, set BOTH or NEITHER)
# GITHUB_APP_ID=123456
# GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
# GITHUB_APP_WEBHOOK_SECRET="webhook-secret-here"

# SMTP Email Delivery (Optional)
# SMTP_HOST="smtp.example.com"
# SMTP_PORT=587
# SMTP_USER="apikey"
# SMTP_PASSWORD="password"
# SENDER_EMAIL="reports@firecrow.dev"

# Telegram Delivery (Optional)
# TELEGRAM_BOT_TOKEN="bot-token"
# TELEGRAM_CHAT_ID="operator-chat-id"

# Google Gemini AI Narrative (Optional: Unset = NotConfigured, audits still succeed)
# GEMINI_API_KEY=""
# GEMINI_MODEL="gemini-2.0-flash"
```

### 4. Run the development environment

Start both the backend server and frontend development server concurrently:

```bash
npm run dev
```

Or run each independently:

```bash
# Terminal 1: Backend (Axum on port 8000)
cd backend
cargo run

# Terminal 2: Frontend (Vite on port 3000, proxies /api to port 8000)
cd frontend
npm run dev
```

The web dashboard is served at `http://localhost:3000`.

---

## 7. Testing & Verification

Fire Crow contains a comprehensive suite of unit, integration, and security regression tests:

```bash
cd backend

# Run the complete test suite (spins up isolated PostgreSQL via docker-compose)
./scripts/test.sh

# Run database-free unit tests only
./scripts/test.sh --unit

# Check formatting and clippy lints
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Database-backed tests use `#[sqlx::test(migrations = "./migrations")]` to ensure every test executes against a fresh, fully migrated database schema with zero cross-test interference.

---

## 8. Repository Layout

```text
Fire-Crow-/
├── .github/workflows/          # GitHub Actions CI & Cloudflare Pages deployment
├── backend/                    # Rust (Axum) web server & scanning orchestrator
│   ├── migrations/             # 28 SQLx PostgreSQL schema migrations
│   ├── scanners/semgrep/       # Pinned local SAST ruleset (firecrow-sast.yml)
│   ├── scripts/                # Test runner and development scripts
│   ├── src/
│   │   ├── agents/             # Fetch engine & container scanner runtimes
│   │   ├── api/                # REST API routers & request handlers
│   │   ├── middleware/         # Auth, CSRF, rate-limiting, security headers
│   │   ├── models/             # Database entity models with secret-safe Debug
│   │   ├── orchestrator/       # 7-phase state machine & atomic commit
│   │   ├── schemas/            # Canonical Audit v1, AI narrative, report schemas
│   │   ├── services/           # Sandbox, reporter, LLM transport, email, telegram
│   │   └── workers/            # Job queue workers, heartbeat, and orphan reaper
│   ├── test-fixtures/          # Golden report benchmarks and scanner fixtures
│   ├── tests/                  # Integration, lifecycle, and security regression tests
│   └── Cargo.toml              # Rust crate manifest
├── documentation/              # Canonical architectural & operational manuals
│   ├── FIRECROW_BACKEND.md     # Single canonical backend reference
│   ├── FRONTEND_CONTRACT.md    # API contract v1 for frontend consumers
│   ├── DETERMINISTIC_REPORT.md # Deterministic report generation manual
│   ├── ATOMIC_AUDIT_COMMIT.md  # Atomic commit & execution identity
│   ├── LLM_PROVIDER.md         # Google Gemini provider contract
│   ├── GITHUB_APP.md           # GitHub App integration & trust boundary
│   ├── THREAT_MODEL.md         # Threat model & security enforcement matrix
│   ├── PRODUCTION_DEPLOYMENT.md# Production deployment topology & configuration
│   ├── CLOUDFLARE_DEPLOYMENT.md# Cloudflare Pages static frontend deployment
│   ├── RELEASE_CANDIDATE.md    # Release candidate evidence scorecard
│   └── RELEASE_GATE.md         # Phase 20 production release gate audit
└── frontend/                   # React 19 + TypeScript + Vite web dashboard
```

---

## 📄 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
