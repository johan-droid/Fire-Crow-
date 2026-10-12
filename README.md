<div align="center">

<img src="frontend/public/fire-crow-logo.png" alt="FireCrow Logo" width="160" style="border-radius: 20px; box-shadow: 0 8px 32px rgba(0,0,0,0.4);" />

# 🦅 FireCrow

### Enterprise Repository Security Auditing & Deterministic Scanning Engine
**Architected for Zero Trust • Ephemeral Docker Sandboxes • Cryptographically Proven Canonical Ledgers**

<br/>

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Axum](https://img.shields.io/badge/Axum-0.7-blue.svg?style=for-the-badge&logo=tokio&logoColor=white)](https://github.com/tokio-rs/axum)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7%2B-3178C6.svg?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-8.1-646CFF.svg?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
[![Docker](https://img.shields.io/badge/Docker-Sandboxed-2496ED.svg?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)

[![Scanners](https://img.shields.io/badge/Tri--Engine-Gitleaks%20%7C%20Semgrep%20%7C%20OSV-8A2BE2.svg?style=for-the-badge)](#-tri-engine-scanning-pipeline)
[![Security Hardened](https://img.shields.io/badge/Security-100%25%20Verified%20(F1--L11)-2ea44f.svg?style=for-the-badge)](#-security-invariants--hardening)
[![Vercel Ready](https://img.shields.io/badge/Vercel-Frontend-black.svg?style=for-the-badge&logo=vercel&logoColor=white)](https://vercel.com)
[![Render Ready](https://img.shields.io/badge/Render-Backend-46E3B7.svg?style=for-the-badge&logo=render&logoColor=black)](https://render.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

<br/>

[Overview](#-overview) • [Key Capabilities](#-key-capabilities) • [System Architecture](#-system-architecture) • [Tri-Engine Pipeline](#-tri-engine-scanning-pipeline) • [Security Invariants](#-security-invariants--hardening) • [Quick Start](#-quick-start-local-development) • [Deployment](#-deployment-guide) • [API Topology](#-api-endpoints--health-probes) • [Documentation](#-documentation-suite)

<br/>

> 🛡️ **Core Security Invariant**: *Nothing is reported that did not originate directly from a sandboxed scanner execution. `failure != clean`. If an underlying engine crashes, times out, or fails to acquire the code, FireCrow records incomplete audit truth—never an illegitimate green checkmark.*

</div>

---

## 📖 Overview

**FireCrow** is an enterprise-grade, deterministic repository security auditing engine and developer intelligence platform. Developed by **NEXT LAB.inc**, FireCrow addresses the critical flaws of modern automated auditing: hallucinated AI vulnerabilities, unbounded ingestion risks, and untrusted code execution on host machines.

FireCrow ingests immutable GitHub repository snapshots using **stream-bounded archive chunking**, executes genuine industry-standard security scanners (**Gitleaks**, **Semgrep**, **OSV-Scanner**) within **zero-privilege, ephemeral Docker micro-containers**, normalizes raw outputs into structured **Canonical Audit v1** ledgers, and derives mathematically reproducible risk scores (0–100).

An optional, isolated **Gemini AI narrative layer** synthesizes executive briefings from finalized audit records—strictly prevented by schema validation and database triggers from ever creating findings, modifying severities, or altering the factual risk score.

```
Untrusted Code ──▶ Stream Bounded ──▶ Zero-Privilege ──▶ Canonical v1 ──▶ Immutable DB ──▶ Exportable
  Repository        Intake (50MB)      Containers        Normalizer       Ledger (Pg16)    Artifacts
                                      (Gitleaks/OSV/                                       (PDF/JSON/
                                        Semgrep)                                            HTML)
```

---

## ✨ Key Capabilities

<table>
  <tr>
    <td width="50%">
      <h3>🛡️ Ephemeral Micro-Sandboxes</h3>
      <p>Scanners execute inside strictly isolated, non-root micro-containers with <code>--cap-drop=ALL</code>, <code>--security-opt=no-new-privileges</code>, read-only repository mounts, strict PID caps (100), and blocked egress. Workspaces are destroyed immediately upon audit completion.</p>
    </td>
    <td width="50%">
      <h3>📦 Stream-Bounded Intake (Anti-Bomb)</h3>
      <p>Hardened ingestion agent applies streaming HTTP chunking, pax inflation bounds, and a strict 50MB unpack ceiling. Protects infrastructure against decompression bombs, symlink attacks, and memory exhaustion before any scanner executes.</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🔬 Tri-Engine Orchestration</h3>
      <p>Combines three gold-standard security scanners in a single unified execution pipeline: <strong>Gitleaks</strong> for high-entropy secrets and keys, <strong>Semgrep</strong> for AST-based SAST & OWASP Top 10 rules, and <strong>OSV-Scanner</strong> for open-source dependency CVEs.</p>
    </td>
    <td width="50%">
      <h3>⚖️ Deterministic Risk Scoring</h3>
      <p>Security scores (0–100) are computed through a transparent mathematical deduction model based on confirmed findings and CVSS 3.1 weights. No subjective estimates, no probabilistic hallucination—100% reproducible and auditable.</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🤖 Total AI Truth Isolation</h3>
      <p>Separation of concerns enforced by design: the LLM briefing layer operates exclusively downstream of finalized audits. Structural validators and PostgreSQL constraints reject any attempt by the AI to invent findings, alter counts, or modify scores.</p>
    </td>
    <td width="50%">
      <h3>🔒 Database-Authoritative Lifecycle</h3>
      <p>PostgreSQL 16 <code>BEFORE UPDATE</code> triggers (<code>audit_jobs_lifecycle_guard_fn</code>) enforce the state machine directly in the database layer. Illegal transitions (e.g. jumping from <code>QUEUED</code> to <code>COMPLETED</code>) are blocked fatally by the engine.</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🍪 Zero-Trust Auth & IDOR Protection</h3>
      <p>HttpOnly, Secure, SameSite session cookies eliminate exposed tokens in URLs and <code>localStorage</code>. Protected by double-submit CSRF tokens and strict ownership verification gates on every audit resource.</p>
    </td>
    <td width="50%">
      <h3>📊 Multi-Format Compliance Artifacts</h3>
      <p>Export cryptographic, verifiable audit records as standardized <strong>Canonical Audit v1 JSON</strong>, printable HTML reports, and executive-ready PDF documentation suitable for SOC 2, ISO 27001, and compliance stakeholders.</p>
    </td>
  </tr>
</table>

---

## 🏛️ System Architecture

FireCrow enforces a strict single-origin API contract (`/api/v1/*`), separating the stateless frontend presentation layer from the hardened Rust orchestration engine and isolated scanner runtime.

```mermaid
flowchart TD
    subgraph Client ["Client Presentation Layer (Vercel)"]
        SPA["React 19 + TypeScript SPA"]
        Vite["Vite 8.1 App Shell"]
    end

    subgraph Gateway ["Public API Origin & Defense (Render / Docker)"]
        Axum["Rust Axum 0.7 Service"]
        MW_Auth["Cookie Auth & IDOR Gate"]
        MW_CSRF["Double-Submit CSRF Guard"]
        MW_Rate["Governor Rate Limiter"]
    end

    subgraph Intake ["Stream-Bounded Intake Engine"]
        FetchAgent["Repository Fetch Agent (fetch.rs)"]
        DecompGuard["Pax Decompressor (Max 50MB Ceiling)"]
        SHAGuard["Commit SHA & Branch Validator"]
    end

    subgraph Sandbox ["Ephemeral Execution Boundary"]
        Proxy["docker-socket-proxy (Deny-by-Default TCP)"]
        C_Gitleaks["Docker: Gitleaks v8.18.2 (Cap-Drop ALL)"]
        C_Semgrep["Docker: Semgrep v1.64.0 (ReadOnly Mount)"]
        C_OSV["Docker: OSV-Scanner v1.6.2 (Egress Guard)"]
    end

    subgraph DataStore ["State & Ledger Persistence (PostgreSQL 16)"]
        Postgres[(PostgreSQL 16)]
        Trigger["BEFORE UPDATE Trigger (State Guard)"]
        AuditLedger["Canonical Audit v1 Records"]
    end

    subgraph AI ["Read-Only AI Narrative Layer"]
        LLM["Gemini AI Briefing Synthesizer"]
        SchemaValidator["Structural Schema Validator (Zero-Write Guard)"]
    end

    %% Flow Connections
    SPA -- "HTTPS / HttpOnly Cookie + CSRF" --> Axum
    Axum --> MW_Auth --> MW_CSRF --> MW_Rate
    MW_Rate --> FetchAgent
    FetchAgent --> DecompGuard --> SHAGuard
    SHAGuard -- "Unpacked Clean Files" --> Proxy

    Proxy --> C_Gitleaks
    Proxy --> C_Semgrep
    Proxy --> C_OSV

    C_Gitleaks & C_Semgrep & C_OSV -- "Raw Findings" --> AuditLedger
    AuditLedger --> Trigger --> Postgres

    AuditLedger -- "Frozen Summary Only" --> SchemaValidator
    SchemaValidator --> LLM
    LLM -- "Executive Briefing Text" --> SPA
```

---

## 🔬 Tri-Engine Scanning Pipeline

FireCrow orchestrates three specialized security engines. Each scanner focuses on an independent vulnerability domain, eliminating tool bias and delivering comprehensive coverage:

| Scanner Engine | Pinned Version | Security Domain | Target Inputs | Output Mapping |
| :--- | :--- | :--- | :--- | :--- |
| **Gitleaks** | `v8.18.2` | High-Entropy Secrets, API Keys, Private Keys, Hardcoded Tokens | Source files, commit diffs, git history, configuration files | `CWE-798: Use of Hard-coded Credentials` (Secret redacted) |
| **Semgrep** | `v1.64.0` | SAST, AST Taint Analysis, OWASP Top 10, Code Quality | Polyglot source code (Rust, JS/TS, Python, Go, Java, etc.) | `CWE-89 (SQLi)`, `CWE-79 (XSS)`, `CWE-22 (Path Traversal)`, etc. |
| **OSV-Scanner** | `v1.6.2` | Software Supply Chain, Dependency CVEs, Transitive Risks | Lockfiles (`package-lock.json`, `Cargo.lock`, `poetry.lock`, etc.) | Upstream CVE / GHSA references with CVSS 3.1 severity scores |

### Canonical Audit Finding Schema (v1)

All scanner outputs are normalized into an immutable, unified finding shape:

```json
{
  "finding_id": "FC-SEC-01",
  "scanner": "gitleaks v8.18.2",
  "rule_id": "generic-api-key",
  "title": "Hardcoded JSON Web Token Secret in Configuration",
  "severity": "critical",
  "cwe": "CWE-798: Use of Hard-coded Credentials",
  "cvss_score": 8.9,
  "file_path": "backend/src/config.rs",
  "line_number": 44,
  "evidence": "let secret_key = b\"[REDACTED_HIGH_ENTROPY_TOKEN]\";",
  "fingerprint": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "remediation": "Load secrets via environment variables or cloud KMS. Rotate the exposed key immediately."
}
```

---

## 🛡️ Security Invariants & Hardening

FireCrow has undergone rigorous formal security hardening. All identified vulnerabilities from initial baselines have been fully remediated and verified with regression suites:

| ID | Dimension | Threat Mitigated | Technical Enforcement Mechanism | Verification Test |
| :---: | :--- | :--- | :--- | :--- |
| **F1** | **Host Boundary** | Container escape / host takeover | `SandboxManager` denies `/var/run/docker.sock`, privileged mounts, and unauthorized devices | `tests/docker_host_boundary.rs` |
| **H1** | **Resource Bounds** | Decompression bombs & memory exhaustion | Stream-bounded HTTP chunking with incremental gzip/pax checks; 50MB unpack ceiling | `tests/repo_fetch_bounds.rs` |
| **H2** | **Network Egress** | SSRF & internal network pivoting | Container network policy blocks metadata (`169.254.169.254`), loopback & RFC1918 addresses | `tests/osv_egress_policy.rs` |
| **H3** | **DB Lifecycle** | State race conditions & skipped stages | PostgreSQL `BEFORE UPDATE` trigger (`audit_jobs_lifecycle_guard_fn`) enforces state transitions | `tests/db_lifecycle_guard.rs` |
| **H4** | **Session Security** | Token leakage via URLs / storage | REST API uses strictly HttpOnly/Secure/SameSite cookies; refresh token lifetime capped at 7 days | `tests/session_security.rs` |
| **M1** | **Report Injection** | Stored XSS via audit outputs | Strict Content Security Policy (`default-src 'self'`) and sanitized sandbox download headers | `src/middleware/security_headers.rs` |
| **M2** | **Rate Limiting** | DoS / scan flooding | Axum `DefaultBodyLimit` (10MB) and per-route rate limiting via `tower_governor` | `src/app.rs` |
| **M3** | **Data Retention** | Indefinite session / log retention | Housekeeping background worker deterministically purges expired sessions & delivery logs | `src/services/housekeeping.rs` |
| **L4** | **Container Defense** | Privilege escalation | Micro-containers launched with `--cap-drop=ALL` and `--security-opt=no-new-privileges` | `src/services/sandbox.rs` |
| **L10**| **AI Isolation** | AI hallucinations influencing security truth | Structural schema validators reject invented findings, modified severities, or score tampering | `tests/ai_narrative_persistence.rs` |

---

## ⚡ Quick Start (Local Development)

### Prerequisites

- **Docker**: Docker Engine 24+ running (`docker ps` functional)
- **Rust**: 1.85+ with `cargo` installed
- **Node.js**: 20+ with `npm`
- **OpenSSL & curl**: For cryptographic key generation and local probes

### 1. One-Command Dev Launcher (Recommended)

FireCrow provides an automated, safety-tested launcher script (`./scripts/dev.sh`):

```bash
# 1. Clone repository
git clone https://github.com/johan-droid/Fire-Crow-.git
cd Fire-Crow-

# 2. Check local tools, ports, and prerequisites
./scripts/dev.sh check

# 3. Safe initial setup (generates secure keys, never overwrites existing .env.local)
./scripts/dev.sh setup

# 4. Start isolated PostgreSQL container (loopback only 55433) + Backend (:8000) + Frontend (:3000)
./scripts/dev.sh start
```

Once started, access your local instance:
- **Frontend Dashboard**: [http://localhost:3000](http://localhost:3000)
- **Backend API**: [http://localhost:8000/api/v1](http://localhost:8000/api/v1)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

### 2. Inspecting, Testing & Stopping

```bash
# Check service health and running PIDs
./scripts/dev.sh status

# Tail service logs (all credentials and secrets are automatically redacted)
./scripts/dev.sh logs backend
./scripts/dev.sh logs frontend
./scripts/dev.sh logs db

# Execute local smoke tests (safe validation; no scans or external deliveries)
./scripts/dev.sh smoke

# Gracefully stop only the processes and container started by the launcher
./scripts/dev.sh stop
```

<details>
<summary><b>🛠️ Manual Setup Instructions (Without Launcher)</b></summary>

If you prefer running services independently:

```bash
# Terminal 1: Database (PostgreSQL)
docker run -d --name firecrow-dev-postgres \
  -e POSTGRES_USER=firecrow \
  -e POSTGRES_PASSWORD=firecrow_dev_password \
  -e POSTGRES_DB=firecrow \
  -p 127.0.0.1:55433:5432 \
  postgres:16-alpine

# Terminal 2: Rust Backend
cd backend
cp .env.example .env.local
# Set DATABASE_URL=postgres://firecrow:firecrow_dev_password@127.0.0.1:55433/firecrow
cargo run

# Terminal 3: React Frontend
cd frontend
cp .env.example .env.local
npm install
npm run dev
```

</details>

---

## 📦 Deployment Guide

### A. Deploy Frontend to Vercel

1. Import the repository into your [Vercel Dashboard](https://vercel.com).
2. Set **Framework Preset** to `Vite`.
3. Set **Root Directory** to `./` (or `frontend`).
4. Set **Environment Variables**:
   - `VITE_API_URL`: `https://your-backend.onrender.com/api/v1` *(**Important**: Must include the `/api/v1` prefix. A bare domain causes 404 errors on API routes).*
5. **Fail-Closed Routing Posture**: Committed `vercel.json` files deliberately contain **no** `/api` upstream proxy rewrite. Because Vercel does not interpolate runtime environment variables in rewrites, committed rewrites would leak Preview traffic into production. Traffic routing is instead configured cleanly per-environment via `VITE_API_URL`.

### B. Deploy Backend to Render

1. Create a **New Blueprint Instance** on [Render](https://render.com) using the included `render.yaml` or create a **Docker Web Service**:
   - **Environment**: `Docker`
   - **Dockerfile Path**: `backend/Dockerfile`
   - **Context**: `.` (Repository root)
2. Attach a **Render PostgreSQL** database.
3. Configure **Environment Variables**:
   ```ini
   DATABASE_URL=postgres://user:pass@render-db-host:5432/firecrow
   SECRET_KEY=<generate via: openssl rand -base64 48>
   ENCRYPTION_KEY=<generate via: openssl rand -base64 48>
   FRONTEND_URL=https://your-firecrow-app.vercel.app
   CORS_ORIGINS=https://your-firecrow-app.vercel.app
   AUTH_COOKIE_SAMESITE=none
   AUTH_COOKIE_SECURE=true
   CSRF_ENABLED=true
   ```
   *(Note: Do not manually set `PORT`—Render injects it automatically and the Axum service binds accordingly).*

---

## 📡 API Endpoints & Health Probes

FireCrow enforces an explicit, uniform API path contract under `/api/v1/*`:

### Platform Health & Diagnostics

| Method | Endpoint | Purpose | Access Scope |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Render / Docker container healthcheck | Platform Probes |
| `GET` | `/api/v1/health/live` | Process liveness probe (Engine up) | Public |
| `GET` | `/api/v1/health/ready` | Database readiness probe (`SELECT 1`) | Public |
| `GET` | `/api/v1/health/deep` | Full subsystem audit (DB, storage, Docker scanner availability) | Public |

### Core Authentication & Audit Operations

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/v1/auth/register` | Register a new user account | No |
| `POST` | `/api/v1/auth/login` | Authenticate user & issue HttpOnly session cookie | No |
| `POST` | `/api/v1/auth/logout` | Revoke session cookie | **Yes** |
| `GET` | `/api/v1/auth/me` | Fetch authenticated user profile & balance | **Yes** |
| `POST` | `/api/v1/audits` | Submit a repository audit job (`repo_url`, `branch`, `commit_sha`) | **Yes** |
| `GET` | `/api/v1/audits` | List all historical audits owned by user | **Yes** |
| `GET` | `/api/v1/audits/:id` | Fetch audit job status and canonical summary | **Yes** |
| `GET` | `/api/v1/audits/:id/executions/:exec_id` | Fetch full canonical findings ledger for an attempt | **Yes** |
| `GET` | `/api/v1/audits/:id/report` | Download standardized report artifact (JSON / HTML / PDF) | **Yes** |

---

## 📂 Repository Structure

```text
Fire-Crow-/
├── .github/workflows/          # Automated GitHub Actions CI/CD pipelines
├── backend/                    # Core Rust (Axum) scanning orchestrator & backend
│   ├── migrations/             # SQLx PostgreSQL schema migrations
│   ├── scanners/semgrep/       # Pinned local SAST rule definitions
│   ├── src/
│   │   ├── agents/             # Vulnerability acquisition & scanner execution
│   │   │   ├── fetch.rs        # Stream-bounded repository intake & archive unpacker
│   │   │   ├── scanner.rs      # Docker container sandbox orchestrator
│   │   │   └── mod.rs          # Agent module definitions
│   │   ├── api/                # Axum REST routes (auth, audits, reports, health)
│   │   ├── middleware/         # Cookie auth, CSRF, security headers, rate limiting
│   │   ├── models/             # Database entity models with secret-scrubbed Debug
│   │   ├── orchestrator/       # State machine, worker pool, and delivery queue
│   │   ├── schemas/            # Canonical Audit v1, AI narrative, report models
│   │   ├── services/           # Container sandbox manager, egress policy, LLM provider
│   │   ├── app.rs              # Axum router configuration & layer assembly
│   │   └── main.rs             # Application bootstrapper & migration runner
│   ├── tests/                  # Integration, unit, and regression test suites
│   ├── Cargo.toml              # Rust crate manifest & dependencies
│   └── Dockerfile              # Multi-stage production container build (rust:1.85-bookworm)
├── documentation/              # Technical specifications & security documentation
│   ├── DEVELOPER_GUIDE.md      # Unified developer & deployment reference
│   ├── FINAL_SECURITY_HARDENING_REPORT.md # Verification report for all security findings
│   ├── INTERNAL_SECURITY_AUDIT.md # Historical baseline security audit
│   ├── API_TOPOLOGY.md         # Public API origin contract & proxy specification
│   └── BOOTSTRAP_ADMIN.md      # Initial administrative user bootstrap guide
├── frontend/                   # Modern React 19 + TypeScript + Vite SPA
│   ├── src/
│   │   ├── api/                # Single-origin API client, error mapping & routing guard
│   │   ├── dashboard/          # Interactive audit table, severity metrics & trend charts
│   │   ├── landing/            # Flagship product landing page & architectural showcase
│   │   ├── App.tsx             # Root application component & routing state
│   │   └── main.tsx            # Client entrypoint
│   ├── public/                 # Brand assets, icons, and logo graphics
│   ├── package.json            # Node.js dependencies & scripts
│   ├── vercel.json             # Vercel SPA configuration
│   └── vite.config.ts          # Vite build config & local proxy setup
├── scripts/
│   ├── dev.sh                  # Comprehensive local development lifecycle launcher
│   └── test-dev.sh             # Test suite for dev launcher functionality
├── docker-compose.yml          # Container configuration (PostgreSQL 16 + Redis + Docker Proxy)
├── render.yaml                 # Render Infrastructure-as-Code blueprint manifest
└── vercel.json                 # Root Vercel deployment manifest
```

---

## 📚 Documentation Suite

Explore the comprehensive technical documentation in the [`documentation/`](documentation/) directory:

- 📘 **[Unified Developer & Deployment Guide](documentation/DEVELOPER_GUIDE.md)**: Exhaustive manual for local development, production configuration, and failure remedies.
- 🛡️ **[Final Security Hardening Report](documentation/FINAL_SECURITY_HARDENING_REPORT.md)**: Detailed audit report with proof of remediation for findings F1 through L11.
- 🌐 **[API Topology & Public Origin Contract](documentation/API_TOPOLOGY.md)**: Specification for single-origin routing, CORS policies, and cookie mode isolation.
- 🔑 **[Administrative Bootstrap Guide](documentation/BOOTSTRAP_ADMIN.md)**: Setup instructions for role-based access control and initial admin provisioning.
- 📜 **[Historical Security Audit Baseline](documentation/INTERNAL_SECURITY_AUDIT.md)**: The original frozen audit record that guided the hardening initiative.

---

## 🛠️ Technology Stack

| Layer | Technologies & Tools |
| :--- | :--- |
| **Backend Core** | [Rust 1.85+](https://www.rust-lang.org/) • [Axum 0.7](https://github.com/tokio-rs/axum) • [Tokio](https://tokio.rs/) • [SQLx 0.8](https://github.com/launchbadge/sqlx) • [Tower](https://github.com/tower-rs/tower) |
| **Frontend UI** | [React 19](https://react.dev/) • [TypeScript 5.7+](https://www.typescriptlang.org/) • [Vite 8.1](https://vitejs.dev/) • [GSAP](https://greensock.com/) • [Lucide Icons](https://lucide.dev/) |
| **Database & Cache**| [PostgreSQL 16](https://www.postgresql.org/) (Triggers & Migrations) • [Redis 7](https://redis.io/) (Rate limits & pub/sub) |
| **Security Scanners**| [Gitleaks v8.18.2](https://github.com/gitleaks/gitleaks) • [Semgrep v1.64.0](https://semgrep.dev/) • [OSV-Scanner v1.6.2](https://github.com/google/osv-scanner) |
| **Sandboxing & Proxy**| [Docker Engine](https://www.docker.com/) • [docker-socket-proxy v0.5.0](https://github.com/Tecnativa/docker-socket-proxy) |
| **Deployment Cloud**| [Vercel](https://vercel.com/) (Frontend SPA) • [Render](https://render.com/) (Docker Web Service & Managed Postgres) |

---

## 📄 License & Credits

Distributed under the **MIT License**. See [`LICENSE`](https://opensource.org/licenses/MIT) for terms.

**FireCrow** is proudly engineered by **NEXT LAB.inc** as a flagship repository security auditing and deterministic vulnerability intelligence platform.

<div align="center">
<sub>Built with precision and zero trust. © 2026 NEXT LAB.inc. All rights reserved.</sub>
</div>
