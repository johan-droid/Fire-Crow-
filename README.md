<div align="center">

# 🦅 FireCrow

### Enterprise Repository Security Auditing & Deterministic Scanning Engine

[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Axum](https://img.shields.io/badge/Axum-0.7-blue.svg?style=for-the-badge&logo=tokio)](https://github.com/tokio-rs/axum)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791.svg?style=for-the-badge&logo=postgresql)](https://www.postgresql.org/)
[![React](https://img.shields.io/badge/React-19-61DAFB.svg?style=for-the-badge&logo=react)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8.1-646CFF.svg?style=for-the-badge&logo=vite)](https://vitejs.dev/)
[![Vercel Ready](https://img.shields.io/badge/Vercel-Frontend-black.svg?style=for-the-badge&logo=vercel)](https://vercel.com)
[![Render Ready](https://img.shields.io/badge/Render-Backend-46E3B7.svg?style=for-the-badge&logo=render)](https://render.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

*FireCrow fetches an immutable GitHub repository snapshot, executes real security scanners (Gitleaks, OSV, Semgrep) inside hardened Docker containers, normalizes findings into Canonical Audit v1, persists an immutable database record, and renders byte-deterministic security reports. An optional AI narrative layer explains findings without ever influencing security truth.*

> **Security Core Invariant**: Nothing is reported that did not originate directly from a sandboxed scanner execution. `failure != clean`.

**Documentation Quick Links**:
- [📘 Unified Developer & Deployment Guide](documentation/DEVELOPER_GUIDE.md)
- [🛡️ Final Security Hardening & Audit Report](documentation/FINAL_SECURITY_HARDENING_REPORT.md)
- [📜 Historical Security Audit Baseline](documentation/INTERNAL_SECURITY_AUDIT.md)

</div>

---

## 🚀 Key Highlights

- **Stream-Bounded Acquisition**: Incremental HTTP response chunking & pax inflation controls prevent memory exhaustion and decompression bombs (max 50MB limit).
- **Hardened Ephemeral Sandboxes**: Scanners run in unprivileged containers with read-only filesystems, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, and strict memory/PID caps.
- **Canonical Audit v1 Engine**: Deduplicates findings across scanners by exact identity (`scanner + rule + fingerprint + location + evidence digest`) and redacts secret patterns.
- **Database-Authoritative Lifecycle**: State transitions are strictly enforced via PostgreSQL `BEFORE UPDATE` triggers, preventing illegal job state mutations.
- **Total AI Truth Isolation**: The optional Gemini AI narrator reads only finalized audit summaries; it cannot create findings, alter severities, or modify risk scores.
- **Zero-Trust Auth & IDOR Protection**: HttpOnly/Secure/SameSite cookie authentication replaces URL query tokens, backed by strict ownership gates on all endpoints.

---

## 🏗️ Architecture Flow

```text
       ┌────────────────────────────────────────────────────────┐
       │             Vercel Frontend (React 19 / Vite)          │
       └───────────────────────────┬────────────────────────────┘
                                   │ HTTPS (HttpOnly Session Cookie / Strict CSRF)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │             Render Backend (Rust Axum Service)         │
       └─────┬─────────────────────┬──────────────────────┬─────┘
             │                     │                      │
             ▼                     ▼                      ▼
  ┌───────────────────┐ ┌────────────────────┐ ┌──────────────────────┐
  │ PostgreSQL Store  │ │ Stream Fetch Agent │ │ Sandboxed Containers │
  │ (Render Database) │ │ (Bounded Tarball)  │ │ Gitleaks/OSV/Semgrep │
  └───────────────────┘ └────────────────────┘ └──────────────────────┘
             │
             ▼
  ┌─────────────────────────────────────────────────────────────┐
  │       Canonical Audit v1 Normalization & Report Store       │
  └───────────────────────────┬─────────────────────────────────┘
                              │ Redacted Canonical Summary
                              ▼
  ┌─────────────────────────────────────────────────────────────┐
  │            Optional AI Explanation Layer (Gemini)           │
  └─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

- **Backend**: Rust 1.85+, Axum 0.7, SQLx (PostgreSQL 16), Tokio, Serde.
- **Frontend**: React 19, TypeScript 5.7+, Vite 8.1, Vanilla CSS Design Tokens.
- **Scanners**: Gitleaks v8.18.2, OSV-Scanner v1.6.2, Semgrep v1.64.0.
- **Deployment**: Vercel (Frontend SPA & API Proxy) + Render (Containerized Backend & Managed Postgres).

---

## ⚡ Quick Start (Local Development)

### Prerequisites
- Docker & Docker Compose
- Node.js 20+ & `npm`
- Rust 1.85+ (`cargo`)

### 1. Clone & Start Infrastructure
```bash
git clone https://github.com/johan-droid/Fire-Crow-.git
cd Fire-Crow-

# Start local PostgreSQL instance
docker run -d --name firecrow-postgres \
  -e POSTGRES_DB=firecrow_dev \
  -e POSTGRES_USER=firecrow \
  -e POSTGRES_PASSWORD=firecrow_pass \
  -p 55433:5432 postgres:16-alpine
```

### 2. Run Backend
```bash
cd backend
export DATABASE_URL="postgres://firecrow:firecrow_pass@127.0.0.1:55433/firecrow_dev"
export SECRET_KEY="local_dev_secret_key_minimum_32_bytes_long_change_me!"
export ENCRYPTION_KEY="local_dev_encryption_key_minimum_32_bytes_long!"
export FRONTEND_URL="http://localhost:5173"
export CORS_ORIGINS="http://localhost:5173"

cargo run
```

### 3. Run Frontend
```bash
cd ../frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 📦 Deployment Guide

### Deploying Frontend to Vercel
1. Import repository into [Vercel](https://vercel.com).
2. Set **Framework Preset** to `Vite`.
3. Set **Environment Variable**:
   - `VITE_API_URL`: Your deployed Render backend URL (e.g. `https://firecrow-backend.onrender.com`).
4. Vercel automatically proxies `/api/*` to the Render backend via `vercel.json`.

### Deploying Backend to Render
1. Create a **New Blueprint Instance** on [Render](https://render.com) using `render.yaml` OR create a **Web Service**:
   - **Environment**: `Docker`
   - **Dockerfile Path**: `backend/Dockerfile`
2. **Configure Environment Variables**:
   - `DATABASE_URL`: Render PostgreSQL Connection String
   - `SECRET_KEY`: `openssl rand -base64 48`
   - `ENCRYPTION_KEY`: `openssl rand -base64 48`
   - `FRONTEND_URL`: Your Vercel application URL
   - `CORS_ORIGINS`: Your Vercel application URL

---

## 🔒 Security Invariants & Compliance

| Security Dimension | Enforcement Mechanism | Status |
| :--- | :--- | :--- |
| **Host Boundary** | Hardened Docker flag validation rejecting `/var/run/docker.sock` & privileged mounts | **VERIFIED (F1)** |
| **Resource Bounds** | Incremental streaming HTTP & gzip inflation bounds (max 50MB total) | **VERIFIED (H1)** |
| **Network Egress** | OSV network policy blocking link-local (`169.254.169.254`), loopback & private networks | **VERIFIED (H2)** |
| **DB Lifecycle** | PostgreSQL BEFORE UPDATE trigger enforcing state machine transitions | **VERIFIED (H3)** |
| **Session Security** | HttpOnly/Secure/SameSite cookies replacing query tokens; 7d refresh TTL | **VERIFIED (H4)** |
| **Security Truth** | Scanner failure/timeout/cancel yields `NULL` score and incomplete audit status | **VERIFIED (Truth)** |
| **AI Isolation** | Structural validator rejects invented findings, severity edits, or score mutations | **VERIFIED (L10)** |

For full details, review the [Final Security Hardening Report](documentation/FINAL_SECURITY_HARDENING_REPORT.md).

---

## 📂 Repository Layout

```text
Fire-Crow-/
├── .github/workflows/          # GitHub Actions CI
├── backend/                    # Rust (Axum) web server & scanning orchestrator
│   ├── migrations/             # PostgreSQL SQLx schema migrations
│   ├── scanners/semgrep/       # Pinned local SAST ruleset
│   ├── src/
│   │   ├── agents/             # Stream-bounded fetch & scanner execution agents
│   │   ├── api/                # REST API endpoints & route handlers
│   │   ├── middleware/         # Cookie auth, CSRF, security headers, rate limits
│   │   ├── models/             # Database entity models with secret-safe Debug
│   │   ├── orchestrator/       # State machine, worker pool, and delivery
│   │   ├── schemas/            # Canonical Audit v1, AI narrative, report schemas
│   │   └── services/           # Container sandbox, egress guard, LLM provider
│   ├── tests/                  # Integration, unit, and regression test suite
│   └── Cargo.toml              # Rust crate manifest
├── documentation/              # Architecture, security & deployment guides
│   ├── DEVELOPER_GUIDE.md      # Unified Developer & Deployment Guide
│   ├── FINAL_SECURITY_HARDENING_REPORT.md # Comprehensive security audit report
│   └── INTERNAL_SECURITY_AUDIT.md       # Historical audit baseline
├── frontend/                   # React 19 + TypeScript + Vite SPA (Vercel Ready)
├── render.yaml                 # Render Infrastructure-as-Code manifest
└── vercel.json                 # Vercel deployment manifest
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
