<div align="center">

# 🦅 Fire Crow

### Autonomous Agentic Security Intelligence & Application Hardening Platform

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Axum](https://img.shields.io/badge/Axum-0.7-blue.svg?style=for-the-badge&logo=tokio)](https://github.com/tokio-rs/axum)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon-336791.svg?style=for-the-badge&logo=postgresql)](https://neon.tech/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg?style=for-the-badge&logo=react)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-5.0-646CFF.svg?style=for-the-badge&logo=vite)](https://vitejs.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

*Fire Crow coordinates sandboxed security LLM agents to map source code repositories, execute safe vulnerability exploit simulations, enforce enterprise IAM/PAM, and compile compliance-ready PDF reports.*

[Key Features](#-key-features) • [Architecture](#-architecture) • [Getting Started](#-getting-started) • [Environment Setup](#-environment-setup) • [API Documentation](#-documentation)

</div>

---

## 🌟 Key Features

### 🤖 Autonomous Agentic Code Auditing
- **LLM Reasoning Loops**: Integrates Google Gemini Security models for deep code analysis, threat modeling, and automated CWE/OWASP classification.
- **Automated Remediation**: Generates ready-to-merge patch snippets and code fixes for detected vulnerabilities.
- **Attack Graph Generation**: Persists multi-node chained attack vectors directly to PostgreSQL graph tables (`attack_graph_nodes` & `attack_graph_edges`).

### 🔒 Enterprise Identity & Access Control
- **Dual Authentication**: Full support for both `Authorization: Bearer <JWT>` headers and HTTP-Only session cookies (`access_token`, `refresh_token`).
- **OAuth 2.0 & OIDC**: Integrated GitHub OAuth and Google OpenID Connect single sign-on flows.
- **Multi-Factor Authentication (MFA)**: Built-in TOTP authenticator app enrollment, barcode QR generation, and emergency recovery codes.
- **Privileged Access Management (PAM)**: Just-in-time privilege elevation requests, ticket reference tracking, and admin approval workflows.
- **Multi-Tenancy**: Organization and tenant data isolation with custom domain verifications.

### 🎨 State-of-the-Art Dashboard
- **Glassmorphism UI**: Minimalist, dark-mode React control panel with real-time health scores, severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), and animated telemetry feeds.
- **Interactive Scans & Finding Drawer**: Trigger automated audits on Git repositories and view granular finding details with one-click code remediations.

---

## 🏗️ Architecture

```mermaid
graph TD
    Client[Operator Browser / SPA] -->|HTTPS / Bearer / Cookie| Axum[Axum Rust Web Server]
    Axum -->|Session & Auth| AuthMiddleware[Auth Middleware & Anti-Replay Cache]
    AuthMiddleware -->|Revocation Check| Redis[(Redis Cache)]
    Axum -->|SQL Queries| Postgres[(Neon PostgreSQL DB)]
    Axum -->|Agent Orchestration| Orchestrator[Rust State Machine Orchestrator]
    Orchestrator -->|Docker Container API| Sandbox[Sandboxed Docker Scanners]
    Orchestrator -->|LLM Reasoning| Gemini[Gemini Security API]
    Axum -->|Artifact Upload| R2[Cloudflare R2 / S3 Reports]
```

---

## 🚀 Getting Started

### Prerequisites

Ensure you have the following installed on your host system:
- **Rust** (cargo `1.75+`)
- **Node.js** (`v18+`) & `npm`
- **PostgreSQL** or **Neon PostgreSQL** account

### 1. Clone the Repository

```bash
git clone https://github.com/johan-droid/Fire-Crow-.git
cd Fire-Crow-
```

### 2. Install Dependencies

```bash
# Install frontend node modules
cd frontend
npm install
cd ..
```

### 3. Configure Environment Variables

Create or edit your `backend/.env.local` file:

```env
# Database & Core Security Keys
DATABASE_URL="postgresql://user:password@ep-host.neon.tech/neondb?sslmode=require"
SECRET_KEY="your-min-32-character-random-secret-key"
ENCRYPTION_KEY="your-min-32-character-data-encryption-key"

# OAuth Credentials
GITHUB_CLIENT_ID="your_github_client_id"
GITHUB_CLIENT_SECRET="your_github_client_secret"
GITHUB_TOKEN="ghp_your_personal_access_token"

GOOGLE_CLIENT_ID="your_google_client_id"
GOOGLE_CLIENT_SECRET="your_google_client_secret"

# AI Security Models
GEMINI_API_KEY="your_gemini_api_key"

# Service URLs
FRONTEND_URL="http://localhost:5173"
BACKEND_BASE_URL="http://localhost:8000"
```

### 4. Run the Platform

Start both the Axum backend and Vite React frontend concurrently:

```bash
npm run dev
```

Or start the Rust backend manually:

```bash
cd backend
cargo run
```

Access the frontend dashboard at `http://localhost:5173`.

---

## 📁 Repository Structure

```text
Fire-Crow-/
├── backend/                  # Rust Axum Web Server & Agent Orchestrator
│   ├── migrations/           # SQLx database schema migrations
│   ├── src/
│   │   ├── agents/           # LLM agent definitions & scanner runners
│   │   ├── api/              # Axum REST route handlers (auth, sso, pam, iam, audit...)
│   │   ├── config.rs         # Settings model & environment loader
│   │   ├── middleware/       # Auth, CORS, Request ID, Rate limiters
│   │   ├── models/           # SQLx FromRow data structures
│   │   ├── orchestrator/     # Native Rust state machine scan engine
│   │   ├── services/         # Core domain logic (auth, crypto, storage, mfa...)
│   │   └── main.rs           # Application entry point
│   └── Cargo.toml
├── frontend/                 # React 18 + Vite Control Panel
│   ├── src/
│   │   ├── App.tsx           # Security Console Dashboard & Auth UI
│   │   ├── index.css         # Glassmorphism design tokens & animations
│   │   └── main.tsx
│   └── package.json
├── API_DOCUMENTATION.md      # Comprehensive REST & API Key Manual
└── GITHUB_AUTH.md            # GitHub OAuth Setup & Integration Guide
```

---

## 📖 Documentation

- 📘 [API Reference Manual](API_DOCUMENTATION.md) — Endpoint specs, input schemas, headers, and Service Account API keys.
- 🔑 [GitHub OAuth Integration Guide](GITHUB_AUTH.md) — Step-by-step setup for GitHub developer applications.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
