# Repository Architecture & File Map

This guide provides a structural index of the FireCrow codebase and a decision matrix for routing code changes to the correct files and subsystems.

---

## 1. Top-Level Directory Layout

```
.
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions CI workflow (Rust check, test, Clippy, Vite build)
├── backend/                     # Axum 0.7 + Tokio async Rust backend service
│   ├── Cargo.toml               # Rust dependencies and crate workspace configuration
│   ├── Cargo.lock               # Exact pinned Rust dependency lockfile
│   ├── Dockerfile               # Multi-stage production container build (Debian bookworm-slim)
│   ├── migrations/              # PostgreSQL SQL migrations (schema, tables, lifecycle triggers)
│   ├── scanners/                # Scanner-specific configurations
│   │   └── semgrep/             # Custom Semgrep SAST rule definitions (firecrow-sast.yml)
│   └── src/                     # Backend application source code
├── frontend/                    # React 19 + TypeScript 5.7 + Vite single-page application
│   ├── package.json             # Frontend dependencies and npm scripts
│   ├── tsconfig.json            # Base TypeScript configuration
│   ├── tsconfig.app.json        # Application-specific compiler options
│   ├── tsconfig.node.json       # Tooling/Vite-specific compiler options
│   ├── vite.config.ts           # Vite bundler configuration, build target, dev server proxy
│   ├── vercel.json              # Vercel deployment routing (fail-closed static rewrite)
│   └── src/                     # React application source code
├── scripts/                     # Local developer experience and automation scripts
│   ├── dev.sh                   # Unified local development launcher (DB, Backend, Frontend)
│   └── test-dev.sh              # Headless integration test suite for dev environment
├── documentation/               # Historic/specialized audit documentation
│   ├── API_TOPOLOGY.md          # Endpoint route reference
│   ├── DEVELOPER_GUIDE.md       # Onboarding reference
│   └── INTERNAL_SECURITY_AUDIT.md # Security audit findings
├── docs/                        # Complete Engineering Handbook (this documentation system)
├── render.yaml                  # Infrastructure-as-code blueprint for Render deployment
└── README.md                    # Primary repository landing and quickstart guide
```

---

## 2. Backend Subsystem Layout (`backend/`)

```
backend/
├── migrations/
│   └── 001_initial_schema.sql       # Initial tables: users, sessions, audit_jobs, triggers
├── scanners/
│   └── semgrep/
│       └── firecrow-sast.yml        # Custom OWASP & CWE rules executed by Semgrep engine
└── src/
    ├── main.rs                      # Binary entrypoint: initializes tracing, config, DB pool, Axum
    ├── app.rs                       # Axum router construction, route binding, middleware mounting
    ├── config.rs                    # Strongly typed environment configuration (AppConfig) & validation
    ├── agents/                      # Orchestration & scanner execution pipeline
    │   ├── mod.rs                   # Agent module exports
    │   ├── fetch.rs                 # FetchAgent: Stream-bounded tarball download & unpack (100MB download / 150MB unpack ceiling)
    │   ├── scanner.rs               # ScannerAgent: Ephemeral Docker container manager (Gitleaks/Semgrep/OSV)
    │   └── summary.rs               # SummaryAgent: Isolated Google Gemini executive narrative generator
    ├── schemas/                     # Core domain data contracts
    │   ├── mod.rs
    │   ├── audit_state.rs           # AuditJob entity & lifecycle state enum (queued, running, completed, failed)
    │   └── canonical_audit.rs       # Canonical Audit Schema v1 struct definitions & serde serializers
    ├── db/                          # Database connection and queries
    │   ├── mod.rs                   # Database connection pool manager (sqlx::PgPool)
    │   └── audit_repo.rs            # CRUD queries for audit jobs, users, and audit records
    ├── middleware/                    # Security & authentication subsystem
    │   ├── auth.rs                    # Session extractors (`AuthenticatedUser`/`AdminUser`), IDOR owner assertion
    │   └── csrf.rs                    # Origin-header allowlist CSRF guard for mutating methods (no CSRF token)
    ├── services/                      # Business services
    │   ├── auth.rs                    # Argon2id password hashing, MFA/TOTP challenges, GitHub OAuth state
    │   ├── session.rs                 # Session store & revocation
    │   ├── egress_policy.rs           # OSV egress allowlist & `OSV_EGRESS_PROXY` validation (fail-closed)
    │   └── sandbox.rs                 # Ephemeral scanner container manager
    └── routes/                      # HTTP endpoint controllers
        ├── auth.rs                  # /api/auth routes (login, logout, session, mfa)
        ├── audit.rs                 # /api/audit routes (run, status, list, export)
        └── health.rs                # /health, /healthz, /ready probes
```

---

## 3. Frontend Subsystem Layout (`frontend/`)

```
frontend/
├── public/                          # Static assets, favicon, logo images
├── src/
│   ├── main.tsx                     # React application root entrypoint
│   ├── App.tsx                      # Root shell: auth state + URL routing (/, /login, /console/:window)
│   ├── dash.tsx                     # Console primitives: ScoreRing, StatusPill, SeverityBars, fmt/time helpers
│   ├── scene.tsx                    # Landing hero canvas (HeroCanvas3D)
│   ├── BrandMark.tsx                # Brand mark shared by console + landing
│   ├── dashboard.css                # Console layout, grid, and --fc-* tokens
│   ├── console-theme.css            # Console reset / overrides
│   ├── index.css                    # Base tokens (--bg-*, --text-*, --apple-*), typography, reset
│   ├── dashboard/                   # Console widgets and pure view state
│   │   ├── MetricCard.tsx           # KPI card
│   │   ├── AuditTable.tsx           # Audit list/table (sort + filter)
│   │   ├── ActionSidebar.tsx        # Sidebar actions
│   │   ├── Dropdown.tsx             # Accessible menu-button primitive (portal, APG keyboard)
│   │   ├── console.ts               # Pure, unit-tested filter/sort/attention state
│   │   └── dropdown.css
│   ├── api/                         # Typed fetch client, DTOs, SSE, health, toasts
│   │   ├── client.ts                # Requests: credentials, retry, timeouts, typed responses
│   │   ├── api-base.ts              # API origin resolution + validation
│   │   └── errors.ts                # ApiError, backoff, SPA-fallback detection
│   ├── LandingPage.tsx              # Public marketing landing page (mounted at /)
│   ├── landing/                     # Landing page source
│   │   ├── components/BrandLogos.tsx # NextLab symbol (landing + login)
│   │   ├── data/landingData.ts      # Capabilities, FAQ, pipeline stages, sample findings
│   │   └── site/                    # Ledger.tsx + landing-site.css (--lp-* tokens on .lp)
│   └── LoginPage.tsx                # Sign-in page (credentials + TOTP)
```

---

## 4. "Where Do I Make This Change?" Lookup Matrix

Use this matrix to identify exactly which files must be created or modified for common development tasks:

| Goal / Task Description | Primary Files to Touch | Supporting / Test Files |
| :--- | :--- | :--- |
| **Add a new API endpoint** | [backend/src/routes/](../../../../../../backend/src/routes)<br/>[backend/src/app.rs](../../../../../../backend/src/app.rs) | [frontend/src/api/client.ts](../../../../../../frontend/src/api/client.ts)<br/>[docs/api/README.md](../../../../../../docs/api/README.md) |
| **Add a new scanner engine** | [backend/src/agents/scanner.rs](../../../../../../backend/src/agents/scanner.rs)<br/>[backend/src/schemas/canonical_audit.rs](../../../../../../backend/src/schemas/canonical_audit.rs) | [docs/deployment/containers.md](../../../../../../docs/deployment/containers.md)<br/>[docs/development/maintenance.md](../../../../../../docs/development/maintenance.md) |
| **Update SAST scanning rules** | [backend/scanners/semgrep/firecrow-sast.yml](../../../../../../backend/scanners/semgrep/firecrow-sast.yml) | Semgrep unit test fixtures |
| **Add a database table / column** | `backend/migrations/` (new SQL file)<br/>[backend/src/db/](../../../../../../backend/src/db) | [backend/src/schemas/](../../../../../../backend/src/schemas) |
| **Modify audit state machine** | `backend/migrations/` (update trigger `audit_jobs_lifecycle_guard_fn`)<br/>[backend/src/schemas/audit_state.rs](../../../../../../backend/src/schemas/audit_state.rs) | [docs/architecture/adr/003-execution-lifecycle.md](../../../../../../docs/architecture/adr/003-execution-lifecycle.md) |
| **Modify risk score weights** | [backend/src/agents/scanner.rs](../../../../../../backend/src/agents/scanner.rs) (or normalizer module) | [frontend/src/dash.tsx](../../../../../../frontend/src/dash.tsx)<br/>[docs/development/backend.md](../../../../../../docs/development/backend.md) |
| **Change token/session expiry** | [backend/src/config.rs](../../../../../../backend/src/config.rs)<br/>[backend/src/middleware/auth.rs](../../../../../../backend/src/middleware/auth.rs) | [docs/configuration/environment.md](../../../../../../docs/configuration/environment.md) |
| **Adjust rate limiting rules** | [backend/src/app.rs](../../../../../../backend/src/app.rs) | [backend/src/config.rs](../../../../../../backend/src/config.rs)<br/>[docs/api/README.md](../../../../../../docs/api/README.md) |
| **Modify Docker sandboxing flags** | [backend/src/agents/scanner.rs](../../../../../../backend/src/agents/scanner.rs) | [docs/deployment/containers.md](../../../../../../docs/deployment/containers.md)<br/>[docs/security/threat-model.md](../../../../../../docs/security/threat-model.md) |
| **Add a new dashboard view/widget** | [frontend/src/dash.tsx](../../../../../../frontend/src/dash.tsx)<br/>[frontend/src/dashboard.css](../../../../../../frontend/src/dashboard.css) | [frontend/src/api/client.ts](../../../../../../frontend/src/api/client.ts) |
| **Update landing page copy/pricing** | [frontend/src/landing/data/landingData.ts](../../../../../../frontend/src/landing/data/landingData.ts)<br/>[frontend/src/landing/site/](../../../../../../frontend/src/landing/site) | [frontend/src/LandingPage.tsx](../../../../../../frontend/src/LandingPage.tsx)<br/>[frontend/tests/landing-page.test.ts](../../../../../../frontend/tests/landing-page.test.ts) |
| **Change global design tokens / theme**| [frontend/src/index.css](../../../../../../frontend/src/index.css)<br/>[frontend/src/dashboard.css](../../../../../../frontend/src/dashboard.css) | All UI components |
| **Add a new test suite** | `frontend/tests/` or `backend/tests/` | [docs/development/testing.md](../../../../../../docs/development/testing.md) |
