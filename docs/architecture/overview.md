# System Architecture & Technical Overview

This document describes the end-to-end technical architecture, component boundaries, execution lifecycles, and security postures of the **FireCrow** platform.

---

## 1. System Context & Component Architecture

FireCrow is organized as a decoupled, multi-tier architecture consisting of a React 19 single-page application frontend, an asynchronous Rust (Axum 0.7) backend service, an isolated Docker container engine for sandboxed tool execution, a PostgreSQL 16 database, and external integrations with GitHub and Google Gemini.

```mermaid
flowchart TB
    subgraph Clients["Clients & Interfaces"]
        Browser["User Web Browser (SPA)"]
        CLI["Automation / CI Webhooks"]
    end

    subgraph Edge["Edge Layer (Vercel)"]
        VercelCDN["Vercel Edge Network / Static CDN"]
        SPABundle["React 19 + Vite Production Build"]
    end

    subgraph BackendHost["Backend Service Host (Render / Linux Docker Host)"]
        subgraph AxumServer["Axum 0.7 Web Engine"]
            Router["HTTP Router (/api/*) & SSE/WS Stream"]
            Middleware["Middleware Pipeline:\n- Trace/Request ID\n- CORS Validation\n- Governor Rate Limiter\n- Session Cookie Auth\n- Double-Submit CSRF Guard"]
            AuthMod["Authentication & MFA Service\n(OAuth / Argon2id / TOTP)"]
            AuditMod["Audit Orchestration Engine"]
            ExportMod["Compliance Report Generator\n(JSON / HTML / PDF)"]
        end

        subgraph Agents["Deterministic Pipeline Agents"]
            FetchAgent["FetchAgent\nStream-bounded Intake\n50MB Unpack Cap"]
            ScanAgent["ScannerAgent\nMicro-Sandbox Manager"]
            ScoreAgent["Scoring Engine\nDeterministic Math Model"]
            SummaryAgent["SummaryAgent\nIsolated Gemini Narrative"]
        end

        subgraph DockerEngine["Host Container Runtime (Docker Daemon)"]
            GitleaksBox["Ephemeral Micro-Sandbox:\nGitleaks v8.18.4"]
            SemgrepBox["Ephemeral Micro-Sandbox:\nSemgrep 1.96.0"]
            OSVBox["Ephemeral Micro-Sandbox:\nOSV-Scanner v2.2.4"]
        end
    end

    subgraph DataTier["Data & Persistence Tier"]
        Postgres[("PostgreSQL 16 Database\n- Users & Sessions\n- Audit Jobs & Runs\n- Canonical Audit Ledgers\n- Lifecycle Trigger Guards")]
    end

    subgraph External["External Services"]
        GitHubAPI["GitHub REST API\n(Repo tarballs & OAuth)"]
        GeminiAPI["Google Gemini 1.5 Pro / Flash\n(Narrative Synthesis Only)"]
    end

    Browser -->|HTTPS / Assets| VercelCDN
    VercelCDN --> SPABundle
    Browser -->|Direct HTTPS / Cookies| Router
    CLI -->|HTTPS / Bearer / Cookies| Router

    Router --> Middleware
    Middleware --> AuthMod
    Middleware --> AuditMod
    Middleware --> ExportMod

    AuditMod --> FetchAgent
    FetchAgent -->|Download Tarball Stream| GitHubAPI
    FetchAgent -->|Extracted Workspace| ScanAgent

    ScanAgent -->|Spawn Container| GitleaksBox
    ScanAgent -->|Spawn Container| SemgrepBox
    ScanAgent -->|Spawn Container| OSVBox

    ScanAgent --> ScoreAgent
    ScoreAgent --> SummaryAgent
    SummaryAgent -.->|Downstream Summary Only| GeminiAPI

    AuthMod --> Postgres
    AuditMod --> Postgres
    ScoreAgent --> Postgres
    ExportMod --> Postgres
```

---

## 2. End-to-End Audit Execution Lifecycle

Every repository audit traverses a strict 7-stage deterministic lifecycle. The state transitions are enforced at both the application level and the database level via a PostgreSQL `BEFORE UPDATE` trigger function (`audit_jobs_lifecycle_guard_fn`).

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Client
    participant API as Axum API (/api/audit)
    participant DB as PostgreSQL 16
    participant Fetch as FetchAgent
    participant GH as GitHub API
    participant Docker as Docker Daemon
    participant Normalizer as Normalizer & Scorer
    participant AI as Gemini Narrative Agent

    User->>API: POST /api/audit/run { repository, branch }
    API->>DB: INSERT INTO audit_jobs (status='queued', owner_id, repo)
    DB-->>API: job_id (UUID)
    API-->>User: 202 Accepted { job_id, status: 'queued' }

    Note over API,DB: Background Tokio Task Spawned

    API->>DB: UPDATE audit_jobs SET status='running' (Phase: INTAKE)
    API->>Fetch: Execute streaming tarball intake
    Fetch->>GH: Stream GET /repos/{owner}/{repo}/tarball/{branch}
    Note over Fetch: 50MB Decompression Ceiling Enforced<br/>Pax-header verification<br/>Symlink traversal blocked
    Fetch-->>API: Extracted local sandbox workspace: /tmp/fc_work_{uuid}

    API->>DB: UPDATE audit_jobs SET phase='SCANNING'
    API->>Docker: Run Gitleaks v8.18.4 (RO Volume, --cap-drop=ALL, Net=none)
    Docker-->>API: gitleaks_report.json
    API->>Docker: Run Semgrep 1.96.0 (RO Volume, custom ruleset mounted)
    Docker-->>API: semgrep_report.json
    API->>Docker: Run OSV-Scanner v2.2.4 (RO Volume, lockfile audit)
    Docker-->>API: osv_report.json

    Note over API: Ephemeral Workspace /tmp/fc_work_{uuid} DELETED immediately

    API->>DB: UPDATE audit_jobs SET phase='ANALYZING'
    API->>Normalizer: Ingest raw reports -> Canonical Audit Schema v1
    Normalizer->>Normalizer: Deduplicate findings, map CWEs, calculate deterministic score (0-100)
    Normalizer-->>API: CanonicalAuditV1 Record

    opt AI Narrative Enabled
        API->>AI: Send sanitized finding counts & rules (No raw code)
        AI-->>API: Executive Narrative & Remediation Guidance
        Note over API: Assert AI did NOT alter finding count or risk score
    end

    API->>DB: UPDATE audit_jobs SET status='completed', result=CanonicalAuditV1
    DB-->>API: Trigger verifies transition (running -> completed) OK

    User->>API: GET /api/audit/{id}
    API-->>User: 200 OK (Canonical Audit Record)
```

---

## 3. Data Ownership & Persistence Boundaries

### A. Persistent State (PostgreSQL 16)
The database is the authoritative truth for all durable records:
- **`users`**: User identities, GitHub handles, password hashes (Argon2id), roles (`admin`, `member`), TOTP secrets.
- **`user_sessions`**: Session tokens, expiration timestamps, user agent hashes, IP records.
- **`audit_jobs`**: Job status (`queued`, `running`, `completed`, `failed`), timestamps, parameters, raw error logs.
- **`audit_results`**: Fully validated **Canonical Audit Schema v1** records stored as binary JSONB, immutable upon write.
- **`organizations` / `repositories`**: Organization hierarchies and repository sync configurations.

### B. Ephemeral Host State (`/tmp/firecrow/*`)
The host filesystem stores temporary artifacts during the execution window only:
- Intake tarballs are extracted into `/tmp/firecrow/workspaces/{audit_id}` with permissions `0700`.
- Scanner containers bind-mount this directory strictly as **Read-Only** (`:ro`).
- Scanners output findings into an isolated output directory `/tmp/firecrow/outputs/{audit_id}`.
- Upon completion (or failure), the Rust orchestrator issues a recursive cleanup (`tokio::fs::remove_dir_all`) in a guaranteed cleanup guard block.
- Zero repository source code persists on disk after audit job termination.

### C. Downstream AI Boundary (Google Gemini)
- Only high-level, sanitized audit findings (finding titles, rule IDs, affected file paths, line numbers, and CVSS severities) are transmitted to the Gemini API.
- **Raw repository source code, git histories, secrets content, and intellectual property are never transmitted to the LLM.**
- Gemini outputs executive summaries and remediation blueprints. The database schema rejects any database update where finding counts or security scores diverge from the scanner normalizer output.

---

## 4. Authentication, Session & Security Boundaries

```mermaid
flowchart LR
    subgraph Client["Client Browser"]
        CookieStorage["fc_session (HttpOnly, Secure, SameSite=Lax)\nfc_csrf (Readable Cookie)"]
        HeaderInject["X-CSRF-Token: <fc_csrf value>"]
    end

    subgraph AuthPipeline["Axum Authentication Pipeline"]
        ExtractCookie["Extract 'fc_session' Cookie"]
        SessionCheck["Verify DB Session & Expiry (15m Access)"]
        CSRFGuard["Validate X-CSRF-Token matches fc_csrf Cookie"]
        RBAC["Assert User Ownership / Tenant ID (Prevent IDOR)"]
    end

    subgraph ProtectedEndpoint["Protected Business Logic"]
        RunAudit["Run Audit Engine"]
        GetAudit["Fetch Audit Record"]
    end

    CookieStorage -->|Automatic Cookie Transmission| ExtractCookie
    HeaderInject -->|Header Submission| CSRFGuard
    ExtractCookie --> SessionCheck
    SessionCheck --> CSRFGuard
    CSRFGuard --> RBAC
    RBAC --> ProtectedEndpoint
```

### Authentication Invariants:
1. **Cookie-Based Sessions**: Session tokens are held in `HttpOnly`, `Secure`, `SameSite=Lax` cookies. JavaScript cannot access the session token, defeating XSS token theft.
2. **Double-Submit CSRF Protection**: State-changing requests (`POST`, `PUT`, `DELETE`) require an `X-CSRF-Token` header that matches the value in the readable `fc_csrf` cookie.
3. **MFA Verification Gate**: Accounts with MFA enabled receive a pre-auth session token restricted to `/api/auth/mfa/verify`. Access to audit engines and repository data is blocked until TOTP verification succeeds.
4. **IDOR & Tenant Isolation**: Every audit query (`/api/audit/{id}`) executes with `WHERE id = $1 AND owner_id = $2` unless the authenticated user holds the `admin` role. Cross-tenant reads return `404 Not Found`.

---

## 5. Production Network Topology & Fail-Closed Routing

```mermaid
flowchart TD
    subgraph Internet["Public Internet"]
        Users["Global Users & CI Clients"]
    end

    subgraph VercelEdge["Vercel Global Edge (Frontend)"]
        FrontendDomain["firecrow.dev / preview.vercel.app"]
        StaticAssets["Vite Pre-built Static SPA"]
        VercelRouting["vercel.json:\nFail-Closed Static Rewrite (/index.html)\nNO EXTERNAL /api PROXIES"]
    end

    subgraph RenderPlatform["Render Cloud (Backend Host)"]
        BackendDomain["api.firecrow.dev"]
        ReverseProxy["Render Load Balancer / TLS Termination"]
        AxumApp["Axum Backend Service (Port 8080)"]
        LocalDocker["Host Docker Runtime Engine"]
    end

    subgraph ManagedDB["Neon / Cloud PostgreSQL"]
        PostgresDB["PostgreSQL 16 (SSL Enforced)"]
    end

    Users -->|HTTPS: HTML/JS/CSS| FrontendDomain
    FrontendDomain --> StaticAssets
    Users -->|Direct HTTPS API Requests with CORS| BackendDomain
    BackendDomain --> ReverseProxy
    ReverseProxy --> AxumApp
    AxumApp -->|Unix Socket /run/docker.sock| LocalDocker
    AxumApp -->|TLS Encrypted Connection Pool| PostgresDB
```

### Fail-Closed Routing Posture
In `vercel.json`, FireCrow deliberately configures:
```json
{
  "rewrites": [
    { "source": "/(.*)", "destination": "/index.html" }
  ]
}
```
There is **no server-side rewrite proxying `/api/*` to Render**. Instead, the React SPA makes direct client-side fetch calls to `VITE_API_URL` (e.g. `https://api.firecrow.dev`). This architecture ensures that:
- Vercel Preview deployments cannot accidentally proxy internal traffic or credentials to staging backend instances.
- Previews fail-closed if `VITE_API_URL` is omitted or unconfigured.
- Browser CORS policies strictly govern origin access to the backend API.
