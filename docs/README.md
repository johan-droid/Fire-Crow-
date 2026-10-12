# FireCrow Engineering Handbook

Welcome to the comprehensive engineering documentation system for **FireCrow** (`johan-droid/Fire-Crow-`), an enterprise-grade repository security auditing platform developed by NEXT LAB.inc.

FireCrow executes deterministic, sandboxed multi-engine security scans (Gitleaks, Semgrep, OSV-Scanner) inside zero-privilege Docker containers, normalizes results into immutable Canonical Audit v1 records, derives reproducible risk scores (0–100), and provides an isolated AI narrative layer that is strictly prevented from altering findings or scores.

---

## 🗺️ Master Documentation Index

```
docs/
├── README.md                               # This master navigation index
├── architecture/
│   ├── overview.md                         # End-to-end architecture, lifecycle & boundaries
│   ├── repository-map.md                   # Codebase layout & "Where do I make this change?" matrix
│   └── adr/
│       ├── 001-scanner-first-architecture.md
│       ├── 002-canonical-audit-schema.md
│       ├── 003-execution-lifecycle.md
│       └── 004-fail-closed-routing.md
├── development/
│   ├── getting-started.md                  # Prerequisites, quickstart & dev launcher (scripts/dev.sh)
│   ├── backend.md                          # Rust 1.85+, Axum 0.7, actors, scanners, DB triggers
│   ├── frontend.md                         # React 19, Vite, state management, design tokens
│   ├── testing.md                          # Testing matrix, 166-test suite, execution guide
│   └── maintenance.md                      # Adding scanners, modifying schemas, migrations, upgrades
├── api/
│   └── README.md                           # Exhaustive endpoint inventory, payloads & rate limits
├── configuration/
│   └── environment.md                      # Exhaustive environment variable dictionary
├── operations/
│   └── troubleshooting.md                  # Symptom-Cause-Diagnostic-Remediation handbook
├── deployment/
│   ├── README.md                           # Deployment architecture & prerequisites
│   ├── frontend.md                         # Vercel deployment, headers, fail-closed routing
│   ├── backend.md                          # Render deployment, Dockerfile, health checks
│   ├── containers.md                       # Micro-sandboxing, Docker flags, scanner image pinning
│   └── release-checklist.md               # Step-by-step production promotion & verification
└── security/
    ├── README.md                           # Security philosophy & invariants (Failure != Clean)
    ├── threat-model.md                     # STRIDE analysis, trust boundaries & mitigations
    ├── secure-development.md               # Rust & TypeScript coding standards, sanitization
    └── incident-response.md                # Severity classification, playbooks & post-mortem
```

---

## 🧭 Targeted Reading Pathways

Choose your persona to navigate directly to the relevant documentation:

### 1. New Developer / Onboarding
1. [docs/development/getting-started.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/development/getting-started.md) — Set up your machine, Docker, Rust, and Node.js; run `./scripts/dev.sh`.
2. [docs/architecture/repository-map.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/architecture/repository-map.md) — Understand where files live and use the change-routing matrix.
3. [docs/development/testing.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/development/testing.md) — Run the test suites and verify your local build.
4. [CONTRIBUTING.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/CONTRIBUTING.md) — Read branch policies, commit conventions, and PR requirements.

### 2. Backend & Systems Engineer
1. [docs/architecture/overview.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/architecture/overview.md) — System context, actor model, and data ownership boundaries.
2. [docs/development/backend.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/development/backend.md) — Axum 0.7 handlers, stream intake, Docker orchestration, and database triggers.
3. [docs/api/README.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/api/README.md) — API contract definitions, headers, and rate limits.
4. [docs/development/maintenance.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/development/maintenance.md) — Schema evolution and scanner integrations.

### 3. Frontend & UI Engineer
1. [docs/development/frontend.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/development/frontend.md) — React 19 architecture, view routing, API client, and theme tokens.
2. [docs/architecture/repository-map.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/architecture/repository-map.md) — Locate views, components, and shared styles.
3. [docs/deployment/frontend.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/deployment/frontend.md) — Vercel preview environments and build specifications.

### 4. Security Auditor & Compliance Officer
1. [docs/security/README.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/security/README.md) — Core security invariants and zero-trust posture.
2. [docs/security/threat-model.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/security/threat-model.md) — STRIDE threat analysis, trust boundaries, and mitigations.
3. [docs/architecture/adr/001-scanner-first-architecture.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/architecture/adr/001-scanner-first-architecture.md) — Architectural proof of scanner authority over AI narrative.
4. [docs/architecture/adr/003-execution-lifecycle.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/architecture/adr/003-execution-lifecycle.md) — State machine guarantees enforced by database triggers.

### 5. Production Reliability & DevOps Engineer
1. [docs/deployment/README.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/deployment/README.md) — Multi-cloud architecture (Vercel + Render + Neon/Postgres).
2. [docs/deployment/backend.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/deployment/backend.md) & [docs/deployment/frontend.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/deployment/frontend.md) — Host-level configurations.
3. [docs/configuration/environment.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/configuration/environment.md) — Mandatory and optional environment variables.
4. [docs/operations/troubleshooting.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/operations/troubleshooting.md) — Diagnostic commands, triage procedures, and recovery paths.
5. [docs/deployment/release-checklist.md](file:///home/ashutoshsahoo/Downloads/Fire-Crow-/docs/deployment/release-checklist.md) — Pre-flight, cutover, and post-deploy checks.

---

## 📜 Core Architectural Invariants

Every engineer working on FireCrow must uphold the following inviolable principles:

1. **Scanner-First Truth**: Findings are produced exclusively by deterministic scanners (`gitleaks`, `semgrep`, `osv-scanner`). The LLM synthesis layer has zero authority to create, suppress, or modify findings.
2. **Failure Is Never Clean (`failure != clean`)**: If a scanner engine crashes, encounters a syntax error, or times out, FireCrow records incomplete scan states. It never issues a false clean audit.
3. **Database-Authoritative Lifecycle**: Audit state transitions are strictly governed by PostgreSQL `BEFORE UPDATE` trigger (`audit_jobs_lifecycle_guard_fn`). Applications cannot bypass state transition rules.
4. **Bounded Stream Intake**: Repositories are streamed in fixed chunks up to 50MB and decompressed with pax-header validation, symlink traversal prevention, and hard quota limits to defend against decompression bombs.
5. **Zero-Privilege Ephemeral Execution**: All scanner containers execute with `--cap-drop=ALL`, `--security-opt=no-new-privileges`, read-only workspace volume mounts, PID limits (100), and disconnected egress networks.
