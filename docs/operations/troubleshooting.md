# Troubleshooting & Operational Runbook

This runbook catalogs the top production and development failure modes in FireCrow, their diagnostic signatures, root causes, and verified remediation procedures.

---

## 1. Quick Diagnostic Triage Matrix

| Failure Mode | HTTP Status / Log Signature | Primary Subsystem |
| :--- | :--- | :--- |
| [1. Docker Daemon Unavailable](#1-docker-daemon-unavailable-or-permission-denied) | `500 Internal Server Error` / `Cannot connect to Docker daemon` | Scanner Execution |
| [2. PostgreSQL Connection Refused](#2-postgresql-connection-refused-or-pool-exhaustion) | `500 Internal Server Error` / `connection refused (os error 111)` | Database Tier |
| [3. Illegal Status Transition Trigger](#3-database-lifecycle-trigger-violation) | `500 Internal Server Error` / `Illegal audit job status transition` | PostgreSQL Trigger |
| [4. Scanner Execution Timeout](#4-scanner-execution-timeout-300s-exceeded) | `Job status: failed` / `Scanner 'semgrep' timed out after 300s` | Container Sandboxing |
| [5. Stream Intake Quota Exceeded](#5-stream-intake-50mb-ceiling-exceeded) | `413 Payload Too Large` / `Intake quota exceeded (52428800 bytes)` | Fetch Ingestion |
| [6. CORS Origin Rejection](#6-cors-origin-rejection) | Browser error: `No 'Access-Control-Allow-Origin' header present` | Axum Middleware |
| [7. CSRF Token Mismatch](#7-csrf-token-mismatch) | `403 Forbidden` / `Invalid or missing CSRF token` | Auth Middleware |
| [8. Rate Limiter Triggered](#8-rate-limiter-engagement-http-429) | `429 Too Many Requests` / `Rate limit exceeded` | Governor Middleware |
| [9. Semgrep Rule Mounting Failure](#9-semgrep-rule-file-mount-failure) | `Job status: failed` / `Rule file /rules/firecrow-sast.yml not found` | Docker Bind Mount |
| [10. Gemini API Failure](#10-gemini-ai-narrative-timeout-or-quota) | `200 OK` (Audit completed with fallback template summary) | AI Narrative Layer |

---

## 2. Detailed Failure Modes & Remediations

### 1. Docker Daemon Unavailable or Permission Denied
- **Symptom**:
  ```
  ERROR backend::agents::scanner: Failed to spawn container: Docker daemon error: Permission denied (os error 13)
  ```
- **Root Cause**: The process running the Axum backend does not have write access to `/var/run/docker.sock`, or Docker Desktop is stopped.
- **Diagnostic Command**:
  ```bash
  docker info
  ls -la /var/run/docker.sock
  ```
- **Remediation**:
  ```bash
  # Add local user to docker group
  sudo usermod -aG docker $USER
  newgrp docker

  # Ensure socket permissions
  sudo chmod 666 /var/run/docker.sock
  ```
- **Verify Fix**: `docker ps` outputs container table without sudo.

---

### 2. PostgreSQL Connection Refused or Pool Exhaustion
- **Symptom**:
  ```
  ERROR backend::db: Database pool connection error: connection to server at "localhost", port 5432 failed
  ```
- **Root Cause**: PostgreSQL service is down, wrong credentials in `DATABASE_URL`, or connection pool max capacity reached.
- **Diagnostic Command**:
  ```bash
  pg_isready -h localhost -p 5432
  docker ps --filter "name=postgres"
  ```
- **Remediation**:
  ```bash
  # If using Docker container
  docker start firecrow-postgres

  # Test credentials directly
  psql "postgresql://firecrow_user:firecrow_secret@localhost:5432/firecrow" -c "\dt"
  ```
- **Verify Fix**: `curl http://localhost:8080/ready` returns `{"database":"connected"}`.

---

### 3. Database Lifecycle Trigger Violation
- **Symptom**:
  ```
  ERROR sqlx::query: db error: ERROR: Illegal audit job status transition from queued to completed for job c1f73b64-...
  ```
- **Root Cause**: Application code attempted to skip the `running` phase or update a `completed`/`failed` job back to an active state, violating the `audit_jobs_lifecycle_guard_fn` PostgreSQL trigger.
- **Diagnostic Query**:
  ```sql
  SELECT id, status, created_at, updated_at FROM audit_jobs WHERE id = 'c1f73b64-...';
  ```
- **Remediation**:
  - Review background worker code. Ensure jobs transition sequentially: `queued` ➔ `running` ➔ `completed` or `failed`.
  - In manual recovery, update status through intermediate states if resetting.
- **Verify Fix**: Audit job transitions cleanly without throwing database exception.

---

### 4. Scanner Execution Timeout (300s Exceeded)
- **Symptom**: Audit enters `status: failed`. Logs display:
  ```
  WARN backend::agents::scanner: Scanner semgrep exceeded 300s execution window. Container SIGKILL issued.
  ```
- **Root Cause**: Target repository is exceptionally large, contains minified vendor bundles, or Semgrep AST parsing encountered complex recursion.
- **Diagnostic Command**:
  ```bash
  docker ps -a --filter "name=fc-scan"
  ```
- **Remediation**:
  - In `backend/scanners/semgrep/firecrow-sast.yml`, add exclude paths for vendor artifacts (`node_modules/`, `dist/`, `vendor/`, `*.min.js`).
  - Increase `SCANNER_TIMEOUT_SECONDS` in environment if repository size warrants extended execution.
- **Verify Fix**: Run audit against repository and observe completion within timeout window.

---

### 5. Stream Intake 50MB Ceiling Exceeded
- **Symptom**: User receives `413 Payload Too Large`. Logs indicate:
  ```
  ERROR backend::agents::fetch: Repository unpack size exceeded hard ceiling of 52428800 bytes. Ingestion aborted.
  ```
- **Root Cause**: Target repository contains large binary assets, video files, or tar archive expansion exceeds the 50MB anti-bomb safety ceiling.
- **Diagnostic Command**:
  ```bash
  # Check unpacked size of repository archive locally
  tar -ztvf repo.tar.gz | awk '{sum += $3} END {print sum/1024/1024 " MB"}'
  ```
- **Remediation**:
  - Use `.gitattributes` or shallow archive tarball excluding large binary files.
  - If self-hosting for enterprise codebases requiring higher quotas, set `MAX_INTAKE_BYTES=104857600` (100MB) in `backend/.env`.
- **Verify Fix**: Re-run audit; tarball unpack completes successfully.

---

### 6. CORS Origin Rejection
- **Symptom**: Browser console: `Access to fetch at 'https://api.firecrow.dev/api/audit/run' from origin 'https://preview.vercel.app' has been blocked by CORS policy`.
- **Root Cause**: The requesting frontend domain is missing from `CORS_ALLOWED_ORIGINS` on the backend.
- **Diagnostic Command**:
  ```bash
  curl -I -X OPTIONS http://localhost:8080/api/audit/run \
    -H "Origin: https://preview.vercel.app" \
    -H "Access-Control-Request-Method: POST"
  ```
- **Remediation**:
  Update `CORS_ALLOWED_ORIGINS` in Render or backend environment:
  ```env
  CORS_ALLOWED_ORIGINS=https://firecrow.dev,https://*.vercel.app
  ```
- **Verify Fix**: Response includes `Access-Control-Allow-Origin: https://preview.vercel.app`.

---

### 7. CSRF Token Mismatch
- **Symptom**: `POST /api/audit/run` returns `403 Forbidden` with `{ "error": "Invalid CSRF token" }`.
- **Root Cause**: The client did not send the `X-CSRF-Token` header, or its value did not match the `fc_csrf` cookie.
- **Diagnostic Command**: Inspect browser request headers and application cookies in developer tools.
- **Remediation**:
  - In frontend code (`services/api.ts`), ensure `getCookie('fc_csrf')` is passed in `X-CSRF-Token`.
  - Ensure request includes `credentials: 'include'`.
- **Verify Fix**: Mutation requests return `200` or `202`.

---

### 8. Rate Limiter Engagement (HTTP 429)
- **Symptom**: Endpoint returns `429 Too Many Requests`.
- **Root Cause**: Client exceeded token-bucket limit (e.g., >5 auth attempts/min or >10 audit runs/min).
- **Diagnostic Command**:
  ```bash
  curl -i -X POST http://localhost:8080/api/auth/login ...
  ```
  Inspect `Retry-After` header.
- **Remediation**:
  - Client must observe exponential backoff and respect `Retry-After` header.
  - In test environments, relax rate limiting or configure test bypass IP.
- **Verify Fix**: Request succeeds after waiting the duration specified in `Retry-After`.

---

### 9. Semgrep Rule File Mount Failure
- **Symptom**: Semgrep container exits with code 2: `Invalid rule file: /rules/firecrow-sast.yml`.
- **Root Cause**: The host path `backend/scanners/semgrep/firecrow-sast.yml` is missing or not readable by Docker daemon.
- **Diagnostic Command**:
  ```bash
  ls -la backend/scanners/semgrep/firecrow-sast.yml
  ```
- **Remediation**:
  - Verify file exists at `backend/scanners/semgrep/firecrow-sast.yml`.
  - Ensure host path has read permissions (`chmod 644`).
- **Verify Fix**: Semgrep scans workspace without rule parsing errors.

---

### 10. Gemini AI Narrative Timeout or Quota
- **Symptom**: Audit completes successfully (`status: completed`, score: 85), but the executive summary reads:
  `Deterministic Summary: 3 findings detected across 1 scanner engine...`
- **Root Cause**: `GEMINI_API_KEY` is invalid, expired, or Google API quota exceeded.
- **Behavior**: **Fail-Open Gracefully**. The core audit integrity is preserved because `SummaryAgent` falls back to deterministic template summaries without failing the audit.
- **Remediation**:
  - Check Google Cloud Console API quota.
  - Refresh or rotate `GEMINI_API_KEY`.
- **Verify Fix**: Next completed audit features AI-synthesized narrative.
