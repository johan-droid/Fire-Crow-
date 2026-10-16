# API Specifications & Endpoint Inventory

This reference documents the complete HTTP and real-time streaming API contract for FireCrow, including authentication requirements, rate limiting tiers, request/response JSON schemas, and `curl` examples.

---

## 1. API Conventions & Protocols

- **Base URL**: Local: `http://localhost:8080/api` • Production: `https://api.firecrow.dev/api`
- **Content-Type**: `application/json; charset=utf-8`
- **Session Transport**: `fc_access_token` (plus `fc_access_token_refresh`; cookies are `HttpOnly`, `Secure`, `SameSite`)
- **CSRF**: No token header or cookie. Mutating requests (`POST`/`PUT`/`PATCH`/`DELETE`) must carry an allowlisted `Origin` header; cookie-bearing mutations with no `Origin` are rejected with 403. `Authorization: Bearer` callers are unaffected.
- **Request Tracing**: All responses include `X-Request-ID: <UUID>`

### Rate Limiting Headers
When rate limits are engaged, responses include standard IETF rate limiting headers:
```http
X-RateLimit-Limit: 20
X-RateLimit-Remaining: 19
X-RateLimit-Reset: 1728777600
Retry-After: 3
```

### Standard Error Response Format
All errors return a structured JSON envelope:
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests. Please wait 3 seconds before retrying.",
    "request_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
  }
}
```

---

## 2. Complete Endpoint Inventory

### A. Health & Liveness Probes

#### `GET /health`
- **Purpose**: Lightweight liveness probe for load balancers.
- **Auth**: None
- **Rate Limit**: Global
- **Response**: `200 OK`
```json
{
  "status": "ok",
  "version": "0.1.0",
  "timestamp": "2026-10-13T02:00:00Z"
}
```
```bash
curl -s http://localhost:8080/health
```

#### `GET /ready`
- **Purpose**: Deep readiness check (verifies PostgreSQL connection pool).
- **Auth**: None
- **Rate Limit**: Global
- **Response**: `200 OK`
```json
{
  "status": "ready",
  "database": "connected",
  "docker_daemon": "responsive"
}
```

---

### B. Authentication & Session Endpoints

#### `POST /api/v1/auth/login`
- **Purpose**: Authenticate user with username and password.
- **Auth**: Public
- **Rate Limit**: 5 requests / min
- **Request Body**:
```json
{
  "username": "security@company.com",
  "password": "CorrectHorseBatteryStaple!"
}
```
- **Response** (MFA disabled): `200 OK`
- **Cookies Set**: `fc_access_token` (`HttpOnly`), `fc_access_token_refresh`
- **Response** (MFA enabled): `200 OK` with **no cookies** and no session —
  `{"status": "mfa_required", "mfa_token": "<challenge>", "username": "..."}`
  The short-lived (5-minute), single-use `mfa_token` must be redeemed at
  `POST /api/v1/auth/login/mfa` before any session exists.
```bash
curl -i -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"security@company.com","password":"SecretPassword123!"}'
```

#### `POST /api/v1/auth/login/mfa`
- **Purpose**: Redeem the `mfa_token` challenge from login (or the OAuth
  exchange step) with a 6-digit TOTP code or a single-use recovery code.
- **Auth**: Public endpoint — authorization is the challenge itself
  (`mfa_token`); **no pre-auth session cookie exists or is required**.
- **Rate Limit**: 5 requests / min, plus an account lockout after 5 wrong
  codes within 10 minutes.
- **Request Body**:
```json
{
  "mfa_token": "<challenge from POST /api/v1/auth/login>",
  "code": "482910"
}
```
- **Response**: `200 OK` (sets `fc_access_token` / `fc_access_token_refresh`;
  identity metadata only — tokens are never echoed in the body).
  Wrong code: `401`. Locked account: `429`. Used/expired challenge: `401`.

#### `GET /api/auth/session`
- **Purpose**: Get current user identity and active tenant context.
- **Auth**: Required (`fc_access_token`)
- **Rate Limit**: Global
- **Response**: `200 OK`
```json
{
  "user": {
    "id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "email": "security@company.com",
    "role": "admin",
    "mfa_enabled": true
  }
}
```

#### `POST /api/auth/logout`
- **Purpose**: Revoke session and clear cookies.
- **Auth**: Required
- **Response**: `200 OK` (Expires `fc_access_token` and `fc_access_token_refresh` cookies)

---

### C. Audit Operations

#### `POST /api/audit/run`
- **Purpose**: Initiate asynchronous tri-engine security audit for a repository.
- **Auth**: Required
- **Rate Limit**: 10 requests / min
- **Headers**: `Origin: <allowlisted-origin>` (no CSRF token header)
- **Request Body**:
```json
{
  "repository": "https://github.com/org/repo-target",
  "branch": "main",
  "engines": ["gitleaks", "semgrep", "osv-scanner"]
}
```
- **Response**: `202 Accepted`
```json
{
  "job_id": "c1f73b64-8422-4416-8f3b-ec86b36423a2",
  "status": "queued",
  "estimated_time_seconds": 60,
  "created_at": "2026-10-13T02:05:00Z"
}
```
```bash
curl -X POST http://localhost:8080/api/audit/run \
  -b "fc_access_token=..." \
  -H "Origin: http://localhost:3000" \
  -H "Content-Type: application/json" \
  -d '{"repository":"https://github.com/org/repo","branch":"main"}'
```

#### `GET /api/audit/:id`
- **Purpose**: Retrieve status or finalized **Canonical Audit Schema v1** record.
- **Auth**: Required (Tenant owner or Admin)
- **Response**: `200 OK`
```json
{
  "schema_version": "1.0.0",
  "audit_id": "c1f73b64-8422-4416-8f3b-ec86b36423a2",
  "repository": "org/repo",
  "commit_sha": "a1b2c3d4e5f67890",
  "score": 85,
  "grade": "B",
  "status": "completed",
  "summary": {
    "total_findings": 3,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 2,
    "info": 0
  },
  "findings": [
    {
      "id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "engine": "semgrep",
      "rule_id": "rules.python.django.security.injection.sql",
      "title": "Raw SQL query construction",
      "severity": "High",
      "category": "SAST",
      "file_path": "backend/api/views.py",
      "start_line": 42,
      "end_line": 45,
      "cwe_ids": ["CWE-89"],
      "remediation": "Use parameterized queries or Django ORM filter expressions."
    }
  ]
}
```

#### `GET /api/audit/history`
- **Purpose**: List past audits for the authenticated account.
- **Query Parameters**:
  - `limit`: Integer (default: 20, max: 100)
  - `offset`: Integer (default: 0)
- **Response**: `200 OK` array of audit job summaries.

#### `GET /api/audit/:id/export/json`
- **Purpose**: Download raw standardized Canonical Audit v1 JSON file.
- **Headers**: `Content-Disposition: attachment; filename="audit-{id}.json"`

#### `GET /api/audit/:id/export/pdf`
- **Purpose**: Download cryptographically verified compliance PDF report.
- **Headers**: `Content-Type: application/pdf`

---

### D. Real-Time Streaming (`/api/audit/:id/stream`)

#### `GET /api/audit/:id/stream`
- **Purpose**: Server-Sent Events (SSE) stream for real-time progress updates during audit execution.
- **Headers**: `Accept: text/event-stream`
- **Event Sequence**:
```
event: status
data: {"phase": "INTAKE", "message": "Streaming repository tarball (12MB)...", "progress": 20}

event: status
data: {"phase": "SCANNING", "engine": "gitleaks", "message": "Running secrets detection...", "progress": 40}

event: status
data: {"phase": "SCANNING", "engine": "semgrep", "message": "Running AST SAST rules...", "progress": 65}

event: status
data: {"phase": "ANALYZING", "message": "Computing deterministic risk score...", "progress": 90}

event: complete
data: {"audit_id": "c1f73b64-8422-4416-8f3b-ec86b36423a2", "score": 85, "grade": "B"}
```
