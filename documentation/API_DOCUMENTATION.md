# Fire Crow API Reference Manual 📖

Welcome to the Fire Crow API documentation. This reference manual outlines all implemented REST endpoints, Server-Sent Events (SSE) streams, input schemas, authentication protocols, and integration contracts for the **Rust (Axum)** backend.

---

## 🔒 Authentication & Headers

Fire Crow enforces a **secure-by-default** authentication strategy. Requests to protected routes must provide credentials via an HTTP Bearer Token, an API Key, or the `fc_access_token` session cookie.

### Headers for Authenticated Routes
| Header | Value | Description |
| :--- | :--- | :--- |
| `Authorization` | `Bearer <JWT_ACCESS_TOKEN>` | Required when JWT token authentication is used instead of session cookies. |
| `X-API-Key` | `<SERVICE_ACCOUNT_API_KEY>` | Programmatic access key for CI/CD integrations & automated worker scripts (`fc_sa_...` or `fc_svc_...`). |
| `X-Request-ID` | `<UUID>` | Optional trace ID. If omitted, the server generates and returns a UUID in the response. |
| `X-CSRF-Token` | `<CSRF_TOKEN>` | Required for state-changing operations (POST, PUT, DELETE) when `CSRF_ENABLED=true`. |

---

## 🔑 Environment Variables & Security Credentials

All sensitive credentials and connection strings must be configured via environment variables (e.g., `backend/.env.local`).

### Core Variables Table
| Key Name | Type | Description | Mandatory |
| :--- | :--- | :--- | :--- |
| `SECRET_KEY` | String (min 32 chars) | HMAC secret key used for signing and verifying JWT access tokens. | **Yes** |
| `ENCRYPTION_KEY` | String (min 32 chars) | AES encryption key used by `CryptoManager` for encrypting secrets in DB. Must differ from `SECRET_KEY`. | **Yes** |
| `DATABASE_URL` | String | PostgreSQL connection string (`postgresql://user:pass@host:5432/db`). | **Yes** |
| `FRONTEND_URL` | String | Frontend URL for CORS (`http://localhost:3000` in dev, `https://app.firecrow.dev` in prod). | **Yes** |
| `CORS_ORIGINS` | String | Permitted CORS origin list. | **Yes** |
| `GITHUB_CLIENT_ID` | String | GitHub OAuth 2.0 Client ID. | Optional (OAuth login) |
| `GITHUB_CLIENT_SECRET`| String | GitHub OAuth 2.0 Client Secret. | Optional (OAuth login) |
| `GITHUB_TOKEN` | String (`ghp_...`) | Personal Access Token fallback for reading repositories. | Optional |
| `GITHUB_APP_ID` | u64 | GitHub App ID for organization integrations (requires `GITHUB_APP_PRIVATE_KEY`). | Optional |
| `GITHUB_APP_PRIVATE_KEY`| String (PEM) | RSA private key PEM for the GitHub App. | Optional |
| `GITHUB_APP_WEBHOOK_SECRET`| String | HMAC secret for verifying GitHub App webhooks. | Optional |
| `GEMINI_API_KEY` | String | Google Gemini API Key for optional narrative explanations. | Optional |
| `GEMINI_MODEL` | String | Configured Gemini model name (e.g. `gemini-2.0-flash`). No silent fallback. | Optional |
| `SMTP_HOST` | String | Hostname for SMTP email report delivery via `lettre`. | Optional |
| `SMTP_PORT` | u16 (default 587) | Port for SMTP email delivery. | Optional |
| `SMTP_USER` | String | Username for SMTP authentication. | Optional |
| `SMTP_PASSWORD` | String | Password for SMTP authentication. | Optional |
| `SENDER_EMAIL` | String | From address for audit report emails. | Optional |
| `TELEGRAM_BOT_TOKEN` | String | Bot token for Telegram report delivery. | Optional |
| `TELEGRAM_CHAT_ID` | String | Operator chat ID for Telegram report delivery. | Optional |
| `REDIS_URL` | String | Optional Redis connection for session fast path and token revocation. | Optional |

> [!NOTE]
> `RESEND_API_KEY`, `BREVO_API_KEY`, and `GOOGLE_CLIENT_ID/SECRET` are dead/legacy configurations. The active email delivery transport is SMTP via `lettre`.

---

## 📂 Table of Contents
1. [Authentication & Session Management](#1-authentication--session-management)
2. [API Keys & Service Accounts (IAM)](#2-api-keys--service-accounts-iam)
3. [Multi-Factor Authentication (MFA)](#3-multi-factor-authentication-mfa)
4. [Single Sign-On (SSO) & OIDC](#4-single-sign-on-sso--oidc)
5. [Privileged Access Management (PAM)](#5-privileged-access-management-pam)
6. [Identity & Access Management (IAM)](#6-identity--access-management-iam)
7. [Multi-Tenancy](#7-multi-tenancy)
8. [Domain Verification](#8-domain-verification)
9. [Security Auditing & Execution Lifecycle](#9-security-auditing--execution-lifecycle)
10. [GitHub App & Webhooks](#10-github-app--webhooks)
11. [Server-Sent Events (SSE)](#11-server-sent-events-sse)
12. [Storage & Artifact Management](#12-storage--artifact-management)
13. [Non-Contract Stubs (Chat & Leaderboard)](#13-non-contract-stubs-chat--leaderboard)
14. [User Management & GDPR Compliance](#14-user-management--gdpr-compliance)
15. [Health & Diagnostics](#15-health--diagnostics)

---

## 1. Authentication & Session Management

All authentication routes are mounted at `/api/v1/auth`.

### `POST /auth/register`
Registers a new user account.
- **Request Body (`RegisterRequest`):**
```json
{
  "username": "operator_one",
  "password": "SecurePassword123!",
  "email": "operator@company.com",
  "privacy_policy_accepted": true,
  "privacy_policy_version": "2026-06-06",
  "timezone": "UTC",
  "region": "US"
}
```
- **Response (`TokenResponse`):**
```json
{
  "access_token": "ey...",
  "token_type": "bearer",
  "username": "operator_one",
  "user_id": "usr_9f0a28b6"
}
```

### `POST /auth/login`
Authenticates credentials and sets the `fc_access_token` HTTP-only cookie.
- **Request Body (`LoginRequest`):**
```json
{
  "username": "operator_one",
  "password": "SecurePassword123!",
  "privacy_policy_accepted": true,
  "privacy_policy_version": "2026-06-06"
}
```

### `GET /auth/github`
Initiates GitHub OAuth 2.0 redirect flow.

### `GET /auth/github/callback`
Receives GitHub authorization code and state.

### `POST /auth/exchange`
Exchanges GitHub authorization code for a session token.
- **Request Body:** `{ "code": "..." }`

### `GET /auth/me`
Retrieves the authenticated user profile.
- **Requires Authentication**

### `POST /auth/logout`
Revokes active session tokens and clears session cookies.

---

## 2. API Keys & Service Accounts (IAM)

Mounted at `/api/v1/iam`.

### `POST /iam/service-accounts`
Creates a programmatic service account key.
- **Requires Authentication** (Admin)
- **Request Body:**
```json
{
  "name": "GitHub Actions CI Pipeline",
  "description": "API key for automated repository auditing",
  "permissions": "audit:create,audit:read,report:read",
  "expires_at": "2027-01-01T00:00:00Z"
}
```
- **Response:** Returns the generated API key once.

### `POST /iam/service-accounts/:id/revoke`
Revokes a service account key.

---

## 3. Multi-Factor Authentication (MFA)

Mounted at `/api/v1/mfa`. Protected with a 5/minute rate limiter.

- `POST /mfa/enroll` — Generates a new TOTP secret, QR URI, and recovery codes.
- `POST /mfa/activate` — Verifies first TOTP passcode and enables MFA.
- `POST /mfa/verify` — Validates a TOTP code during session elevation.
- `POST /mfa/recovery` — Validates emergency recovery code.
- `POST /mfa/disable` — Disables MFA.
- `GET /mfa/status` — Returns MFA configuration status.
- `GET /mfa/admin/compliance` — (Admin) Lists admins lacking MFA.
- `POST /mfa/admin/enforce` — (Admin) Enforces MFA policy.

---

## 4. Single Sign-On (SSO) & OIDC

Mounted at `/api/v1/sso`.

- `GET /sso/providers` — Lists registered OIDC/SAML providers.
- `POST /sso/providers` — Registers a new identity provider.
- `PUT /sso/providers/:id` — Updates provider metadata.
- `DELETE /sso/providers/:id` — Removes provider configuration.
- `GET /sso/oidc/:id/login` — Initiates OIDC redirect.
- `GET /sso/oidc/callback` — Handles provider authorization callback.

---

## 5. Privileged Access Management (PAM)

Mounted at `/api/v1/pam`.

- `POST /pam/requests` — Requests temporary privilege elevation.
- `GET /pam/requests/pending` — Lists pending requests.
- `POST /pam/requests/:id/approve` — Approves privilege escalation.
- `POST /pam/requests/:id/deny` — Denies elevation request.
- `GET /pam/grants` — Lists active privilege grants.
- `POST /pam/grants/revoke` — Revokes active grant.

---

## 6. Identity & Access Management (IAM)

Mounted at `/api/v1/iam`.

- `GET /iam/policies` — Lists active permission policies.
- `POST /iam/policies` — Creates a permission policy.
- `GET /iam/audit/dormant` — Scans for accounts inactive over `days` threshold.
- `GET /iam/audit/shared-accounts` — Detects concurrent logins across distinct IPs.

---

## 7. Multi-Tenancy

Mounted at `/api/v1/tenant` (nested at `/tenant` in router).

- `GET /tenant/me` — Fetches active tenant quota and allocation statistics.
- `POST /tenant/` — Creates a new tenant organization (Admin required).
- `GET /tenant/:id` — Retrieves tenant details by ID.

---

## 8. Domain Verification

Mounted at `/api/v1/verify`.

- `POST /verify/domain` — Registers domain and generates DNS TXT validation token.
- `POST /verify/domain/check` — Probes DNS TXT records to confirm domain ownership.

---

## 9. Security Auditing & Execution Lifecycle

Mounted at `/api/v1/audit`. All audit endpoints are **execution-scoped** and owner-isolated (foreign requests return 404, never 403).

### `POST /audit/submit`
Submits a GitHub repository to trigger an audit job.
- **Requires Authentication**
- **Concurrency Gate:** Enforces per-user active job limit via PostgreSQL transaction advisory lock (`pg_advisory_xact_lock`). Excess submissions return 409 Conflict.
- **Request Body (`SubmitJobRequest`):**
```json
{
  "repo_url": "https://github.com/owner/repository",
  "repo_branch": "main",
  "commit_sha": "optional-40-hex-commit-sha"
}
```
- **Response (`JobResponse`):**
```json
{
  "id": "e5c6a78b-1234-5678-90ab-cdef12345678",
  "user_id": "usr_9f0a28b6",
  "tenant_id": null,
  "repo_url": "https://github.com/owner/repository",
  "repo_branch": "main",
  "status": "queued",
  "security_score": null,
  "created_at": "2026-10-04T12:00:00Z",
  "finished_at": null,
  "error_message": null,
  "cancel_requested": false,
  "execution_id": null
}
```

### `GET /audit/jobs`
Lists all audit jobs owned by the authenticated user.
- **Response:** Array of `JobResponse`.

### `GET /audit/job/:job_id`
Returns job status, findings for the active execution, and latest execution pointer.
- **Response (`JobDetailResponse`):**
```json
{
  "job": {
    "id": "e5c6a78b-...",
    "status": "completed",
    "security_score": 8.5,
    "commit_sha": "a1b2c3d4e5f6...",
    "execution_id": "exec_12345"
  },
  "findings": [
    {
      "id": "canonical-v1:9f0a...",
      "agent_source": "gitleaks",
      "scanner_mode": "secret",
      "title": "generic-api-key",
      "description": "Committed secret detected",
      "severity": "critical",
      "file_path": "config/keys.json",
      "line_number": 12,
      "evidence": "API_KEY = \"[REDACTED]\"",
      "cwe_id": "CWE-798",
      "owasp_category": null,
      "confidence": "high",
      "metadata_json": "{\"native_fingerprint\":\"...\"}"
    }
  ]
}
```

### `DELETE /audit/job/:job_id`
Requests cancellation of a running audit. Cancelled executions terminate with `status = "cancelled"`, never as success.

### `POST /audit/job/:job_id/retry`
Spawns attempt $N+1$ for the job under a new `execution_id`. The previous execution rows remain permanently immutable.

### `GET /audit/job/:job_id/executions`
Returns the complete attempt history for the job:
```json
[
  {
    "execution_id": "exec_attempt_1",
    "attempt_number": 1,
    "status": "failed",
    "commit_sha": "a1b2c3...",
    "started_at": "2026-10-04T12:00:00Z",
    "finished_at": "2026-10-04T12:05:00Z",
    "finding_count": 0,
    "has_report": false,
    "has_narrative": false,
    "deliveries": []
  },
  {
    "execution_id": "exec_attempt_2",
    "attempt_number": 2,
    "status": "completed",
    "commit_sha": "a1b2c3...",
    "started_at": "2026-10-04T12:06:00Z",
    "finished_at": "2026-10-04T12:10:00Z",
    "finding_count": 1,
    "has_report": true,
    "has_narrative": true,
    "deliveries": [
      { "channel": "email", "status": "sent", "failure_class": null }
    ]
  }
]
```

### `GET /audit/job/:job_id/phases`
Returns the `phase_ledger` progress rows for the job (`intake`, `fetch`, `scan`, `normalize`, `score`, `report`, `deliver`).

### `GET /audit/job/:job_id/report`
Downloads the deterministic security report for the latest execution.
- **Query Parameter:** `format` (`markdown` [default], `json`, or `html`).

### `GET /audit/job/:job_id/execution/:execution_id/report`
Downloads the deterministic report for a specific historical execution attempt.
- **Query Parameter:** `format` (`markdown`, `json`, or `html`).

### `GET /audit/job/:job_id/execution/:execution_id/narrative`
Retrieves the stored validated AI narrative for this execution. Returns 404 if no narrative has been generated.

### `POST /audit/job/:job_id/execution/:execution_id/narrative`
Generates an AI narrative using Gemini. The output is validated strictly against the execution's deterministic report:
- Every explained finding must exist in the report.
- Severities, scores, and coverage cannot be altered.
- Invented CVEs/CWEs or unredacted secrets cause rejection.
- If rejected or if Gemini is unconfigured, returns error; deterministic report remains untouched.

### `POST /audit/job/:job_id/execution/:execution_id/email`
Dispatches the finalized report via SMTP to the authenticated user's account email address.
- **No destination parameter accepted in request body** (prevents delivery hijacking).
- Idempotency key: `(execution_id, "email", user_email, delivery_version)`.

### `POST /audit/job/:job_id/execution/:execution_id/telegram`
Dispatches the finalized report to the operator's configured Telegram chat ID.
- **No destination parameter accepted in request body**.

### `GET /audit/job/:job_id/insight`
Returns derived summary insight structure: `{"insights": []}`.

### `GET /audit/job/:job_id/graph`
Returns vulnerability topology nodes. Edges are deliberately empty (`edges: []`) because no automated attack-chain correlation is performed.

### `GET /audit/privacy-logs`
Lists user privacy audit logs.

---

## 10. GitHub App & Webhooks

Mounted at `/api/v1/github`.

### `POST /github/webhook`
Receives GitHub App webhooks (`push`, `pull_request`, `installation`).
- **Authentication:** HMAC-SHA256 validated using `GITHUB_APP_WEBHOOK_SECRET` over the raw payload body.
- **Deduplication:** Uses GitHub `X-GitHub-Delivery` ID with `ON CONFLICT DO NOTHING`. Redelivery returns the existing job.
- **Audit Funnel:** Verified push and PR events funnel into `create_audit_job_attributed` behind the same backpressure gate.
- **Check Run:** Completed audits post a status Check Run named `firecrow-security-audit` on the pinned commit SHA (conclusion, status, and summary counts only; no inline PR annotations).

---

## 11. Server-Sent Events (SSE)

Mounted at `/api/v1/sse`.

### `GET /sse/job/:job_id`
Establishes a persistent SSE stream that yields job status and `phase_ledger` progress updates every 2.5 seconds. Replaces polling loops.
- **Requires Authentication**
- **Event Types:** `status`, `phase`, `error`.

### `GET /sse/dashboard`
Streams aggregate active audit statistics for authenticated dashboard views.

---

## 12. Storage & Artifact Management

Mounted at `/api/v1/storage`.

- `GET /storage/artifacts/:id/download` — Downloads raw logs or scanner output files.
- `POST /storage/artifacts/:id/legal-hold` — Flags an artifact with legal hold to prevent housekeeping deletion (`?hold=true|false`).

---

## 13. Non-Contract Stubs (Chat & Leaderboard)

These routes return valid HTTP 200 responses but are explicitly **stubs**:

- `POST /api/v1/chat/ask` — Returns:
  ```json
  { "response": "Chat assistant is not yet implemented in the Rust backend." }
  ```
- `GET /api/v1/leaderboard` — Returns:
  ```json
  { "entries": [] }
  ```

---

## 14. User Management & GDPR Compliance

Mounted at `/api/v1/user`.

- `GET /user/export` — Exports complete user records and activity logs in JSON format.
- `DELETE /user/delete` — Permanently deletes user account and personal data.

---

## 15. Health & Diagnostics

Mounted at root (`/health`) and `/api/v1/health`.

| Endpoint | Auth | Purpose | Response |
| :--- | :--- | :--- | :--- |
| `GET /health` | None | Basic uptime and database connectivity probe (`SELECT 1`). | `{"status":"up","database":"connected"}` |
| `GET /api/v1/health/live` | None | Container liveness probe (does not query database). | `{"status":"live"}` |
| `GET /api/v1/health/ready`| None | Readiness probe checking database and Redis readiness. | `{"status":"ready"}` |
| `GET /api/v1/health/deep` | None | Telemetry diagnostic inspecting storage, pool, and circuit breakers. | `{"status":"healthy",...}` |

---

## Rate Limiting & Error Codes

Global rate limiting is enforced via `tower_governor` based on the verified TCP client peer:
- **Default:** 20 requests/second with a burst allowance of 40 requests.
- **Auth Routes (`/auth/*`, `/mfa/*`):** 5 requests/minute.
- **Webhooks (`/github/webhook`, `/payments/dodo`):** 30 requests/minute.
- When throttled, requests receive `HTTP 429 Too Many Requests`.

Errors follow standardized JSON payloads:
```json
{
  "error": "Error description",
  "status_code": 400
}
```
In production mode, detailed database errors and internal backtraces are sanitized by `error_sanitizer` middleware to prevent information leakage.
