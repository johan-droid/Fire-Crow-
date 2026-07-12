# Fire Crow API Reference Manual 📖

Welcome to the Fire Crow API documentation. This reference guide outlines all available REST endpoints, websocket/SSE streams, input schemas, authentication protocols, and integration guidelines.

---

## 🔒 Authentication & Headers

Fire Crow enforces a **secure-by-default** authentication strategy. Secure operations require either an HTTP Bearer Token or the `fc_access_token` session cookie.

### Headers Required for Authenticated Routes
| Header | Value | Description |
| :--- | :--- | :--- |
| `Authorization` | `Bearer <JWT_ACCESS_TOKEN>` | Required when token auth is used instead of session cookies. |
| `X-Request-ID` | `<UUID>` | Optional trace ID. If omitted, the server generates and returns one in responses. |
| `X-CSRF-Token` | `<CSRF_TOKEN>` | Required for state-changing operations (POST, PUT, DELETE) when `CSRF_ENABLED=true`. |

---

## 📂 Table of Contents
1. [Authentication & Session Management](#1-authentication--session-management)
2. [Multi-Factor Authentication (MFA)](#2-multi-factor-authentication-mfa)
3. [Single Sign-On (SSO) & OIDC/SAML](#3-single-sign-on-sso--oidcsaml)
4. [Privileged Access Management (PAM)](#4-privileged-access-management-pam)
5. [Identity & Access Management (IAM)](#5-identity--access-management-iam)
6. [Multi-Tenancy](#6-multi-tenancy)
7. [Domain Verification](#7-domain-verification)
8. [Security Auditing & SSE Logging](#8-security-auditing--sse-logging)
9. [Storage & Artifact Management](#9-storage--artifact-management)
10. [Security Assistant (Chat)](#10-security-assistant-chat)
11. [Leaderboard & Statistics](#11-leaderboard--statistics)
12. [Push Notifications](#12-push-notifications)
13. [User Management & GDPR Compliance](#13-user-management--gdpr-compliance)
14. [Health & Diagnostics](#14-health--diagnostics)

---

## 1. Authentication & Session Management

All auth routes are prefixed with `/api/v1/auth`.

### `POST /auth/register`
Creates a new user account and returns credentials.
- **Request Body (`RegisterRequest`):**
```json
{
  "username": "operator_one",
  "password": "SecurePassword123!",
  "email": "operator@company.com",
  "privacy_policy_accepted": true,
  "privacy_policy_version": "2026-06-06",
  "timezone": "Asia/Kolkata",
  "region": "IN"
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
Authenticates user credentials. Enforces rate-limiting and account lockout policy.
- **Request Body (`LoginRequest`):**
```json
{
  "username": "operator_one",
  "password": "SecurePassword123!",
  "privacy_policy_accepted": true,
  "privacy_policy_version": "2026-06-06"
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

### `POST /auth/exchange`
Verifies and exchanges GitHub OAuth code for a JWT.
- **Request Body (`ExchangePayload`):**
```json
{
  "code": "oauth_code_here"
}
```
- **Response:** `200 OK` (JSON response containing session metadata or JWT).

### `GET /auth/github`
Redirection endpoint initiating GitHub OAuth authentication.
- **Query Parameters:**
  - `privacy_policy_accepted` (boolean, Required)
  - `privacy_policy_version` (string, Required)
  - `timezone` (string, Optional)
  - `region` (string, Optional)
- **Response:** Redirects client to GitHub login screen.

### `GET /auth/github/callback`
GitHub OAuth callback landing point.
- **Query Parameters:**
  - `code` (string, Required)
  - `state` (string, Required)

### `GET /auth/me`
Retrieves information about the current authenticated user.
- **Requires Authentication**
- **Response:**
```json
{
  "user_id": "usr_9f0a28b6",
  "username": "operator_one",
  "email": "operator@company.com",
  "role": "operator",
  "tenant_id": "tenant_abc123"
}
```

### `POST /auth/logout`
Clears HTTP-only cookies and revokes sessions.
- **Response:** `{}`

---

## 2. Multi-Factor Authentication (MFA)

All MFA routes are prefixed with `/api/v1/mfa`.

### `POST /mfa/enroll`
Initiates MFA enrollment, generating a new TOTP key, QR Code URI, and emergency recovery codes.
- **Requires Authentication**
- **Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "uri": "otpauth://totp/Fire%20Crow:operator_one?secret=JBSWY3DPEHPK3PXP&issuer=Fire+Crow",
  "recovery_codes": [
    "abcd-1234-efgh",
    "ijkl-5678-mnop",
    "qrst-9012-uvwx",
    "yzab-3456-cdef"
  ]
}
```

### `POST /mfa/activate`
Activates enrolled MFA. Requires a valid token from the authenticator app.
- **Request Body (`MFAActivateRequest`):**
```json
{
  "token": "123456"
}
```
- **Response:**
```json
{
  "status": "activated",
  "activated_at": "2026-07-13T02:00:00Z"
}
```

### `POST /mfa/verify`
Validates a one-time passcode.
- **Request Body (`MFAVerifyRequest`):**
```json
{
  "token": "654321"
}
```
- **Response:**
```json
{
  "verified": true
}
```

### `POST /mfa/recovery`
Uses one of the pre-generated recovery codes to log in when the TOTP device is lost.
- **Request Body (`RecoveryCodeRequest`):**
```json
{
  "code": "abcd-1234-efgh"
}
```
- **Response:**
```json
{
  "verified": true
}
```

### `POST /mfa/disable`
Disables multi-factor authentication for the active session.
- **Requires Authentication**
- **Response:**
```json
{
  "status": "mfa_disabled"
}
```

### `GET /mfa/status`
Checks if MFA is configured and active for the logged-in operator.
- **Response:**
```json
{
  "mfa_enabled": true,
  "activated_at": "2026-07-13T02:00:00Z"
}
```

### `GET /mfa/admin/compliance`
Lists administrators who haven't enabled MFA yet (Admin permission required).
- **Response:**
```json
{
  "requires_mfa": true,
  "users_without_mfa": [
    {
      "user_id": "usr_00000000",
      "username": "lazy_admin",
      "email": "lazy@company.com"
    }
  ]
}
```

### `POST /mfa/admin/enforce`
Enforces MFA compliance by deactivating accounts of administrators who have not enabled MFA.
- **Response:**
```json
{
  "status": "enforced",
  "deactivated_count": 1
}
```

---

## 3. Single Sign-On (SSO) & OIDC/SAML

Prefixed with `/api/v1/sso`.

### `GET /sso/providers`
Lists configured SSO integrations.
- **Response:** List of registered OIDC/SAML configurations.

### `POST /sso/providers`
Registers a new SSO Identity Provider (IdP).
- **Request Body (`SSOProviderCreate`):**
```json
{
  "name": "Okta SSO",
  "provider_type": "oidc",
  "issuer_url": "https://okta.company.com/oauth2/default",
  "client_id": "client_id_guid",
  "client_secret": "client_secret_hash",
  "enforce_mfa": true,
  "auto_provision": true,
  "domains": ["company.com"]
}
```

### `PUT /sso/providers/{provider_id}`
Updates details of an existing identity provider.

### `DELETE /sso/providers/{provider_id}`
Removes an SSO provider integration.

### `GET /sso/oidc/{provider_id}/login`
Redirects the client to initiate OIDC Authorization Code Flow.

### `GET /sso/oidc/callback`
Consumes authentication tokens sent back by OIDC providers.

---

## 4. Privileged Access Management (PAM)

Allows administrators to request time-bound elevated system authorizations. Routes are prefixed with `/api/v1/pam`.

### `POST /pam/requests`
Submits a request for temporary administrative privileges.
- **Request Body:**
```json
{
  "requested_role": "super_admin",
  "duration_minutes": 120,
  "reason": "Production hotfix deployment"
}
```
- **Response:** Returns the request payload with a pending state status and unique request ID.

### `GET /pam/requests/pending`
Lists all unresolved requests (requires super admin authorization).

### `POST /pam/requests/{request_id}/approve`
Approves and starts the duration countdown on elevated privileges.

### `POST /pam/requests/{request_id}/deny`
Denies the active privilege escalation request.

### `GET /pam/grants`
Returns a list of actively running privilege elevations.

### `POST /pam/grants/revoke`
Immediately drops/revokes active elevated access credentials.

---

## 5. Identity & Access Management (IAM)

Admin configurations for access rules. Prefixed with `/api/v1/iam`.

### `GET /iam/policies`
Lists all active system permission policies.

### `POST /iam/policies`
Creates a new Access Policy.
- **Request Body (`PolicyCreate`):**
```json
{
  "name": "S3Reader",
  "effect": "allow",
  "actions": ["storage.read"],
  "resources": ["arn:aws:s3:::firecrow-reports/*"],
  "priority": 1
}
```

### `POST /iam/service-accounts`
Creates a secure API service account.
- **Request Body (`ServiceAccountCreate`):**
```json
{
  "name": "CI-Scanner-Token",
  "permissions": ["audit.submit", "audit.read"],
  "description": "Token used for GitHub Actions CI scans",
  "expires_in_days": 90
}
```
- **Response:**
```json
{
  "account_id": "svc_09a128cf",
  "name": "CI-Scanner-Token",
  "token": "fc_svc_3a2b1c...",
  "expires_at": "2026-10-11T02:00:00Z"
}
```

### `GET /iam/audit/dormant`
Scans database and returns accounts inactive for longer than a specified threshold.
- **Query Parameter:** `days` (integer, default `90`)

### `GET /iam/audit/shared-accounts`
Security check identifying users accessing accounts from multiple distinct IPs.
- **Query Parameter:** `threshold_ips` (integer, default `5`)

---

## 6. Multi-Tenancy

Routes prefixed with `/api/v1/tenants`. Enforces strict tenant logical scoping.

### `GET /tenants/me`
Gets statistics and allocation variables for the active tenant.

### `POST /tenants/`
Creates a new isolated tenant namespace (Admin permission required).
- **Request Body (`TenantCreate`):**
```json
{
  "name": "Acme Corp",
  "slug": "acme",
  "domain": "acme.com",
  "plan": "premium",
  "max_users": 50,
  "max_storage_gb": 100
}
```

---

## 7. Domain Verification

Prefixed with `/api/v1/verify`. Validates domain ownership prior to enabling SSO or customized settings.

### `POST /verify/domain`
Registers a domain for verification.
- **Request Body:**
```json
{
  "domain": "company.com"
}
```
- **Response:** Returns verification status and TXT record details.
```json
{
  "id": "dom_12345",
  "domain": "company.com",
  "txt_record_host": "@",
  "txt_record_value": "firecrow-verification=9f0a28b6...",
  "verified": false
}
```

### `POST /verify/domain/check`
Requests the DNS resolver to crawl DNS settings and check for the presence of the validation TXT token.
- **Request Body:**
```json
{
  "domain": "company.com"
}
```
- **Response:**
```json
{
  "verified": true
}
```

---

## 8. Security Auditing & SSE Logging

All auditing routes are prefixed with `/api/v1/audit`.

### `POST /audit/submit`
Submits a Git repository link to begin a remote security audit job.
- **Requires Authentication**
- **Request Body (`SubmitJobRequest`):**
```json
{
  "repo_url": "https://github.com/company/microservice",
  "repo_branch": "main",
  "attestation_accepted": true,
  "authorization_scope": "authorized_representative"
}
```
- **Response (`JobResponse`):**
```json
{
  "id": "job_e5c6a78b",
  "user_id": "usr_9f0a28b6",
  "repo_url": "https://github.com/company/microservice",
  "repo_branch": "main",
  "status": "queued",
  "created_at": "2026-07-13T02:04:00Z",
  "cancel_requested": false,
  "report_pdf_url": null,
  "error_message": null,
  "security_score": null
}
```

### `GET /audit/jobs`
Lists all security audit jobs submitted under the tenant.
- **Response:** Array of `JobResponse`.

### `GET /audit/job/{job_id}`
Returns details, status, and findings of the requested job.
- **Response (`JobDetailResponse`):**
```json
{
  "job": {
    "id": "job_e5c6a78b",
    "status": "completed",
    "security_score": 8.5
  },
  "findings": [
    {
      "id": "find_1",
      "agent_source": "gemini_static_scanner",
      "title": "SQL Injection vulnerability in Auth Handler",
      "description": "Raw string concatenation detected in db.execute",
      "severity": "critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    }
  ]
}
```

### `DELETE /audit/job/{job_id}`
Sends cancellation requests for a queued or currently executing scanning task.

### `GET /audit/job/{job_id}/report`
Returns a binary file stream downloading the compiled PDF Security Report.

### `POST /audit/job/{job_id}/email`
Sends the compiled PDF Security Report to an email address.
- **Request Body:**
```json
{
  "email": "security@company.com"
}
```

### `GET /audit/job/{job_id}/insight`
Generates LLM high-level executive dashboard summaries for this job.

### `GET /audit/job/{job_id}/graph`
Returns JSON attack path nodes representing the relational diagram.

### `GET /audit/{job_id}/stream`
Establishes a **Server-Sent Events (SSE)** connection to receive real-time execution logs from the auditing orchestrator and sandbox container.
- **Event Names:** `log`, `status`, `complete`, `error`
- **Output Stream Data Example:**
```text
event: log
data: {"timestamp": "2026-07-13T02:04:05Z", "message": "Cloning repository..."}

event: log
data: {"timestamp": "2026-07-13T02:04:12Z", "message": "Running security analyzer inside Docker sandbox..."}
```

---

## 9. Storage & Artifact Management

All routes are prefixed with `/api/v1/storage`.

### `GET /storage/artifacts/{artifact_id}/download`
Downloads raw logs, reports, or data artifacts generated during a containerized run.
- **Requires Authentication (checked against tenant permission scopes).**
- **Response:** Raw binary file stream download.

### `POST /storage/artifacts/{artifact_id}/legal-hold`
Applies or removes legal hold tags. Legal hold prevents database housekeeping cleanups from deleting critical log evidence files.
- **Query Parameter:** `hold` (boolean, Required)
- **Response:** `{}`

---

## 10. Security Assistant (Chat)

Allows operators to query agent findings using conversational LLM interfaces. Prefixed with `/api/v1/chat`.

### `POST /chat/ask`
Sends queries to the security assistant scoped to a specific audit job's findings.
- **Request Body (`ChatRequest`):**
```json
{
  "job_id": "job_e5c6a78b",
  "message": "Where in the code is the SQL Injection, and how can I fix it?"
}
```
- **Response:**
```json
{
  "answer": "The vulnerability is located in `backend/app/api/routes_auth.py` at line 74. You can remediate this by changing...",
  "referenced_files": ["backend/app/api/routes_auth.py"]
}
```

---

## 11. Leaderboard & Statistics

Prefixed with `/api/v1/leaderboard`.

### `GET /leaderboard`
Lists security performance scores and scan summaries across systems/repositories.

---

## 12. Push Notifications

Allows browsers to receive instant push alerts. Prefixed with `/api/v1/push`.

### `GET /push/vapid-public-key`
Retrieves the application's VAPID public key. Used to initialize web push subscriptions in client browsers.
- **Response:**
```json
{
  "public_key": "BEl69..."
}
```

### `POST /push/subscribe`
Saves user browser subscription parameters.
- **Request Body (`SubscribeRequest`):**
```json
{
  "endpoint": "https://fcm.googleapis.com/fcm/send/...",
  "keys": {
    "p256dh": "BLm...",
    "auth": "Wd..."
  }
}
```

---

## 13. User Management & GDPR Compliance

Prefixed with `/api/v1/user`.

### `GET /user/export`
Generates a complete JSON payload containing all active details, logins, and log traces associated with the requester (GDPR portability compliance).

### `DELETE /user/delete`
Permanently purges and deletes user records, audits, and settings from the database (GDPR right to be forgotten compliance).

---

## 14. Health & Diagnostics & Key Validation Guide

This section is a comprehensive developer manual for monitoring, testing backend connectivity, handling session cookies/API keys, and reporting system diagnostics in the frontend user interface.

### 🔑 API Key & Token Authentication flow for Testing
When building the frontend or executing programmatic checks, there are two primary methods to pass credentials:
1. **User JWT Access Token (Cookie or Bearer):**
   - After a successful `/auth/login` or OAuth callback exchange, the backend returns an access token and sets an HTTP-Only cookie `fc_access_token`.
   - In frontend AJAX requests (e.g., using `axios` or `fetch`), make sure to include `credentials: "include"` (or equivalent CORS settings) so the cookie is forwarded automatically.
   - Alternatively, you can supply it via the `Authorization: Bearer <token>` header.
2. **Service Account Tokens (Long-lived API Keys):**
   - Admin accounts can generate long-lived service tokens via `POST /iam/service-accounts`.
   - These API keys always start with the prefix `fc_svc_` (e.g., `fc_svc_6c2a...`).
   - Authenticate by adding the `Authorization: Bearer fc_svc_your_token_here` header.

---

### 🚦 Health Probe Endpoints

The backend exposes four health check endpoints. Each serves a specific infrastructure or application requirement:

| Endpoint | Auth Required | Rate Limit | Purpose | HTTP Status Code |
| :--- | :--- | :--- | :--- | :--- |
| **`GET /health`** | None | 30/min | Lightweight check for uptime (probes Database). | `200` (Healthy) or `503` (Degraded) |
| **`GET /health/live`** | None | 30/min | Kubernetes/Docker liveness probe (does not probe sub-services). | `200` (Live) |
| **`GET /health/ready`** | None | 10/min | Readiness probe for ingress routers (probes Database + Redis). | `200` (Ready) or `503` (Degraded) |
| **`GET /health/deep`** | None | 10/min | Full telemetry diagnostic check (DB + Local Storage + Cloudflare R2 + Circuit Breaker states). | `200` (All OK) or `503` (Service Degraded) |

---

### 🔍 Endpoint Details & Payloads

#### 1. Quick Health Check: `GET /health`
Validates that the web server is responsive and the primary database can run a simple verification query (`SELECT 1`).
- **Response (Healthy - HTTP 200):**
```json
{
  "status": "up",
  "database": "connected"
}
```
- **Response (Degraded - HTTP 503):**
```json
{
  "status": "degraded",
  "database": "unavailable"
}
```

#### 2. Liveness Check: `GET /health/live`
Used strictly to determine if the backend process is running. Avoids database overhead.
- **Response (HTTP 200):**
```json
{
  "status": "live"
}
```

#### 3. Readiness Check: `GET /health/ready`
Ensures the backend and its state coordinators (database and Redis cache) are online before routing traffic.
- **Response (Healthy - HTTP 200):**
```json
{
  "status": "ready"
}
```
- **Response (Degraded - HTTP 503):**
```json
{
  "status": "degraded",
  "database": "connected",
  "cache": "unavailable"
}
```

#### 4. Telemetry Diagnostics: `GET /health/deep`
Designed for administrative status monitors, giving detailed metrics on storage engines, S3 compatibility layer, and external AI circuit breakers.
- **Response (Healthy - HTTP 200):**
```json
{
  "status": "healthy",
  "database": "ok",
  "local_storage": "ok",
  "object_storage": "ok",
  "circuit_breakers": {
    "database": {
      "state": "closed",
      "failures": 0,
      "last_failure": null
    },
    "gemini": {
      "state": "closed",
      "failures": 0,
      "last_failure": null
    }
  },
  "shutting_down": false
}
```

- **Response (Degraded - HTTP 503):**
```json
{
  "status": "unhealthy",
  "database": "failed",
  "local_storage": "ok",
  "object_storage": "failed",
  "circuit_breakers": {
    "database": {
      "state": "open",
      "failures": 5,
      "last_failure": "2026-07-13T02:05:12.182Z"
    },
    "gemini": {
      "state": "closed",
      "failures": 0,
      "last_failure": null
    }
  },
  "shutting_down": false
}
```

---

### 💻 Developer Guide: Frontend Implementation

#### A. Fetching Status & Visualizing Circuit Breakers
For a premium frontend user experience, you should build an administrative status dashboard widget. Map the health outputs to these visual components:

1. **Service status (Database, Object Storage, Local Storage):**
   - `"ok"` / `"connected"` ➡️ Render **Green Dot (Healthy)**.
   - `"failed"` / `"unavailable"` / `"degraded"` ➡️ Render **Red Pulsing Dot (Critical)**.
   - `"disabled"` ➡️ Render **Grey Dot (Inactive)**.
2. **Circuit Breakers (`closed`, `open`, `half-open`):**
   - **`closed`:** Normal operational status. Render **Green Badge ("Active")**.
   - **`open`:** The backend has automatically severed requests to this downstream service because of repeated failures. Render **Red Pulsing Badge ("Tripped / Fallback Active")** and show a developer notice.
   - **`half-open`:** The backend is testing connectivity with small traffic limits to see if the service has recovered. Render **Amber Badge ("Reconnecting / Probe Mode")**.

#### B. Handling Rate Limits (`HTTP 429 Too Many Requests`)
The health checks and other endpoints are protected by `SlowAPI` and return standard rate-limiting headers. Ensure the frontend client intercepts these headers to manage retry intervals:

| Header | Description |
| :--- | :--- |
| `X-RateLimit-Limit` | Maximum number of allowed requests in the active window. |
| `X-RateLimit-Remaining` | Remaining requests allowed in the current window. |
| `X-RateLimit-Reset` | Unix Epoch timestamp indicating when the rate limit window resets. |

**Handling standard fetch exceptions:**
```typescript
async function fetchDeepStatus() {
  try {
    const response = await fetch('http://localhost:8000/health/deep');
    
    if (response.status === 429) {
      const resetTime = response.headers.get('X-RateLimit-Reset');
      console.warn(`Rate limited. Try again at timestamp: ${resetTime}`);
      // Disable poll hooks / alert user
      return;
    }
    
    if (!response.ok) {
      throw new Error(`API returned HTTP ${response.status}`);
    }
    
    const data = await response.json();
    updateDashboardUI(data);
  } catch (error) {
    console.error("Health check network failure:", error);
    updateDashboardUI({ status: "network_failure" });
  }
}
```

---

### 🧪 Executing Health Endpoint Checks (CLI)

Use these standard commands from your terminal to verify health check endpoints manually:

```bash
# 1. Quick ping (Checks if API server and SQLite/PostgreSQL are running)
curl -i http://localhost:8000/health

# 2. Liveness check (Used for container restart loops)
curl -i http://localhost:8000/health/live

# 3. Readiness check (Checks API, PostgreSQL, and Redis cache/broker)
curl -i http://localhost:8000/health/ready

# 4. Deep System telemetry (Checks S3, databases, local file writes, and AI models)
curl -i http://localhost:8000/health/deep
```

