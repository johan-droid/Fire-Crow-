# Fire Crow — Frontend API Contract v1 (Backend Architecture FROZEN)

The backend architecture is permanently frozen for the controlled-beta candidate. Build frontend components against these execution-scoped contracts; do not invent parallel business logic, client-side scoring calculations, or fake findings.

- **Base URL:** `{API}/api/v1`
- **Frontend Dev Server:** Port `3000` (`http://localhost:3000`, proxies `/api` to port `8000`)
- **Backend API Server:** Port `8000` (`http://localhost:8000`)
- **Authentication:** JWT Bearer header (`Authorization: Bearer <token>`) or HTTP-Only cookie (`fc_access_token`). GitHub OAuth entry: `/auth/github` → callback `/auth/github/callback`.
- **Health Checks (Unauthenticated):** `/health`, `/api/v1/health`, `/api/v1/health/live`, `/api/v1/health/ready`, `/api/v1/health/deep`.

---

## 1. Audit Job Lifecycle (Execution-Scoped)

> **Architectural Rule:** An audit job represents the request; an **execution** represents an attempt. Retries create a new execution ($N+1$) and never overwrite historical attempts.

### `POST /audit/submit`
Submits a repository to begin auditing.
- **Request:**
  ```json
  {
    "repo_url": "https://github.com/owner/repo",
    "repo_branch": "main",
    "commit_sha": "optional-40-hex-commit-sha"
  }
  ```
- **Response (`200 OK`):**
  ```json
  {
    "id": "e5c6a78b-...",
    "user_id": "usr_9f0a28b6",
    "repo_url": "https://github.com/owner/repo",
    "repo_branch": "main",
    "status": "queued",
    "created_at": "2026-10-04T12:00:00Z",
    "security_score": null,
    "execution_id": null
  }
  ```
- **Error (`409 Conflict`):** Returned when active job limit (default 2 per user) is reached.

### `GET /audit/jobs`
Lists all audit jobs owned by the authenticated user. Foreign jobs return `404 Not Found`, never `403`.

### `GET /audit/job/:job_id`
Returns job details, pointer to the latest execution, and active findings.

### `DELETE /audit/job/:job_id`
Requests cancellation of a queued or running job. Cancelled executions terminate with status `cancelled`, never as success.

### `POST /audit/job/:job_id/retry`
Creates attempt $N+1$ under a fresh `execution_id`. The terminal database rows of prior attempts are frozen by database triggers.

### `GET /audit/job/:job_id/executions`
Returns attempt history for the audit timeline:
```json
[
  {
    "execution_id": "exec_1",
    "attempt_number": 1,
    "status": "failed",
    "commit_sha": "40-hex-sha",
    "started_at": "2026-10-04T12:00:00Z",
    "finished_at": "2026-10-04T12:05:00Z",
    "finding_count": 0,
    "has_report": false,
    "has_narrative": false,
    "deliveries": []
  },
  {
    "execution_id": "exec_2",
    "attempt_number": 2,
    "status": "completed",
    "commit_sha": "40-hex-sha",
    "started_at": "2026-10-04T12:06:00Z",
    "finished_at": "2026-10-04T12:10:00Z",
    "finding_count": 2,
    "has_report": true,
    "has_narrative": true,
    "deliveries": [{ "channel": "email", "status": "sent", "failure_class": null }]
  }
]
```

### `GET /audit/job/:job_id/phases`
Returns the `phase_ledger` progress rows (`intake`, `fetch`, `scan`, `normalize`, `score`, `report`, `deliver`) with start/end timestamps and phase statuses.

---

## 2. Server-Sent Events (SSE)

### `GET /sse/job/:job_id`
Streams live job status and `phase_ledger` progress updates every 2.5 seconds. Use this endpoint instead of rapid polling loops.

---

## 3. Canonical Findings Representation

Findings are normalized to **Canonical Audit v1**. The frontend must never invent or re-score findings:

| Field | Type | Description |
|---|---|---|
| `id` | String | Deterministic canonical ID (`canonical-v1:<sha256>`). |
| `agent_source` | String | Scanner origin: `gitleaks`, `osv`, or `semgrep`. |
| `scanner_mode` | String | `secret`, `dependency`, or `sast`. |
| `title` | String | Rule identifier or advisory ID. |
| `description` | String | Explanatory description. |
| `severity` | String | `critical`, `high`, `medium`, `low`, `info`, or `unknown`. |
| `file_path` | String | Normalized repository file path. |
| `line_number` | Integer | Positive 1-indexed source line. |
| `evidence` | String | Bounded scanner match snippet with secrets replaced by `[REDACTED]`. |
| `cwe_id` | String / null | Present ONLY when supplied by scanner. Never inferred. |
| `owasp_category` | String / null | Present ONLY when supplied by scanner. |
| `confidence` | String / null | Scanner confidence (`high`, `medium`, `low`). |
| `metadata_json` | JSON String | Curated scanner metadata (native fingerprint, advisory links, direct/transitive flag). |

### Scoring & Coverage Contract
- **Failure is never clean:** A crashed, timed-out, or unparseable scanner produces **unknown coverage**, never zero findings.
- **Score is NULL unless coverage is complete:** `security_score` is strictly `null` for partial or failed scans.
- **Zero findings = 9.0:** A clean scan reports `9.0/10`, never `10.0/10` (perfection is not claimed).

---

## 4. Deterministic Reports

Reports are immutable, byte-identical representations derived directly from the canonical audit without re-scanning or calling an LLM:

- `GET /audit/job/:job_id/report` — Downloads the latest execution's report.
- `GET /audit/job/:job_id/execution/:execution_id/report` — Downloads a specific historical execution's report.
- **Formats:** Pass `?format=markdown` (default), `?format=json`, or `?format=html`.
- **Unfinished executions:** Return `409 Conflict` (partial audits are never presented as finished reports).

---

## 5. AI Narrative Layer (Optional Explanation)

The AI narrative is an optional explanation layer that explains the report; it does not decide security truth:

- `GET /audit/job/:job_id/execution/:execution_id/narrative` — Fetches the stored narrative. Returns `404 Not Found` if not generated or if Gemini was unconfigured.
- `POST /audit/job/:job_id/execution/:execution_id/narrative` — Generates narrative. Validated strictly against the report:
  - Every explained finding must exist in the canonical audit.
  - Severities, scores, and coverage cannot be altered.
  - Invented findings or unredacted secrets cause rejection.
  - AI failure leaves the deterministic report completely untouched.

---

## 6. Downstream Delivery (Execution-Scoped & Idempotent)

Delivery is execution-scoped and idempotent:

- `POST /audit/job/:job_id/execution/:execution_id/email` — Dispatches report via SMTP to the authenticated user's account email address. No recipient body accepted.
- `POST /audit/job/:job_id/execution/:execution_id/telegram` — Dispatches report to the configured operator Telegram chat. No recipient body accepted.
- **Idempotency Key:** `(execution_id, channel, destination, version)`. Re-submitting an already sent report returns success without duplicating delivery.
- **Delivery failure never alters audit status:** Errors are recorded on the delivery row; audit jobs and executions remain completed.

---

## 7. GitHub App Integration

- **Webhooks:** `POST /github/webhook` (HMAC-SHA256 verified; handled entirely server-side).
- **Check Runs:** A single status Check Run named `firecrow-security-audit` is posted on the pinned commit SHA with conclusion, summary counts, and coverage.
- **No Inline Annotations:** The App does not annotate individual PR diff lines or block merges.
- **Token Security:** GitHub App installation tokens are exchanged in worker memory and are never persisted in the database or sent to the browser.

---

## 8. Non-Contract Stubs (Do NOT Build Features On These)

The following routes are present in the router but return placeholder stub responses:

- `POST /api/v1/chat/ask` — Returns:
  ```json
  { "response": "Chat assistant is not yet implemented in the Rust backend." }
  ```
- `GET /api/v1/leaderboard` — Returns:
  ```json
  { "entries": [] }
  ```
- `GET /api/v1/audit/job/:job_id/insight` — Returns `{"insights": []}`.
- `GET /api/v1/audit/job/:job_id/graph` — Returns vulnerability nodes with empty `edges: []`.
