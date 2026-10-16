# Configuration & Environment Variables Reference

This document provides an exhaustive reference for all environment variables supported by the FireCrow backend and frontend systems, their validation constraints, default values, and operational impacts.

---

## 1. Backend Environment Variables (`backend/src/config.rs`)

The backend loads configuration from environment variables (or a local `backend/.env` file). Configuration is parsed into `AppConfig` and validated at process startup. If any required variable fails validation, the service exits immediately with code 1.

| Variable Name | Type | Default | Required? | Validation Rules | Description & Failure Impact |
| :--- | :--- | :--- | :---: | :--- | :--- |
| `DATABASE_URL` | String | *None* | **Yes** | Valid PostgreSQL URI with user, pass, host, db (`postgresql://...`) | Primary database connection string. If omitted or invalid, process aborts on boot. |
| `PORT` | u16 | `8080` | No | `1` – `65535` | TCP port on which Axum listens for incoming HTTP connections. |
| `HOST` | String | `0.0.0.0` | No | Valid IPv4/IPv6 address | Bind IP address. Default `0.0.0.0` binds all interfaces. |
| `SESSION_SECRET` | String | *None* | **Yes** | Minimum 32 ASCII characters | Secret key used to sign and encrypt session cookies (`fc_access_token`). Startup fails if < 32 chars. |
| `JWT_SECRET` | String | *None* | **Yes** | Minimum 32 ASCII characters | Secret key used to sign HMAC-SHA256 JWT access tokens. |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | u32 | `15` | No | `1` – `1440` (max 24h) | Lifetime of access tokens. Set to 15m to limit exposure window (FC-AUTH-02 fix). |
| `CORS_ALLOWED_ORIGINS` | String | `http://localhost:5173` | No | Comma-separated list of valid URLs | Allowed origins for browser CORS headers. If misconfigured, browsers block frontend API requests. |
| `DOCKER_SOCKET` | String | `/var/run/docker.sock` | No | Valid local socket path or TCP URL (`tcp://...`) | Socket path used to communicate with the host Docker daemon. |
| `WORK_DIR` | String | `/tmp/firecrow` | No | Writable filesystem path | Root directory for ephemeral intake workspaces and scanner outputs. |
| `GITHUB_CLIENT_ID` | String | *None* | Optional | Valid GitHub OAuth App Client ID | Client ID for GitHub OAuth 2.0 login. If omitted, GitHub login is disabled. |
| `GITHUB_CLIENT_SECRET` | String | *None* | Optional | Valid GitHub OAuth Client Secret | Client secret for GitHub OAuth 2.0 token exchange. |
| `GEMINI_API_KEY` | String | *None* | Optional | Non-empty API key string | Google Gemini 1.5 API key for AI narrative generation. If omitted, executive summaries use deterministic templates. |
| `GEMINI_MODEL` | String | `gemini-1.5-flash` | No | `gemini-1.5-flash` or `gemini-1.5-pro` | Gemini model variant used for narrative synthesis. |
| `LOG_LEVEL` | String | `info` | No | `trace`, `debug`, `info`, `warn`, `error` | Tracing filter directive for console output. |
| `OSV_EGRESS_PROXY` | String | *None* | No (dependency scanning fails closed without it) | `http`/`https` URL in `scheme://host[:port]` form; no embedded credentials, path, or query (`backend/src/services/egress_policy.rs`) | Filtering proxy through which the OSV dependency scanner must reach the OSV database. When unset or malformed, the scanner refuses to run and dependency coverage is reported unknown (fail-closed). The proxy must allowlist only `api.osv.dev:443` and `osv.dev:443` (machine-readable rule: `evaluate_egress_target`); no proxy artifact ships in this repository — deployment must provide one. |
| `SCANNER_TIMEOUT_SECONDS` | u64 | `300` | No | `10` – `1800` | Maximum container execution window per scanner before SIGKILL. |
| `CF_TURNSTILE_ENABLED` | Boolean | `false` | No | `true` / `false` | Enables Cloudflare Turnstile on `POST /auth/login` and `POST /auth/register`. **Operator warning:** the backend enforces this fail-closed — every login/register request must carry a valid `turnstile_token` (missing token → 403, rejected before any credential check; enabled without a `CF_TURNSTILE_SECRET_KEY` → 500). **No shipped frontend widget currently sends `turnstile_token` (FC-RELEASE-017 finding 3; G7 tracks the widget), and the shipped CSP (`script-src 'self'`) would block the challenge script — so this flag is API-only until G7 closes: setting it to `true` blocks browser logins and signups.** Keep `false` unless only API clients (supplying the token themselves) authenticate, or the G7 widget has landed. |
| `CF_TURNSTILE_SECRET_KEY` | String | *None* | Required when `CF_TURNSTILE_ENABLED=true` | Non-empty secret | Turnstile site-verify secret. Enforced fail-closed: enabled + empty secret rejects requests rather than skipping verification. |
| `CF_TURNSTILE_SITE_KEY` | String | *None* | Required when `CF_TURNSTILE_ENABLED=true` | Non-empty site key | Turnstile widget site key for clients (not read by the backend verifier). |
| `RESEND_API_KEY` | String | *None* | Optional | Non-empty API key string (FC-OPS-EMAIL-001) | Selects the Resend HTTP transport for audit-report email delivery (`POST /emails`). **Server-side only — never expose to the frontend.** Requires a sender address (`RESEND_FROM_EMAIL` or `SENDER_EMAIL`); a key with no sender address anywhere fails startup loudly. When unset, report email falls back to SMTP if configured, else the route answers `501 Email delivery is not configured`. Verify a sender/domain in Resend before real delivery; verify current quota and webhook-replay expectations in the official Resend docs (no paid monitoring added by this change). |
| `RESEND_FROM_EMAIL` | String | Falls back to `SENDER_EMAIL` | Required when `RESEND_API_KEY` is set (directly or via `SENDER_EMAIL`) | Valid sender address, e.g. `Fire Crow <reports@example.test>` (FC-OPS-EMAIL-001) | `From` identity for the Resend transport. Must be a Resend-verified sender/domain. Takes precedence over `SENDER_EMAIL` for Resend requests; SMTP always uses `SENDER_EMAIL`. |
| `SENDER_EMAIL` | String | *None* | Optional (required for any email channel) | Valid sender address | Default sender identity. Supplies the `From` for SMTP and the fallback `From` for Resend. An empty sender means `EmailService::from_settings` returns `None` and deliveries answer 501 rather than claiming queued. |
| `TRUST_DIRECT_PEER` | String | *None* (unset) | Optional | Truthy `1`/`true`/`yes` (case-insensitive; FC-RELEASE-017 findings 1+2) | Operator attestation that the TCP peer IS the client — i.e. a direct deploy with no shared ingress in front. Enables the per-IP login-lockout dimension on the peer address. **Leave unset (or non-truthy) behind any load balancer, tunnel, or platform ingress (Render, Cloudflare Tunnel, unknown LBs):** without this signal the IP dimension is skipped entirely, because an IP key over a shared address would be a global lockout. Presence alone does NOT enable it (`TRUST_DIRECT_PEER=0` is off). The per-account lockout and rate limiter enforce in every topology. |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` | String / u16 | *None* / `587` | Optional | Non-empty host for SMTP delivery | SMTP transport (STARTTLS). Used only when no `RESEND_API_KEY` is configured. |

---

## 2. Frontend Environment Variables (`frontend/.env`)

Vite exposes environment variables prefixed with `VITE_` to client-side code:

| Variable Name | Type | Default | Required? | Description & Failure Impact |
| :--- | :--- | :--- | :---: | :--- |
| `VITE_API_URL` | String | `""` (Empty string) | No | Base URL for the backend API (e.g. `https://api.firecrow.dev`). If empty, requests default to `/api`. |

---

## 3. Reference Configuration Templates

### Local Development Template (`backend/.env`)
```env
PORT=8080
HOST=127.0.0.1
DATABASE_URL=postgresql://firecrow_user:firecrow_secret@localhost:5432/firecrow
SESSION_SECRET=dev-session-secret-at-least-32-chars-long-abc12345
JWT_SECRET=dev-jwt-secret-at-least-32-chars-long-xyz67890
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
DOCKER_SOCKET=/var/run/docker.sock
WORK_DIR=/tmp/firecrow
LOG_LEVEL=debug
```

### Production Template (Configured via Render Dashboard)
```env
PORT=8080
HOST=0.0.0.0
DATABASE_URL=postgresql://render_user:super_secure_password@ep-cool-cloud.neon.tech/firecrow_prod?sslmode=require
SESSION_SECRET=e7b41295fc3a8e94a1d8213b90f4219487c3a0e192f4e85718293481726a8491
JWT_SECRET=89c314051a82ef48c0a8271e84a291f04821a9c8e10398471b84920a71928471
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
CORS_ALLOWED_ORIGINS=https://firecrow.dev,https://www.firecrow.dev
DOCKER_SOCKET=/var/run/docker.sock
WORK_DIR=/tmp/firecrow
GEMINI_API_KEY=AIzaSyA...
GEMINI_MODEL=gemini-1.5-flash
LOG_LEVEL=info
```

---

## 4. Secrets Management & Storage Policies

1. **Zero Secret Check-ins**: `.env` and `*.local` files are registered in `.gitignore`. CI scans reject commits containing potential high-entropy strings.
2. **Runtime Injection**: In production, secrets are injected as environment variables via Render and Vercel management dashboards. They are never written to disk or container layers.
3. **Audit Token Security**: `SESSION_SECRET` and `JWT_SECRET` must be distinct keys generated using cryptographically secure random number generators:
   ```bash
   openssl rand -hex 32
   ```
