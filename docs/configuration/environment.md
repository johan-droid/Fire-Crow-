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
| `SESSION_SECRET` | String | *None* | **Yes** | Minimum 32 ASCII characters | Secret key used to sign and encrypt session cookies (`fc_session`). Startup fails if < 32 chars. |
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
| `MAX_INTAKE_BYTES` | u64 | `52428800` (50MB) | No | Maximum archive size in bytes | Hard ceiling on repository tarball extraction. Protects against zip bombs. |
| `SCANNER_TIMEOUT_SECONDS` | u64 | `300` | No | `10` – `1800` | Maximum container execution window per scanner before SIGKILL. |

---

## 2. Frontend Environment Variables (`frontend/.env`)

Vite exposes environment variables prefixed with `VITE_` to client-side code:

| Variable Name | Type | Default | Required? | Description & Failure Impact |
| :--- | :--- | :--- | :---: | :--- |
| `VITE_API_URL` | String | `""` (Empty string) | No | Base URL for the backend API (e.g. `https://api.firecrow.dev`). If empty, requests default to `/api`. |
| `VITE_APP_NAME` | String | `"FireCrow"` | No | Brand display name rendered in headers and title tags. |
| `VITE_ENABLE_ANALYTICS`| Boolean| `false` | No | Controls telemetry and client-side error reporting. |

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
