# Fire Crow — Public API Origin Contract (FC-DEP-01)

## Topology

```
Browser ──▶ ONE public API origin ──▶ Fire Crow backend (Render, Docker)
   ▲              │
   │              ├── PostgreSQL (durable jobs, canonical audit records)
   │              ├── Redis (cache, rate limits, pub/sub)
   │              └── docker-socket-proxy ──▶ isolated scanner containers
   │
Frontend host (Vercel, static SPA)
```

The browser resolves all API traffic through one origin per environment, using
one client with one path contract (`/api/v1/*`), one credential policy
(`credentials: 'include'`), and one error mapping layer. There is exactly one
frontend API client: `frontend/src/api/client.ts` (base resolution via
`getApiBase()`, errors in `frontend/src/api/errors.ts`). No component
constructs URLs or sends tokens; tokens never appear in query strings.

## How the single API origin is wired (authoritative policy)

**The committed `vercel.json` files deliberately declare NO external `/api`
rewrite.** This is the Phase 24 fail-closed posture, statically enforced by
`frontend/src/api/deploy.ts` (`verifyRouting`) and the committed regression
suite (`frontend/tests/health.test.ts`): Vercel does not interpolate
environment variables in rewrites, so a committed external upstream would
silently route every Preview deployment — which is supposed to be
production-blind — at whatever host is written in the file (the Phase 22A
defect). Do not add an `/api` upstream rewrite to a committed config; the
checks exist to make that regression statically detectable.

API wiring is therefore **per environment**:

1. **Local development (default).** `frontend/vite.config.ts` proxies `/api`
   → `http://localhost:8000`. The browser stays same-origin and the backend
   keeps its strict cookie defaults.
2. **Deployment-scoped same-origin rewrite (preferred where available).** A
   rewrite/reverse-proxy for `/api/*` applied *at deploy time, outside the
   committed repo files* (e.g. platform dashboard configuration or a
   generated config) gives the browser the same-origin contract with the same
   `/api/v1` path. `verifyRouting(cfg, 'production' | 'staging')` encodes the
   review rules for such a config: explicit allow-listed host, no duplicated
   `/api` prefix, no production host in staging.
3. **Cross-origin direct (`VITE_API_URL`).** `getApiBase()` honors the
   per-environment `VITE_API_URL` build variable. When it names a different
   origin, the backend MUST run in cross-origin cookie mode (below).

## Cookie, CORS, and CSRF requirements

Authentication is cookie-based: HttpOnly session cookies set by
`/api/v1/auth/*` (never readable by JavaScript), plus a double-submit CSRF
token cookie (`backend/src/services/csrf.rs`,
`backend/src/middleware/csrf.rs`).

- **Same-origin mode (default):** backend defaults apply unchanged —
  `AUTH_COOKIE_SAMESITE=strict`, `AUTH_COOKIE_SECURE=true`,
  `CSRF_ENABLED=true`.
- **Cross-origin mode (`VITE_API_URL` points at another origin):** the
  backend deployment MUST set `AUTH_COOKIE_SAMESITE=none` and
  `AUTH_COOKIE_SECURE=true` (`SameSite=None` without `Secure` is rejected by
  browsers), set `CORS_ORIGINS` to the exact frontend origin, and keep
  `CSRF_ENABLED=true` — the double-submit token exists precisely for this
  mode. **Never** disable CSRF or loosen CORS to make a topology work.

## Health and capability endpoints

| Path | Purpose | Exposure |
| :--- | :--- | :--- |
| `GET /health` | Container/platform healthcheck (Render health check, Docker HEALTHCHECK follows `${PORT:-8000}`, FC-CONTRACT-01) | Platform probes; harmless body only |
| `GET /api/v1/health/live` | Liveness: process is up | Through the API origin |
| `GET /api/v1/health/ready` | Readiness: database connectivity (a probe that never fails is not a probe) | Through the API origin |
| `GET /api/v1/health/deep` | Capability honesty: database, local storage, and **Docker scanner availability** (`configured` vs `unavailable`, FC-DEP-04) | Through the API origin |

Liveness and readiness are deliberately separate; neither depends on optional
integrations (Redis, email, AI providers), so an optional outage never takes
down unrelated API functionality. A deployment without a Docker execution
path reports `docker: unavailable` and scans **fail closed** with an explicit
`engine_unavailable` job status — never a fake clean result.

## Error contract

All `/api/v1/*` responses are JSON (`backend/src/error.rs`), including 404s
for unknown API paths. HTML responses can only come from the SPA fallback for
non-`/api` paths, so the frontend can never mistake an error page for a JSON
payload (`client.ts` throws `ApiError('malformed')` on non-JSON success
bodies). API errors distinguish failed scans from failed AI narratives: a
narrative failure is returned by the narrative endpoint only and never
mutates or invalidates the canonical report.
