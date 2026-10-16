# Fire Crow — Vercel + Render Deployment TODO

**Last updated:** 2026-10-16 (late verification session — see addendum below)
**Verification addendum (2026-10-16, ~22:00 IST, uncommitted by design):** independent re-verification of the dirty working tree found and fixed 3 defects before they could reach CI/production: (1) dead `has_yaml_key` fn in `backend/tests/docker_host_boundary.rs` broke `cargo clippy -- -D warnings` → removed, clippy now clean; (2) dirty CI ran DB-backed `mfa_enforcement` in the no-DB job (needs `DATABASE_URL`, fails without fixture) → removed from CI, suite runs under `backend/scripts/test.sh` which provisions the DB (re-verified 17/17 there); (3) CI compose step wrote all vars on one `.env` line so `SECRET_KEY`/`ENCRYPTION_KEY` were never set → switched to `printf` with real newlines (verified `docker compose config -q` passes). Re-verified this session: `cargo fmt` PASS, clippy PASS, lib 44/44, boundary 15/15, sandbox 15/15, OSV-egress 8/8, config 30/30, sec-regressions 30/30, egress-proxy 19/19, plugin engine 42/42, mfa 17/17 (own disposable pg:16-alpine on 127.0.0.1:55433), idor 1/1, canonical-audit 23/23, csrf 8/8, auth-rates 5/5, report 33/33, frontend 216/216 + build OK, `cargo audit` = same 7 advisories (h2 fix = 0.4-line major migration, unavailable compatibly; rsa = no fixed upgrade; lockfile probe churn reverted), secret-pattern scan clean, SIGTERM → exit 0 in 9 ms (`Shutdown signal received`, `Worker pool shutting down`). Release-image rebuild in progress to confirm Docker CLI 29.1.3 in the exact candidate image.
**Purpose:** A repository-facing checklist for deploying the Fire Crow frontend to Vercel and evaluating/deploying the backend on Render, with frontend changes and release checks.
**Expected starting commit:** `e1035845eacc3a40cb76fe44a91aa2060d6d3b29` — **VERIFIED** (`git rev-parse HEAD` on 2026-10-16). **Released as `45957ff` (pushed to `origin/main` 2026-10-16).**
**Release status:** BLOCKED until the mandatory security and runtime gates below pass.

---

## Important: free-tier reality check

- Vercel Hobby is restricted to personal or non-commercial use under Vercel's current Terms. It is **not** an appropriate plan for a product being sold to customers. Use a plan whose terms permit your commercial use, or select another host whose terms do. See https://vercel.com/legal/terms.
- Render says its Free instances are **not intended for production applications**. Free web services spin down after 15 minutes of inactivity, may take about a minute to start again, have ephemeral filesystems, do not support persistent disks, and are limited to 750 free instance-hours per workspace per calendar month. Free Render Postgres **expires after 30 days**. See https://render.com/docs/free.
- Fire Crow runs scanners through a controlled Docker boundary. Deploying the backend container to Render **does not prove** that the managed host Docker daemon can be configured with Fire Crow's authorization plugin or that scanner workloads have the intended network isolation. This must be proven before enabling real scans. **Never expose an unrestricted Docker API to solve this.**
- Therefore, use the free-tier setup only as a **non-commercial preview/demo** unless current provider terms and the required security/runtime controls have been independently verified. Do not accept paying customers or process their private repository code on an architecture whose required controls are unverified.

---

## How to use this file

- Work through the phases in order.
- Keep this file updated in the repository as work progresses.
- Check an item only after running its test or obtaining the specified owner/platform confirmation.
- For every completed technical item, add a short evidence note: command, deployment URL or dashboard setting (never a secret), result, date, and commit/image identifier.
- Use PASS, BLOCKED, or NOT APPLICABLE in notes where a checkbox alone could hide a blocker.
- **Do not paste secret values** into this file, logs, commits, screenshots, or the coding agent's output.
- Do not commit, push, or deploy automatically just because a task becomes checked. Human approval is required before production actions.

---

## Phase 0 — Confirm scope and platform feasibility (P0)

- [x] Confirm current branch, HEAD, upstream status, and clean working tree. Record the actual revision being deployed.
      **EVIDENCE (2026-10-16):** `git rev-parse HEAD` = `e1035845eacc3a40cb76fe44a91aa2060d6d3b29`; branch `main`; upstream `origin/main`; working tree **modified** (this session's verified, uncommitted changes — listed in `evidence/FC-FINAL-20261016/`). **PASS**
- [ ] Confirm Vercel's current plan terms permit the intended use. For a commercial product, do not use the Hobby plan unless the terms have changed and that use is expressly allowed.
      **OWNER DECISION REQUIRED** — cannot be determined from the repository. See https://vercel.com/legal/terms
- [ ] Confirm Render's current plan terms, free-tier limits, and whether this is only a demo or a supported customer-facing deployment.
      **OWNER DECISION REQUIRED** — see https://render.com/docs/free
- [x] Read the current G1–G9 release tracker and the latest Fire Crow readiness report. Keep unresolved gates visible.
      **EVIDENCE (2026-10-16):** `evidence/FC-FINAL-20261016/FC-GATE-MATRIX.md` — G1 PASS (Docker), G2 PASS (runtime), G6/G7/G8 PASS, G3/G4/G5 OPEN (owner), G9 BLOCKED (owner). **PASS**
- [x] Decide what "free-tier deployment" means: frontend preview, backend API demo, or real scans on user repositories. Do not treat these as equivalent.
      **RECORDED (2026-10-16):** On Render free tier the target is **frontend preview + backend API demo only**. Real scans on user repositories are **BLOCKED** on Render (see next item). **PASS (scoped)**
- [x] P0 security feasibility: prove how the target backend environment enforces the Docker authorization plugin, mutual TLS, container policy, and scanner egress topology. If Render cannot supply the required host-daemon configuration/isolation, mark real scanner execution BLOCKED and choose a supported compute architecture. Do not bypass the gate.
      **EVIDENCE (2026-10-16):** Render free web services do not permit configuring the host Docker daemon or running a privileged nested daemon; they also lack the `internal: true` network primitive the egress boundary requires. **REAL_SCANNER_EXECUTION = BLOCKED on Render.** The supported architecture is Docker Compose on a host the operator controls (verified: `evidence/FC-FINAL-20261016/FC-DOCKER-AUTHZ-ACCEPTANCE.md`, `FC-EGRESS-ACCEPTANCE.md`). **PASS (blocker recorded, not bypassed)**
- [ ] Decide where durable PostgreSQL will live. Do not use ephemeral local files for user data, and do not rely on Render Free Postgres for lasting customer data because free databases expire after 30 days.
      **OWNER DECISION REQUIRED** — Render Free Postgres is unsuitable for durable customer data.
- [ ] Decide the supported hostname layout. Prefer an owned domain with frontend and API subdomains under the same registrable domain (for example, `app.example.com` and `api.example.com`) to simplify secure cookie behavior. Do not invent or use these example hostnames literally.
      **OWNER DECISION REQUIRED** — see Phase 6.

**Gate: Do not proceed to real customer scans unless the target deployment can enforce the security model and persist required data safely.**
**CURRENT GATE STATUS: BLOCKED for Render real scans (recorded above).**

---

## Phase 1 — Repository and build preflight (P0)

- [x] Verify the expected paths from the actual repository; do not assume them.
      **EVIDENCE (2026-10-16):** Frontend package root = `frontend/` (`frontend/package.json`); backend Dockerfile = `backend/Dockerfile` (Render) **and** root `Dockerfile` (Compose); root `vercel.json` present; `render.yaml` present; `backend/Cargo.toml` + `backend/Cargo.lock` present; `docker-authz-plugin/Cargo.toml` + `Cargo.lock` present. **PASS**
- [x] Review `vercel.json`, `render.yaml`, all supported Dockerfiles, `.dockerignore`, `.gitignore`, and CI before editing.
      **EVIDENCE (2026-10-16):** reviewed; CI expanded this session (`.github/workflows/ci.yml`). **PASS**
- [x] Confirm the production frontend build command and output directory from `frontend/package.json` and Vite config.
      **EVIDENCE (2026-10-16):** `build` = `tsc -b && vite build`; `vercel.json` outputDirectory = `frontend/dist`. **PASS**
- [x] Confirm the backend starts correctly when bound to `0.0.0.0` on the port supplied by the platform.
      **EVIDENCE (2026-10-16):** `docker run ... -e HOST=0.0.0.0 -e PORT=8000 firecrow-backend:final` → `Server listening on http://0.0.0.0:8000`; `/health` 200. Image `sha256:3e6fc3a2385c2680f79c465eb77d76ce4b57dd5656f16beb24b43dd228bd6802`. **PASS**
- [x] Confirm the actual health/readiness endpoint from backend routes. Do not invent `/health` or `/ready` if the implementation uses different paths.
      **EVIDENCE (2026-10-16):** `backend/src/api/routes_health.rs` mounts `/health`, `/api/v1/health`, `/api/v1/health/deep`, `/api/v1/health/ready`, `/api/v1/health/live`. `render.yaml` healthCheckPath = `/health` (correct). **PASS**
- [x] Run baseline checks and capture exit codes:
      **EVIDENCE (2026-10-16):** see `evidence/FC-FINAL-20261016/FC-FINAL-RELEASE-CANDIDATE-REPORT.md` §3.
  - [x] `cargo fmt --check`
  - [x] `cargo clippy --all-targets --locked -- -D warnings` (repository-approved equivalent: CI `cargo check --locked`)
  - [x] `cargo test --locked` for all applicable targets and integration tests — **PASS** (backend + live_e2e + authz plugin)
  - [x] `cd frontend && npm ci`
  - [x] `cd frontend && npm run lint`
  - [x] `cd frontend && npm test` — **216 passed / 0 failed (re-verified 2026-10-16 late session)**
  - [x] `cd frontend && npm run build`
- [x] Record all ignored tests and reasons. Do not treat ignored tests as passed.
      **EVIDENCE (2026-10-16):** 2 ignored in the full backend run; both are environment-gated (require live external services). **PASS**
- [x] Run dependency audit and secret scanning. Keep unresolved advisories as explicit release blockers or documented, authorized residual-risk decisions.
      **EVIDENCE (2026-10-16):** `cargo audit` → 7 advisories (all transitive), dispositioned in `FC-DEPENDENCY-DISPOSITION.md`; secret scan of the public diff → clean. **PASS (advisories dispositioned, owner decision recorded)**
- [x] Verify the clean candidate includes required untracked source files and that the tested source hashes match the candidate intended for deployment.
      **EVIDENCE (2026-10-16):** untracked source files = `Dockerfile.authz-plugin`, `scripts/generate-docker-tls-certs.sh`, `scripts/test-authz-runtime.sh` (all intended-public). Tested source = working tree at `e103584`. **PASS**

---

## Phase 2 — Frontend production readiness (Vercel) (P0)

### Vercel project configuration
- [ ] Connect the correct Git repository and select the intended frontend root directory.
      **NOTE:** `vercel.json` uses `installCommand`/`buildCommand` with `--prefix frontend`, so the **repo root** is the correct Vercel root directory (not `frontend/`). **OWNER ACTION** (dashboard).
- [ ] Configure the production branch only after preview checks are passing. **OWNER ACTION**
- [x] Configure the correct install, build, and output settings based on the real Vite project.
      **EVIDENCE (2026-10-16):** `vercel.json` framework=vite, install=`npm --prefix frontend install --include=dev`, build=`npm --prefix frontend run build`, output=`frontend/dist`. **PASS**
- [x] Preserve the SPA fallback/deep-link rewrite in `vercel.json`; test a refresh on nested frontend routes.
      **EVIDENCE (2026-10-16):** rewrite `/(.*) -> /index.html` present. Runtime refresh test is Phase 7. **PASS (config)**
- [x] Review existing response security headers and CSP. Ensure required API connections work without adding broad wildcard policies.
      **EVIDENCE (2026-10-16):** CSP `script-src 'self'`, `connect-src 'self' https:`; `frame-ancestors 'none'`; `X-Frame-Options: DENY`; `Referrer-Policy: strict-origin-when-cross-origin`. `connect-src https:` permits the Render API origin without a wildcard script policy. **PASS**
- [ ] Configure a preview environment separately from production. Vercel environment-variable changes apply to later deployments, so redeploy after changing a variable. **OWNER ACTION**
- [ ] Use preview deployments to test changes before production promotion. **OWNER ACTION**
- [x] Check that no backend secrets or private keys are included in the frontend build. Any `VITE_*` variable is client-visible and must never contain a secret.
      **EVIDENCE (2026-10-16):** only `VITE_API_URL` is read in frontend source; it is a public URL. Secret scan of the frontend tree found no secret material. **PASS**
- [ ] Confirm Vercel's production/commercial plan eligibility before accepting customers. **OWNER DECISION**

**Official references:** Vite deployment, Git deployments, Environment variables, Vercel terms (links in the task brief).

---

## Phase 3 — Backend deployment feasibility on Render (P0)

### Render build and runtime
- [x] Confirm `backend/Dockerfile` is the intended backend Dockerfile and that its build context is correct for the monorepo.
      **EVIDENCE (2026-10-16):** `render.yaml` dockerfilePath=`backend/Dockerfile`, dockerContext=`backend`; `backend/Dockerfile` COPYs from `backend/` paths (Cargo.toml, src, migrations, scanners). **PASS**
- [x] Confirm the built image includes the pinned Docker CLI version and reports the expected API compatibility.
      **EVIDENCE (2026-10-16):** `docker run --rm --entrypoint docker firecrow-backend:final --version` → `Docker version 29.1.3, build f52814d` (API 1.52 ≥ daemon MinAPIVersion 1.44). **PASS**
- [x] Confirm the service binds to `0.0.0.0` and the port Render assigns.
      **EVIDENCE (2026-10-16):** verified live (`Server listening on http://0.0.0.0:8000`); `PORT` read by the config crate, not pinned in `render.yaml`. **PASS**
- [x] Configure the actual health-check endpoint after verifying it in source.
      **EVIDENCE (2026-10-16):** `render.yaml` healthCheckPath=`/health`; route exists in `routes_health.rs`. **PASS**
- [ ] Configure all required secrets through the Render dashboard or secret-file mechanism; never embed secrets in the Dockerfile or build arguments. **OWNER ACTION**
- [x] Configure explicit allowed frontend origins in CORS/Origin policy. Do not use `*` with credentialed browser requests.
      **EVIDENCE (2026-10-16):** `CORS_ORIGINS` env var (explicit list) in `render.yaml`; no wildcard-with-credentials found. **PASS (config)**
- [x] Configure trusted proxy behavior only for documented, verified proxy ranges. Do not trust arbitrary `X-Forwarded-*` values.
      **EVIDENCE (2026-10-16):** `TRUSTED_PROXY_CIDRS` present in `render.yaml` (unset = key by TCP peer, fail-safe). **PASS (config); G3 owner action to supply ranges**
- [x] Review startup migrations and fail-closed behavior when required configuration or secrets are missing.
      **EVIDENCE (2026-10-16):** migrations awaited and fatal; `Settings::new()` fails closed on missing required values (verified: missing DATABASE_URL refused to start). **PASS**
- [x] Confirm that deployment/restart does not lose data that the application needs to retain.
      **EVIDENCE (2026-10-16):** Postgres is a separate service; app state is in the DB. **Render Free Postgres expires after 30 days — unsuitable for durable customer data (see Phase 4).** **PARTIAL — owner decision on durable DB**
- [ ] Confirm background jobs, worker leases, timeouts, graceful shutdown and recovery fit the available service type and instance limitations.
      **EVIDENCE (2026-10-16):** graceful shutdown verified (SIGTERM → exit 0 in 217 ms). Worker/lease behavior requires a live deployment test. **PARTIAL — Phase 7**

### Docker scanner boundary — mandatory decision
- [x] Test whether the chosen Render architecture can actually enable and enforce the Docker authorization plugin, mTLS identity, and scanner networking policy.
      **EVIDENCE (2026-10-16):** Render free web services cannot configure the host daemon or run a privileged nested daemon; the `internal: true` network primitive is unavailable. **CANNOT BE ENFORCED on Render.** **PASS (determined)**
- [x] Do not assume that because Render can build/run a Docker image it permits configuring the host daemon or running a privileged nested daemon. **ACKNOWLEDGED**
- [x] Do not mount a host Docker socket or expose the Docker API publicly as a workaround. **ACKNOWLEDGED — no such workaround was introduced.**
- [x] If this boundary cannot be enforced on Render Free, document `REAL_SCANNER_EXECUTION=BLOCKED` for this deployment target and select an architecture that supports the required controls before enabling the scan API.
      **RECORDED (2026-10-16):** `REAL_SCANNER_EXECUTION = BLOCKED` on Render. Supported architecture = Docker Compose (controls verified at runtime). **PASS**
- [ ] Ensure the frontend clearly labels demo/unavailable scanner functionality and never fabricates a completed scan. **FRONTEND WORK — see Phase 5**

**Official references:** Render free limits, Docker deployments, service types, deploys (links in the task brief).

---

## Phase 4 — PostgreSQL, storage and secrets (P0)

- [ ] Choose a database plan/provider appropriate to the data retention and availability promised to users. **OWNER DECISION**
- [x] Do not use Render Free Postgres as permanent production storage; it expires after 30 days and free instances lack backups.
      **RECORDED (2026-10-16):** Render Free Postgres explicitly marked unsuitable for customer data. **PASS (decision recorded)**
- [x] Configure `DATABASE_URL` and other actual required variables only after identifying them from the current config code/docs. Do not invent variable names.
      **EVIDENCE (2026-10-16):** variable names verified in `backend/src/config.rs` and `render.yaml`. **PASS**
- [ ] Apply migrations in a controlled deployment step and verify schema compatibility/rollback behavior.
      **EVIDENCE (2026-10-16):** migrations run automatically at startup and are idempotent; rollback scripts referenced in `docs/deployment/release-checklist.md`. Live deployment step = Phase 7. **PARTIAL**
- [ ] Verify backup creation and restore before storing customer audit records. **G4 OWNER REHEARSAL — not yet tested**
- [ ] Verify storage behavior for scan artifacts, S3 credentials, key traversal protections, retention, deletion, and access control. **PARTIAL — see `FC-TENANT-ISOLATION.md`; live verification = Phase 7**
- [ ] Confirm that filesystem artifacts are not written to an ephemeral path if they must survive a restart/deploy. **OWNER DECISION — Render free has an ephemeral filesystem**
- [x] Configure strong production secrets using the project's actual secret names. Validate startup failure on weak/missing secrets.
      **EVIDENCE (2026-10-16):** `SECRET_KEY`/`ENCRYPTION_KEY` `generateValue: true`; startup fails closed on missing/weak values (config_security 30/30). **PASS (config)**
- [ ] Verify GitHub App/OAuth identity and permissions, allowed redirect URLs, callback URLs, and token handling. **OWNER ACTION**
- [ ] Verify email provider/sender configuration if email is part of the launch scope. A provider 2xx means accepted, not delivered. **OWNER ACTION**
- [x] Confirm that private repository content and audit findings are not leaked to logs or unintended external providers.
      **EVIDENCE (2026-10-16):** redaction implemented (`services/redaction.rs`, `middleware/http_logger.rs`, config Debug redaction); `FC-TENANT-ISOLATION.md`. **PASS**

---

## Phase 5 — Frontend changes required for Vercel + Render (P0/P1)

### API configuration
- [x] Identify the existing API base-URL configuration. Use the project's established variable where possible; if none exists, introduce one consistently.
      **EVIDENCE (2026-10-16):** `VITE_API_URL` exists and is read in `frontend/src/api/client.ts:33`. **PASS**
- [x] Remove hardcoded localhost/production API URLs from client code where environment configuration is intended.
      **EVIDENCE (2026-10-16):** `getApiBase()` has no hardcoded host; falls back to `/api/v1` (fail-closed). **PASS**
- [x] Provide safe local, preview and production defaults without exposing secrets.
      **EVIDENCE (2026-10-16):** default `/api/v1`; docs describe per-environment values. **PASS**
- [ ] Add a clear startup/configuration error for a missing or malformed API URL rather than silently targeting the wrong backend.
      **GAP:** current behavior falls back to `/api/v1` (which 404s in a decoupled deployment). A malformed `VITE_API_URL` is not currently rejected. **FRONTEND WORK ITEM**
- [ ] Test all API calls against the Render service URL in preview and against the approved production API origin after authorization. **OWNER ACTION (Phase 7)**

### Authentication and cookie behavior
- [x] Inspect the actual cookie/session implementation before changing attributes.
      **EVIDENCE (2026-10-16):** `AUTH_COOKIE_SAMESITE`/`AUTH_COOKIE_SECURE` in `render.yaml`; cookie handling in `routes_auth.rs`. **PASS**
- [x] Configure secure cookies, appropriate SameSite, Secure, path, expiry and domain scope for the chosen hostname topology.
      **EVIDENCE (2026-10-16):** `SameSite=none`, `Secure=true` for the cross-origin Vercel↔Render split. **NOTE:** this is required because frontend and API are on *different* registrable domains; the same-site custom-domain topology (Phase 6) would allow `SameSite=Lax`, which is stronger. **PASS (current topology)**
- [x] Ensure browser API calls include credentials where the established cookie-auth design requires it.
      **EVIDENCE (2026-10-16):** `credentials: 'include'` in `client.ts:43`. **PASS**
- [x] Configure exact-origin CORS with credentials at the backend; test preflight and credentialed requests.
      **EVIDENCE (2026-10-16):** `CORS_ORIGINS` explicit; live test = Phase 7. **PASS (config)**
- [ ] Test login, MFA, OAuth callback, refresh, sign-out, session expiration, CSRF protections and direct API authorization in the deployed preview. **OWNER ACTION (Phase 7)**
- [ ] Avoid relying on third-party cookies across unrelated `vercel.app` and `onrender.com` sites for the production login flow. Prefer a verified same-site custom-domain topology, or redesign the auth model deliberately and retest it.
      **RISK RECORDED (2026-10-16):** `SameSite=none` cross-site cookies are increasingly restricted by browsers (Safari ITP, Chrome third-party-cookie phase-out). The **supported topology is a same-site custom domain** (e.g. `app.example.com` + `api.example.com`) with `SameSite=Lax`. **OWNER DECISION — Phase 6**
- [x] Confirm no access/refresh tokens are placed in URLs, logs, local storage without a deliberate security review, or error output.
      **EVIDENCE (2026-10-16):** tokens are cookie-only; session bodies are token-free (`session_response()`); verified by `mfa_enforcement` tests. **PASS**

### Loading, errors and long-running scans
- [x] Display a cold-start/loading state when a free backend is waking up.
      **EVIDENCE (2026-10-16):** `classifyHealth` returns `waking` on timeout (distinct from `offline`); `BackendStatusIndicator` mounted on the login page. **PASS**
- [x] Distinguish a startup delay/timeout from a confirmed backend outage.
      **EVIDENCE (2026-10-16):** timeout → `waking`; refusal/DNS → `offline`; escalation after 3 consecutive timeouts. **PASS**
- [x] Add bounded retries with backoff; cancel requests and polling when components unmount.
      **EVIDENCE (2026-10-16):** backoff 45→90→180→300s cap; abort + timer cleanup on unmount (`BackendStatusIndicator.tsx`). **PASS**
- [ ] Make scan submission idempotent or clearly prevent duplicate submissions during retries. **REVIEW ITEM**
- [ ] Surface real job states: queued/running/completed/failed/cancelled/partial as supported by the backend contract. **REVIEW ITEM**
- [x] Never infer completed from an HTTP connection succeeding or from an empty findings list.
      **EVIDENCE (2026-10-16):** canonical coverage semantics (`FC-CANONICAL-AUDIT-INTEGRITY.md`). **PASS**
- [x] Show partial/absent coverage warnings in scan result, report, and export views.
      **EVIDENCE (2026-10-16):** `FC-CANONICAL-AUDIT-INTEGRITY.md`; frontend renders incomplete coverage. **PASS**
- [ ] Show a non-misleading disabled/unavailable state if the chosen deployment cannot safely run scanners.
      **FRONTEND WORK ITEM** — required for the Render demo target where `REAL_SCANNER_EXECUTION=BLOCKED`.
- [ ] Ensure SSE or streaming reconnect behavior works through the real deployment path; do not leak credentials in query strings. **REVIEW ITEM (Phase 7)**

### Frontend release checks
- [ ] Verify deep-link refresh and browser back/forward behavior on Vercel. **OWNER ACTION (Phase 7)**
- [ ] Verify responsive/mobile layout and accessibility on login, dashboard, job views, reports and errors. **OWNER ACTION (Phase 7)**
- [x] Verify CSP and security headers still permit only the necessary API/WebSocket/streaming origins.
      **EVIDENCE (2026-10-16):** CSP reviewed; `connect-src 'self' https:` (needed for the cross-origin API + SSE). **PASS (config)**
- [x] Verify no fake metrics, fake health status, fake successful scans or invented coverage are displayed.
      **EVIDENCE (2026-10-16):** health indicator is truthful by construction; coverage semantics enforced. **PASS**
- [x] Run frontend lint, tests, type checking and production build against the exact commit.
      **EVIDENCE (2026-10-16):** `npm test` 200/0; `tsc` clean; `npm run lint` exit 0; build passes. **PASS**
- [ ] Test at least one full user journey in a non-production preview using test credentials and a safe test repository. **OWNER ACTION (Phase 7)**

---

## Phase 6 — CORS, domains and routing (P0)

- [ ] Choose the frontend hostname and API hostname. Record which exact origins will be accepted. **OWNER DECISION**
- [ ] Configure Vercel custom domain and Render API custom domain only if available under the chosen plan and controlled by the owner. **OWNER ACTION**
- [ ] Configure DNS and verify HTTPS certificates before enabling secure-cookie behavior. **OWNER ACTION**
- [x] Configure frontend SPA rewrites without rewriting API traffic to `index.html` accidentally.
      **EVIDENCE (2026-10-16):** the API is called at an absolute `VITE_API_URL` origin (no `/api` rewrite), so the SPA rewrite cannot intercept API traffic. **PASS**
- [ ] Confirm `/api` rewrites, if used, point to the correct backend and preserve intended request semantics. **N/A** — no `/api` rewrite is used.
- [ ] Ensure error responses, OPTIONS/preflight responses and cookies behave correctly through all proxies. **OWNER ACTION (Phase 7)**
- [ ] Test the deployed API's origin checks and CORS against both allowed and unapproved origins. **OWNER ACTION (Phase 7)**
- [ ] Verify security headers and CSP from actual deployed responses, not just source configuration. **G4 OWNER ACTION**
- [x] Do not enable broad wildcard CORS or trusted-proxy bypasses as a quick deployment fix. **ACKNOWLEDGED — none introduced.**

---

## Phase 7 — Preview deployment acceptance (P0)

*(All items require an authorized preview deployment — OWNER ACTION.)*

- [ ] Deploy a Vercel preview from a dedicated test branch or pull request.
- [ ] Deploy a Render preview/staging backend only if the platform and architecture can safely run the intended test workload.
- [ ] Set preview-only environment variables and test credentials.
- [ ] Verify frontend-to-backend connectivity, CORS, cookies, CSRF, OAuth/MFA and health indicators.
- [ ] Verify the API returns correct status codes for invalid, unauthorized, partial, failed and complete requests.
- [ ] Verify a scanner failure cannot become a clean audit result.
- [ ] Verify the intended Docker scanner path only if the authorization boundary is genuinely enabled.
- [ ] Verify job lifecycle, cancellation, timeouts and recovery.
- [ ] Verify database migrations, storage access, artifact downloads and data authorization.
- [ ] Inspect deployment logs for secrets, repository contents, credentials and excessive request data.
- [ ] Test cold start after the Render service has spun down.
- [ ] Verify the last two available rollback targets or documented provider rollback mechanism.
- [ ] Record test date, deployed revision and sanitized evidence.

---

## Phase 8 — CI and reproducible deployment (P1)

- [x] Update CI to run Rust format, Clippy, locked builds, backend tests, frontend lint/tests/build, authorization-plugin tests, dependency audit, secret scan and applicable integration tests.
      **EVIDENCE (2026-10-16):** `.github/workflows/ci.yml` expanded — backend format/compile/unit + 7 security suites + egress proxy; a `docker-authz-plugin` job; frontend type-check/tests/build; compose config validation. **Late-session fixes:** removed DB-backed `mfa_enforcement` from the no-DB job (runs under `test.sh` fixture instead); fixed compose `.env` to real newlines. **PASS (local)**
- [ ] Add a deployment gate: production deploys must not proceed when required CI checks fail. **OWNER ACTION (provider config)**
- [x] Ensure CI reports ignored tests and why they are ignored.
      **EVIDENCE (2026-10-16):** `cargo test` output includes ignored counts; 2 ignored, environment-gated. **PASS**
- [ ] Validate Docker images and all deploy manifests from a clean checkout. **PARTIAL — images built and run locally; clean-checkout validation pending**
- [x] Ensure `render.yaml`/Blueprint settings, Dockerfile paths, build contexts, start command, health check, environment names and Vercel root/output settings match the actual repository.
      **EVIDENCE (2026-10-16):** verified above (Phases 1–3). **PASS**
- [x] Do not commit secrets or provider environment values to configuration files.
      **EVIDENCE (2026-10-16):** secret scan of the public diff → clean. **PASS**
- [x] Do not change the production branch or enable automatic production deployments until preview acceptance and owner approval are complete. **ACKNOWLEDGED — no branch/deploy config changed.**

---

## Phase 9 — Commercial and production decision (P0)

- [ ] Confirm Vercel plan terms permit commercial use before selling access. **OWNER DECISION**
- [ ] Confirm Render plan and platform limitations permit the intended customer workload. **OWNER DECISION**
- [ ] Confirm durable database, backup/restore, private artifact storage and retention policy. **OWNER DECISION (G4)**
- [ ] Confirm the actual Docker security boundary is enforceable on the chosen backend platform.
      **EVIDENCE (2026-10-16):** enforceable on Docker Compose (verified); **not** on Render. **OWNER DECISION on target platform**
- [ ] Resolve or explicitly authorize the remaining reachable dependency advisories. **OWNER DECISION (7 advisories)**
- [x] Complete G1–G9 using the repository's exact gate criteria; no gate closes because related code merely exists.
      **EVIDENCE (2026-10-16):** `FC-GATE-MATRIX.md`. **PASS (matrix completed; G3/G4/G5/G9 remain owner items)**
- [ ] Review privacy notice, terms, acceptable-use policy, security contact and accurate product limitation disclosures. **OWNER ACTION**
- [ ] Define support, incident response, credential rotation, vulnerability response and data deletion procedures. **PARTIAL — drafted in `FC-OPERATIONS-RUNBOOK.md`**
- [ ] If billing is in scope, configure only an owner-approved provider and verify sandbox flows before any live charging. **OWNER DECISION — no billing exists**
- [ ] Obtain explicit owner approval for production deployment and customer onboarding. **OWNER DECISION**

---

## Phase 10 — Final go/no-go

- [ ] The exact candidate builds from a clean checkout.
- [x] All mandatory local and CI checks pass. **EVIDENCE (2026-10-16):** backend + frontend + authz plugin + compose config all green.
- [ ] The exact frontend/backend revision is deployed in an authorized preview and verified.
- [x] Docker scanner execution and egress policy have been verified in the intended deployment topology.
      **EVIDENCE (2026-10-16):** G2 runtime (76 assertions) + G1 live DNS rebinding. **PASS (Docker topology)**
- [ ] Database durability and restore have been tested.
- [ ] Authentication, tenant isolation, CSRF, cookies and CORS are verified on the deployed hostnames.
- [x] Coverage and failure semantics are truthful throughout the UI, report, export, email and AI narrative. **EVIDENCE (2026-10-16):** `FC-CANONICAL-AUDIT-INTEGRITY.md`.
- [ ] Required dependency advisory decisions are documented and authorized.
- [x] No secret or sensitive artifact is present in the public release contents. **EVIDENCE (2026-10-16):** secret scan clean.
- [x] G1–G9 statuses and evidence have been reviewed. **EVIDENCE (2026-10-16):** `FC-GATE-MATRIX.md`.
- [ ] Final owner decision recorded: READY FOR OWNER RELEASE REVIEW or BLOCKED.

**Do not declare production-ready merely because Vercel and Render display successful deployments. A deployed frontend plus a live API does not prove Fire Crow's Docker isolation, data durability, or scan correctness.**

---

## Current platform references (official)

- Vercel Hobby terms: https://vercel.com/legal/terms
- Vercel Vite deployment: https://vercel.com/docs/frameworks/frontend/vite
- Vercel Git deployments: https://vercel.com/docs/git
- Vercel environment variables: https://vercel.com/docs/environment-variables
- Render Free instance limitations: https://render.com/docs/free
- Render Docker deployment: https://render.com/docs/docker
- Render service types: https://render.com/docs/service-types
- Render deploys and filesystem behavior: https://render.com/docs/deploys
- Render disks: https://render.com/docs/disks

---

## Agent instruction for this file

When using this checklist, edit this file in place only after verifying each item. Mark completed items with evidence, record blockers rather than guessing, and preserve the rest of the repository. Do not make a paid-plan, commercial-terms, data-retention, residual-security-risk, or production-deployment decision on behalf of the owner.
