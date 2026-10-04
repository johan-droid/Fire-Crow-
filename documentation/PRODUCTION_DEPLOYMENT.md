# Fire Crow — Production Deployment Contract

Frozen-backend operations reference. Complements `RELEASE_GATE.md`
(release evidence) and `THREAT_MODEL.md` (adversary model).
No architecture is changed here.

## Topology (actual, no invented services)

```text
Browser (Vite SPA, ../frontend/dist, optional)
   |  /api/v1/*
API (Axum 0.7, :8000, build_app + serve_frontend)
   |-- PostgreSQL (sqlx PgPool; migrations ./migrations; source of truth)
   |-- Redis (OPTIONAL: session/token-revocation fast path; DB fallback)
   |-- Worker pool (workers/mod.rs: queue + heartbeat + reaper + retry)
   |     |-- GitHub tarball fetch (agents/fetch.rs)
   |     |-- Scanner containers (sandbox.rs + agents/scanner.rs)
   |           gitleaks v8.18.4 (--network=none)
   |           osv-scanner v2.2.4 (--network=bridge, SOLE exception)
   |           semgrep 1.96.0 (--network=none, local ruleset)
   |-- External: GitHub API (repo read, token exchange, Check Runs)
   |-- External OPTIONAL: Gemini (narrative), SMTP (email), Telegram
```

## Classification

- **CORE (audit fails without it):** PostgreSQL, Docker, GitHub reachability
  (for fetch/token), scanner images, `DATABASE_URL`, `SECRET_KEY`,
  `ENCRYPTION_KEY`, GitHub App identity *or* `GITHUB_TOKEN` path.
- **OPTIONAL (absent = degraded-but-safe):** Redis, Gemini, SMTP,
  Telegram, R2/S3 storage, frontend static dir.
- **DEGRADED-BUT-SAFE:** Redis down → DB-backed revocation/session
  (`services/auth.rs`); Gemini down → audit + no narrative; SMTP/Telegram
  down → delivery error, report untouched; R2 absent → local disk.
- **FAIL-CLOSED:** absent SECRET_KEY/ENCRYPTION_KEY (refuse startup);
  malformed DATABASE_URL; half GitHub App identity; unparseable scanner
  report (FAILED, never clean); empty semgrep scan (`no_files_analyzed`).

## API startup

Required env: `DATABASE_URL` (valid postgres URL), `SECRET_KEY` (≥32 chars),
`ENCRYPTION_KEY` (≥32 chars), `FRONTEND_URL`, `CORS_ORIGINS`.
Health: `GET /health`, `/api/v1/health[/deep|/ready|/live]`.
Migrations: `sqlx migrate run` / `#[sqlx::test(migrations)]`; 28 files,
fresh-apply + idempotent re-run proven. No extensions required.
Pools: `DATABASE_POOL_SIZE` default 10, timeout/recycle knobs in config.rs.

## Worker

`workers/mod.rs`: `run_audit_job` single funnel (timeout + failure UPDATE
guarded on non-terminal status); heartbeat lease; reaper revives dead-worker
jobs preserving attempt history; graceful shutdown via cancellation token;
retry creates attempt N+1, never reopens terminal rows (DB immutability
triggers); backpressure gate = per-user advisory transaction lock
(`routes_audit.rs:163`), webhook path included.

## PostgreSQL

Migrations `./migrations` in order; backup = `pg_dump` of full schema
(findings/reports/narratives/deliveries keyed by `execution_id`);
restore = fresh DB + migrate + restore dump; pool ≥ worker concurrency + API.
Terminal immutability enforced by DB triggers, not app convention.

## Redis

Responsibilities ONLY: session fast path + token-revocation fast path.
Loss behavior: every read falls back to Postgres; audit/scan/report paths
never touch Redis. Safe to run Redis-less in controlled beta.

## GitHub App (production)

`GITHUB_APP_ID` + `GITHUB_APP_PRIVATE_KEY` (both or neither) +
`GITHUB_APP_WEBHOOK_SECRET`; webhook `POST /api/v1/github/webhook`
(HMAC-SHA256, 30/min); install → `github_installations`; token exchange per
job (never persisted); push/PR → pinned-SHA audit; Check Run
`firecrow-security-audit` = status only, no inline annotations.
Required permissions: contents read, checks write, metadata read.

## Known dead configuration (do NOT set expecting effect)

`RESEND_API_KEY`, `BREVO_*`, `resend_api_key`/`brevo_api_key` fields
(SMTP-only transport); `GOOGLE_CLIENT_ID/SECRET` (no OAuth route reads
them); `FIRE_CROW_MOCK_SANDBOX`, `FIRE_CROW_SCANNER_IMAGE`,
`SANDBOX_*_IMAGE`, `GEMINI_FALLBACK_*`, `PASSWORD_AUTH_ENABLED`,
`REPORT_COMPACT_MODE`, `REPORT_STORE_FULL_ARTIFACT_JSON`,
`OAUTH_STATE_EXPIRE_MINUTES`, `OAUTH_EXCHANGE_CODE_TTL_SECONDS`,
`SESSION_LAST_SEEN_UPDATE_INTERVAL_SECONDS`
(`cf_secrets.json.example` legacy keys). Cleanup is a code change and is
explicitly deferred out of the frozen gate — this file is the warning label.
