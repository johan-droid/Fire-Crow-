# Backend testing

## Running the suite

```bash
cd backend
./scripts/test.sh          # everything: starts PostgreSQL + Redis, runs, tears down
./scripts/test.sh --unit   # only tests that need no database
./scripts/test.sh --keep   # leave the test containers running for debugging
```

`scripts/test.sh` is all a clean checkout needs. It brings up the services in
`docker-compose.test.yml`, waits for both to report healthy, exports the
connection strings, runs `cargo test`, and tears the containers down.

## Layout & Test Categories

The backend maintains 39 integration and unit test targets:

| Test Category / Suite | Database Required | Target Files | Verification Scope |
|---|---|---|---|
| **Core & Unit** | No | `src/**` unit tests | Pure functions, cryptographic boundaries, `docker_argv`, redaction algorithms |
| **Config & Security** | No | `tests/config_security.rs` | Fail-closed secret requirements, key lengths, known-insecure value rejection |
| **Security Regressions** | No / Mixed | `tests/security_regressions.rs` | Named regressions for all confirmed findings (secret-safe `Debug`, path traversals) |
| **Sandbox Hardening** | No | `tests/sandbox_hardening.rs` | Docker argument construction, resource ceilings, network flags, mount validation |
| **Repo Intake & Fetch** | No / Mocked | `tests/repo_fetch.rs`, `tests/repo_intake.rs`, `tests/repo_inventory.rs` | Tarball extraction bounds, symlink rejection, traversal protection, SHA pinning |
| **Scanner Runtimes** | No (Unit) / Docker (E2E) | `tests/scanner_runtime.rs`, `tests/gitleaks_integration.rs`, `tests/osv_integration.rs`, `tests/semgrep_integration.rs` | Scanner exit codes, output parsing, live Docker execution, failure semantics |
| **Canonical Audit v1** | No | `tests/canonical_audit.rs`, `tests/scan_contract.rs`, `tests/scan_integrity.rs` | Canonical identity, deduplication, evidence bounds, quarantine, score invariants |
| **Deterministic Reports** | No | `tests/report.rs` | Byte determinism, golden fixtures (Markdown, JSON, HTML), pure reconstruction |
| **Report Persistence** | **Yes** | `tests/report_persistence.rs` | Atomic report insertion, byte-identical regeneration from `canonical_json` |
| **Atomic Commit & Lifecycle** | **Yes** | `tests/atomic_audit_commit.rs`, `tests/audit_lifecycle.rs`, `tests/job_lifecycle.rs` | Single transaction finalization, execution leases (`owner_token`), trigger immutability |
| **Concurrency & Backpressure** | **Yes** | `tests/submission.rs` | Per-user advisory lock gate, distinct user concurrency, webhook backpressure |
| **AI Narrative & Validator** | No | `tests/ai_narrative.rs`, `tests/ai_narrative_generation.rs` | Schema enforcement, rejection of invented findings, score/severity preservation |
| **Narrative Persistence** | **Yes** | `tests/ai_narrative_persistence.rs` | Execution-scoped narrative storage and immutability |
| **LLM Provider Transport** | No / WireMock | `tests/llm_provider.rs` | Gemini transport, timeout handling, transient retries (429, 5xx), key hygiene |
| **Delivery Channels** | **Yes** | `tests/email_delivery.rs`, `tests/telegram_delivery.rs` | SMTP and Telegram idempotency keys, destination immutability, state transitions |
| **GitHub App & Webhooks** | **Yes** | `tests/github_app.rs` | HMAC-SHA256 verification, delivery deduplication, installation tokens, Check Runs |
| **Migrations & Recovery** | **Yes** | `tests/startup_and_migrations.rs`, `tests/kill_recovery.rs` | 28 migrations fresh-apply & idempotent re-run, orphan reaper, dead worker recovery |
| **Schema Reconciliation** | **Yes** | `tests/schema_reconciliation.rs` | Zero drift between Rust `FromRow` models and PostgreSQL database schema |
| **Auth & IAM Security** | **Yes** | `tests/iam_authorization.rs`, `tests/system_authorization.rs` | RBAC authorization gates, admin permissions, MFA rules, session revocation |
| **Test Fixtures & Support** | — | `tests/support/mod.rs` | Seed utilities, token minters, database pool test harnesses |

## How isolation works

Database-backed tests use `#[sqlx::test(migrations = "./migrations")]`. For each
test, sqlx creates a brand-new database, applies the whole migration chain, runs
the test, and drops it. Consequences:

- **No shared state.** A test cannot be affected by another test's rows, or by
  whatever is in a developer's local database.
- **Migrations are exercised on every single test.** If a migration breaks, many
  tests break, not one.
- **No fixture cost.** There is no seeding script to keep in sync.

Test settings are built by deserialising a literal rather than reading process
environment variables, so tests running in parallel cannot race each other's
`std::env::set_var`.

## Rules for writing tests here

**Seed a row before asserting on a list endpoint.** This is not stylistic. A
handler that does `SELECT *` and maps rows with `FromRow` will never attempt
decoding on an empty table, so a structurally broken model returns `200 []` and
the test passes. This exact trap shipped in production: `/sso/providers`,
`/iam/policies`, `/pam/requests` and `/verify/domains` all returned `200 []`
while their models referenced columns that no migration created, and only
returned 500 once a row existed.

```rust
// Wrong: passes even when the model is completely broken.
let res = app.get("/api/v1/iam/policies").await;
assert_eq!(res.status_code(), 200);

// Right: a row forces decoding.
sqlx::query("INSERT INTO iam_policies (id,name,priority,policy_json,created_at)
             VALUES ($1,'probe',0,'{}',NOW())")
    .bind(uuid::Uuid::new_v4().to_string())
    .execute(&pool).await?;
let res = app.get("/api/v1/iam/policies").await;
```

**Assert database state, not only the HTTP response.** For any destructive or
state-changing operation, verify the rows afterwards.

**Name security regressions `security_<finding>_<description>`.** A regression
should be a named test failure rather than a thing somebody has to notice.

**Never put a real secret in a test.** `tests/support` uses fixed throwaway keys.

## When no database is configured

`#[sqlx::test]` resolves `DATABASE_URL` at runtime and **panics** if it cannot.
So the suite fails loudly rather than silently reporting a green run — the
dangerous default is already handled. `infra_ci_will_not_silently_skip_database_tests`
adds a second, clearer guard for CI in particular.

If you want the database-free tests only, use `./scripts/test.sh --unit`, which
selects the relevant targets explicitly instead of relying on skipping.

## CI

CI must export the same variables the script sets:

```yaml
TEST_DATABASE_URL: postgres://firecrow_test:firecrow_test@localhost:55433/postgres
TEST_REDIS_URL: redis://localhost:56480
CI: "true"
```
