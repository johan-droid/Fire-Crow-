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

## Layout

| Suite | Needs a database | Purpose |
|---|---|---|
| `src/**` unit tests | no | pure functions, config validation, crypto |
| `tests/config_security.rs` | no | secret validation, proxy-header trust |
| `tests/security_regressions.rs` | no | named regressions for confirmed findings |
| `tests/integration_harness.rs` | **yes** | proves the harness itself is sound |
| `tests/support/mod.rs` | — | fixtures: seed users/tenants/jobs, build the app, mint tokens |

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
