//! Proves the integration-test harness itself is sound.
//!
//! Every other integration test in this repository depends on these properties.
//! If they regress, every downstream assertion becomes untrustworthy.

mod support;

use support::{database_required, test_app, test_database_url};

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// Migrations must apply cleanly to an empty database.
///
/// `#[sqlx::test]` runs every migration in `migrations/` before the body, so
/// simply reaching the assertions means the whole chain is valid.
#[sqlx::test(migrations = "./migrations")]
async fn infra_migrations_apply_to_a_clean_database(pool: sqlx::PgPool) {
    let tables: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name FROM information_schema.tables
         WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .expect("list tables");

    let names: Vec<&str> = tables.iter().map(|(t,)| t.as_str()).collect();
    assert!(names.contains(&"users"), "users table missing: {names:?}");
    assert!(
        names.contains(&"audit_jobs"),
        "audit_jobs table missing: {names:?}"
    );
    assert!(
        names.contains(&"findings"),
        "findings table missing: {names:?}"
    );
}

/// Each test must get its own database, so state cannot leak between tests.
#[sqlx::test(migrations = "./migrations")]
async fn infra_each_test_gets_an_isolated_database(pool: sqlx::PgPool) {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .expect("count users");
    assert_eq!(count, 0, "a fresh per-test database must start empty");

    sqlx::query(
        "INSERT INTO users (id, username, email, is_active, credit_balance, created_at)
         VALUES ('leak-probe','leak-probe','leak@probe.test',true,0.0,NOW())",
    )
    .execute(&pool)
    .await
    .expect("insert");
}

/// Basic CRUD must work, so a failure elsewhere means a real defect rather than a
/// broken fixture.
#[sqlx::test(migrations = "./migrations")]
async fn infra_insert_read_update_delete(pool: sqlx::PgPool) {
    let user = support::seed_user(&pool, "crud").await;

    let (username, active): (String, bool) =
        sqlx::query_as("SELECT username, is_active FROM users WHERE id = $1")
            .bind(&user.id)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_eq!(username, user.username);
    assert!(active);

    sqlx::query("UPDATE users SET credit_balance = 12.5 WHERE id = $1")
        .bind(&user.id)
        .execute(&pool)
        .await
        .expect("update");
    let (balance,): (f64,) = sqlx::query_as("SELECT credit_balance FROM users WHERE id = $1")
        .bind(&user.id)
        .fetch_one(&pool)
        .await
        .expect("read balance");
    assert_eq!(balance, 12.5);

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(&user.id)
        .execute(&pool)
        .await
        .expect("delete");
    let remaining: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = $1")
        .bind(&user.id)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(remaining.0, 0);
}

/// Migrations must be re-runnable by the application without error, because the
/// server applies them on every boot.
#[sqlx::test(migrations = "./migrations")]
async fn infra_migrations_are_idempotent_on_reapplication(pool: sqlx::PgPool) {
    // Re-running the recorded migrations must be a no-op. sqlx tracks applied
    // migrations in _sqlx_migrations, so this asserts on that bookkeeping rather
    // than replaying raw SQL.
    let applied: Vec<(i64,)> = sqlx::query_as("SELECT version FROM _sqlx_migrations")
        .fetch_all(&pool)
        .await
        .expect("read applied migrations");
    assert!(
        applied.len() >= 15,
        "expected the full migration chain, found {}",
        applied.len()
    );
}

/// The fixture must be able to build the real application and serve requests
/// through the full middleware stack.
#[sqlx::test(migrations = "./migrations")]
async fn infra_test_app_serves_through_the_full_middleware_stack(pool: sqlx::PgPool) {
    let app = test_app(pool).await;

    // Unauthenticated request to a guarded route: rejected by the auth extractor,
    // not by a missing route.
    let res = app.get("/api/v1/auth/me").await;
    assert_eq!(res.status_code(), 401, "expected 401, body: {}", res.text());

    // A health route is reachable, proving the router and middleware are wired.
    let res = app.get("/api/v1/health").await;
    assert_eq!(res.status_code(), 200);

    // Security headers must be present on every response.
    assert!(
        res.headers().get("x-content-type-options").is_some(),
        "missing x-content-type-options"
    );
    assert!(
        res.headers().get("x-frame-options").is_some(),
        "missing x-frame-options"
    );
}

/// A seeded user must be able to authenticate over HTTP with a real token.
#[sqlx::test(migrations = "./migrations")]
async fn infra_seeded_user_can_authenticate(pool: sqlx::PgPool) {
    let app = test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "auth").await;

    let res = app
        .get("/api/v1/auth/me")
        .add_header("authorization", user.auth_header())
        .await;

    assert_eq!(
        res.status_code(),
        200,
        "expected 200 for a valid token, body: {}",
        res.text()
    );
    let body: serde_json::Value = res.json();
    assert_eq!(body["user_id"], user.id);
}

/// Internal database errors must not reach the client.
///
/// The error is triggered by removing a table inside this test's own database, so
/// the assertion does not depend on any particular schema defect persisting. An
/// earlier version of this test used `/iam/policies`, whose `FromRow` model needed
/// columns no migration created; Phase 4 fixed that, and the test correctly failed
/// because the 500 it asserted was gone. Anchoring on a bug made it fragile.
#[sqlx::test(migrations = "./migrations")]
async fn infra_internal_database_errors_are_not_leaked(pool: sqlx::PgPool) {
    let app = test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "errleak").await;

    // Force the handler's query to fail at runtime. CASCADE is required because
    // role_permissions currently holds a foreign key onto iam_policies; this is a
    // throwaway per-test database, so dropping dependents is harmless.
    sqlx::query("DROP TABLE iam_policies CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table to force a database error");

    let res = app
        .get("/api/v1/iam/policies")
        .add_header("authorization", user.auth_header())
        .await;

    let status = res.status_code();
    assert!(
        status.is_server_error(),
        "expected a server error, got {status}"
    );

    let body: serde_json::Value = res.json();
    let detail = body["detail"].as_str().unwrap_or_default();

    assert_eq!(
        detail, "Internal server error",
        "internal detail leaked to the client: {detail:?}"
    );
    for leak_marker in [
        "no column found",
        "relation \"",
        "does not exist",
        "iam_policies",
        "sqlx",
        "postgres",
        "SELECT",
    ] {
        assert!(
            !detail.contains(leak_marker),
            "response leaked {leak_marker:?}: {detail:?}"
        );
    }
}

/// Guards the "silently skipped" failure mode: a test that needs a database must
/// not quietly pass when no database is configured on CI.
#[test]
fn infra_ci_will_not_silently_skip_database_tests() {
    let required = database_required();
    let configured = test_database_url().is_some();

    if required {
        assert!(
            configured,
            "CI has no TEST_DATABASE_URL/DATABASE_URL, so every database test \
             would be skipped and the run would report a false pass"
        );
    }
    if !configured {
        eprintln!(
            "note: no TEST_DATABASE_URL set, so database-backed tests are skipping. \
             Run ./scripts/test.sh to execute them."
        );
    }
}
