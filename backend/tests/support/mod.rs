//! Integration-test fixtures.
//!
//! Every helper is deterministic and self-contained: no dependence on a
//! developer's existing database, and no dependence on process-global environment
//! variables (settings come from deserialising a literal, so tests running in
//! parallel cannot race each other's `std::env::set_var`).
//!
//! Database-backed tests use `#[sqlx::test(migrations = "./migrations")]`, which
//! gives each test its own freshly migrated database. That is what makes the
//! assertions meaningful: a test that seeds a row genuinely exercises `FromRow`
//! decoding, which an empty table would silently skip.

#![allow(dead_code)] // a fixture library; not every test uses every helper

use axum_test::TestServer;
use firecrow_backend::app::{build_app, build_state};
use firecrow_backend::config::Settings;
use sqlx::PgPool;

/// The URL of the PostgreSQL server used for integration tests, if configured.
pub fn test_database_url() -> Option<String> {
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .filter(|v| !v.trim().is_empty())
}

/// The Redis URL used for integration tests, if configured.
pub fn test_redis_url() -> Option<String> {
    std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

/// Whether a missing database must fail rather than skip.
///
/// On CI an unavailable database must never be mistaken for a passing run, so a
/// test that needs the database panics instead of returning early.
pub fn database_required() -> bool {
    matches!(std::env::var("CI").as_deref(), Ok("true") | Ok("1"))
        || std::env::var("REQUIRE_TEST_DB").is_ok()
}

/// Test-only secrets. Public by construction, and only ever used against a
/// throwaway database.
pub const TEST_SECRET_KEY: &str = "test-only-signing-key-not-valid-in-production-0000";
pub const TEST_ENCRYPTION_KEY: &str = "test-only-encryption-key-not-valid-in-prod-0000";

/// Deterministic settings for tests.
///
/// `debug` is false so error sanitization is exercised exactly as in production.
/// `rate_limit_enabled` is false by default because most tests issue several
/// requests from one "IP"; the rate-limit tests re-enable it explicitly.
pub fn test_settings() -> Settings {
    serde_json::from_value(serde_json::json!({
        "secret_key": TEST_SECRET_KEY,
        "encryption_key": TEST_ENCRYPTION_KEY,
        "frontend_url": "https://app.firecrow.test",
        "cors_origins": "https://app.firecrow.test",
        "database_url": test_database_url().unwrap_or_else(|| "postgres://unused".into()),
        "debug": false,
        "rate_limit_enabled": false,
        "csrf_enabled": false,
        "r2_endpoint_url": "",
    }))
    .expect("test settings must deserialize")
}

/// The full application router against a per-test database, with no static-file
/// fallback so unknown paths 404 instead of returning `index.html`.
pub async fn test_app(pool: PgPool) -> TestServer {
    let state = build_state(test_settings(), pool, None)
        .await
        .expect("state must build for tests");
    TestServer::new(build_app(state, false)).expect("test server")
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn unique(prefix: &str) -> String {
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{prefix}-{n}")
}

/// A seeded user.
#[derive(Debug, Clone)]
pub struct SeededUser {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password: String,
    pub tenant_id: String,
}

impl SeededUser {
    /// A valid bearer token for this user, signed with the test key.
    pub fn token(&self) -> String {
        firecrow_backend::services::auth::create_access_token(
            &self.id,
            &self.username,
            TEST_SECRET_KEY,
            &self.tenant_id,
            60,
        )
        .expect("mint token")
        .0
    }

    /// `Authorization` header value.
    pub fn auth_header(&self) -> String {
        format!("Bearer {}", self.token())
    }
}

/// Insert an active user with a known password.
pub async fn seed_user(pool: &PgPool, prefix: &str) -> SeededUser {
    let suffix = unique(prefix);
    let user = SeededUser {
        id: uuid::Uuid::new_v4().to_string(),
        username: suffix.clone(),
        email: format!("{suffix}@firecrow.test"),
        password: "Test-Correct-Horse-Battery-9!".into(),
        tenant_id: String::new(),
    };
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, is_active, credit_balance, created_at)
         VALUES ($1,$2,$3,$4,true,0.0,NOW())",
    )
    .bind(&user.id)
    .bind(&user.username)
    .bind(&user.email)
    .bind(firecrow_backend::services::auth::hash_password(&user.password).expect("hash"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

/// Insert a tenant, attach a fresh user to it, and return both.
///
/// `users.tenant_id` is mirrored into the JWT at mint time, and handlers such as
/// `GET /tenant/` read the tenant from the token rather than the database. A test
/// that attaches a tenant after minting a token would therefore see `tenant_id`
/// of `""` and a misleading 404, so the user must be created with the tenant
/// already set.
pub async fn seed_tenant_with_user(pool: &PgPool, prefix: &str) -> (String, SeededUser) {
    let tenant_id = seed_tenant(pool, prefix).await;
    let suffix = unique(prefix);
    let user = SeededUser {
        id: uuid::Uuid::new_v4().to_string(),
        username: suffix.clone(),
        email: format!("{suffix}@firecrow.test"),
        password: "Test-Correct-Horse-Battery-9!".into(),
        tenant_id: tenant_id.clone(),
    };
    sqlx::query(
        "INSERT INTO users
           (id, username, email, password_hash, is_active, credit_balance, tenant_id, created_at)
         VALUES ($1,$2,$3,$4,true,0.0,$5,NOW())",
    )
    .bind(&user.id)
    .bind(&user.username)
    .bind(&user.email)
    .bind(firecrow_backend::services::auth::hash_password(&user.password).expect("hash"))
    .bind(&tenant_id)
    .execute(pool)
    .await
    .expect("seed tenant user");
    (tenant_id, user)
}

/// Insert a tenant and return its id.
pub async fn seed_tenant(pool: &PgPool, prefix: &str) -> String {
    let slug = unique(prefix);
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO tenants (id, name, slug, created_at) VALUES ($1,$2,$3,NOW())")
        .bind(&id)
        .bind(&slug)
        .bind(&slug)
        .execute(pool)
        .await
        .expect("seed tenant");
    id
}

/// Insert an audit job owned by `user_id` and return its id.
pub async fn seed_job(pool: &PgPool, user_id: &str, status: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, status, created_at, updated_at)
         VALUES ($1,$2,$3,$4,NOW(),NOW())",
    )
    .bind(&id)
    .bind(user_id)
    .bind("https://github.com/example/repo")
    .bind(status)
    .execute(pool)
    .await
    .expect("seed job");
    id
}

/// Make `user` satisfy the `AdminUser` predicate.
///
/// Follows the approved one-shot bootstrap in `documentation/IAM_BOOTSTRAP.md`:
/// create a role, grant it a permission from `ADMIN_PERMISSIONS`, then point the
/// user at that role.
///
/// This was the pre-Phase-5B-1 shape, which inserted an `iam_policies` row as the
/// foreign-key target. Phase 5B-1 repointed `role_permissions.role_id` at `roles`,
/// and Phase 8 caught the stale helper when its tests failed to grant admin.
pub async fn grant_admin(pool: &PgPool, user: &SeededUser) {
    let role_id = format!("test-admin-{}", uuid::Uuid::new_v4());

    sqlx::query(
        "INSERT INTO roles (id, name, description, created_at)
         VALUES ($1, $2, 'test fixture administrator role', NOW())",
    )
    .bind(&role_id)
    .bind(format!("role-{role_id}"))
    .execute(pool)
    .await
    .expect("create role (FK target for role_permissions)");

    sqlx::query("UPDATE users SET role_id = $1 WHERE id = $2")
        .bind(&role_id)
        .bind(&user.id)
        .execute(pool)
        .await
        .expect("set role_id");

    sqlx::query(
        "INSERT INTO role_permissions (id, role_id, permission, resource_pattern, created_at)
         VALUES ($1,$2,'admin','*',NOW())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&role_id)
    .execute(pool)
    .await
    .expect("grant admin");
}

/// Deactivate a user, so `is_active` enforcement can be tested.
pub async fn deactivate_user(pool: &PgPool, user_id: &str) {
    sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("deactivate user");
}
