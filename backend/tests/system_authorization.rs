//! Phase 8: authorization regression for the `/system/database/*` endpoints.
//!
//! Findings S-2 and S-3: both handlers were gated on `AuthenticatedUser`, so any
//! registered user could enumerate database-wide row counts and run the
//! housekeeping sweep, which performs mass `UPDATE`/`DELETE` including deletion
//! of `login_failures` rows that back the login-lockout control.
//!
//! The important assertion here is not the status code. It is that an
//! unauthorized caller causes **no mutation at all**.

mod support;

use sqlx::PgPool;

const STATS: &str = "/api/v1/system/database/stats";
const HOUSEKEEPING: &str = "/api/v1/system/database/housekeeping";

/// Seed rows the housekeeping sweep is designed to remove, plus rows it must
/// never touch.
async fn seed_housekeeping_targets(pool: &PgPool, user_id: &str) {
    // One expired (>30d) and one recent login failure.
    sqlx::query(
        "INSERT INTO login_failures (id, key_hash, attempted_at) VALUES
         ('hk_old_lf','k_old',NOW() - INTERVAL '90 days'),
         ('hk_new_lf','k_new',NOW())",
    )
    .execute(pool)
    .await
    .expect("seed login_failures");

    // One expired and one live exchange code.
    sqlx::query(
        "INSERT INTO auth_exchange_codes (id, code, user_id, username, created_at, expires_at) VALUES
         ('hk_old_aec','oldcode',$1,'u',NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day'),
         ('hk_new_aec','newcode',$1,'u',NOW(), NOW() + INTERVAL '1 day')",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed auth_exchange_codes");

    // One expired (unrevoked) and one live session.
    sqlx::query(
        "INSERT INTO user_sessions
           (id, user_id, token_family, ip_hash, user_agent_hash, created_at, expires_at, is_revoked)
         VALUES
           ('hk_old_sess',$1,'fam_hk_old','h','h',NOW() - INTERVAL '2 days',NOW() - INTERVAL '1 day',false),
           ('hk_new_sess',$1,'fam_hk_new','h','h',NOW(),NOW() + INTERVAL '1 day',false)",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed user_sessions");
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    login_failures: i64,
    exchange_codes: i64,
    sessions_revoked: i64,
    sessions_live: i64,
}

async fn snapshot(pool: &PgPool) -> Snapshot {
    let (lf,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM login_failures")
        .fetch_one(pool)
        .await
        .unwrap();
    let (aec,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM auth_exchange_codes")
        .fetch_one(pool)
        .await
        .unwrap();
    let (rev,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM user_sessions WHERE is_revoked")
        .fetch_one(pool)
        .await
        .unwrap();
    let (live,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM user_sessions WHERE NOT is_revoked")
        .fetch_one(pool)
        .await
        .unwrap();
    Snapshot {
        login_failures: lf,
        exchange_codes: aec,
        sessions_revoked: rev,
        sessions_live: live,
    }
}

// ---------------------------------------------------------------------------
// Unauthenticated
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn system_stats_rejects_unauthenticated(pool: PgPool) {
    let app = support::test_app(pool).await;
    let res = app.get(STATS).await;
    assert_eq!(res.status_code(), 401, "body: {}", res.text());
    assert!(
        !res.text().contains("tables"),
        "an unauthenticated caller must not receive table metadata: {}",
        res.text()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn system_housekeeping_rejects_unauthenticated(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "anon").await;
    seed_housekeeping_targets(&pool, &user.id).await;
    let before = snapshot(&pool).await;

    let res = app.post(HOUSEKEEPING).await;
    assert_eq!(res.status_code(), 401, "body: {}", res.text());

    assert_eq!(
        snapshot(&pool).await,
        before,
        "an unauthenticated housekeeping call must not mutate anything"
    );
}

// ---------------------------------------------------------------------------
// Ordinary authenticated user
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn system_stats_rejects_ordinary_user(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "stats_plain").await;

    let res = app
        .get(STATS)
        .add_header("authorization", user.auth_header())
        .await;

    assert_eq!(res.status_code(), 403, "body: {}", res.text());
    let body: serde_json::Value = res.json();
    assert!(
        body.get("tables").is_none(),
        "an ordinary user must not receive database-wide row counts: {}",
        res.text()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn system_housekeeping_rejects_ordinary_user(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "hk_plain").await;
    seed_housekeeping_targets(&pool, &user.id).await;
    let before = snapshot(&pool).await;

    let res = app
        .post(HOUSEKEEPING)
        .add_header("authorization", user.auth_header())
        .await;

    assert_eq!(res.status_code(), 403, "body: {}", res.text());
    assert_eq!(
        snapshot(&pool).await,
        before,
        "SIDE EFFECT: an ordinary user must not delete login_failures, \
         auth_exchange_codes or revoke sessions"
    );
}

// ---------------------------------------------------------------------------
// Authorized user
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn system_stats_allows_admin(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let admin = support::seed_user(&pool, "stats_admin").await;
    support::grant_admin(&pool, &admin).await;

    let res = app
        .get(STATS)
        .add_header("authorization", admin.auth_header())
        .await;

    assert_eq!(res.status_code(), 200, "body: {}", res.text());
    let body: serde_json::Value = res.json();
    assert!(
        body["tables"].is_object(),
        "admin must still receive the stats payload"
    );
    assert!(body["total_tables"].as_u64().unwrap_or(0) > 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn system_housekeeping_allows_admin_and_still_works(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let admin = support::seed_user(&pool, "hk_admin").await;
    support::grant_admin(&pool, &admin).await;
    seed_housekeeping_targets(&pool, &admin.id).await;

    let res = app
        .post(HOUSEKEEPING)
        .add_header("authorization", admin.auth_header())
        .await;

    assert_eq!(res.status_code(), 200, "body: {}", res.text());
    let body: serde_json::Value = res.json();
    assert_eq!(body["status"], "completed");

    // Existing intended behaviour must be unchanged: expired rows are removed,
    // live rows are preserved.
    assert_eq!(
        snapshot(&pool).await,
        Snapshot {
            login_failures: 1,
            exchange_codes: 1,
            sessions_revoked: 1,
            sessions_live: 1,
        },
        "housekeeping must delete expired rows and preserve live ones"
    );
}

// ---------------------------------------------------------------------------
// Bypass attempts
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn system_housekeeping_resists_method_and_path_variation(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "bypass").await;
    seed_housekeeping_targets(&pool, &user.id).await;
    let before = snapshot(&pool).await;
    let h = user.auth_header();

    // Wrong method for each endpoint, and neighbouring paths.
    for (method, path) in [
        ("GET", HOUSEKEEPING),
        ("PUT", HOUSEKEEPING),
        ("PATCH", HOUSEKEEPING),
        ("DELETE", HOUSEKEEPING),
        ("GET", "/api/v1/system/database/housekeeping/"),
        ("GET", "/api/v1/system/database/housekeepin"),
        ("GET", "/api/v1/system/database"),
        (
            "POST",
            "/api/v1/system/database/housekeeping/../housekeeping",
        ),
        ("POST", "/api/v1/system/status"),
        ("POST", STATS),
    ] {
        let res = match method {
            "GET" => app.get(path).add_header("authorization", h.clone()).await,
            "PUT" => app.put(path).add_header("authorization", h.clone()).await,
            "PATCH" => app.patch(path).add_header("authorization", h.clone()).await,
            "DELETE" => {
                app.delete(path)
                    .add_header("authorization", h.clone())
                    .await
            }
            _ => app.post(path).add_header("authorization", h.clone()).await,
        };
        assert!(
            res.status_code() == 403 || res.status_code() == 404 || res.status_code() == 405,
            "{method} {path} returned {}; it must not reach housekeeping",
            res.status_code()
        );
    }

    assert_eq!(
        snapshot(&pool).await,
        before,
        "no method or path variation may mutate data for a non-admin"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn system_housekeeping_resists_parameter_and_body_injection(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "inject").await;
    seed_housekeeping_targets(&pool, &user.id).await;
    let before = snapshot(&pool).await;

    // The handler takes no parameters, but prove that supplying them changes
    // nothing and grants nothing.
    for query in [
        "?role_id=ops-admin",
        "?admin=true",
        "?permission=admin",
        "?username=probe_admin",
        "?user_id=admin1",
        "?override=true&skip_auth=true",
    ] {
        let res = app
            .post(format!("{HOUSEKEEPING}{query}").as_str())
            .add_header("authorization", user.auth_header())
            .await;
        assert_eq!(
            res.status_code(),
            403,
            "query {query} must not bypass: {}",
            res.text()
        );
    }

    // And a body asserting admin-ness is ignored, since the handler takes none.
    let res = app
        .post(HOUSEKEEPING)
        .add_header("authorization", user.auth_header())
        .json(&serde_json::json!({"role_id":"ops-admin","admin":true,"permission":"admin"}))
        .await;
    assert_eq!(
        res.status_code(),
        403,
        "body must not bypass: {}",
        res.text()
    );

    assert_eq!(snapshot(&pool).await, before);
}

/// The JWT carries `sub`, `username`, `token_type`, `tenant_id`, `token_family`.
/// None of them may confer administrative authority.
#[sqlx::test(migrations = "./migrations")]
async fn system_endpoints_ignore_privileged_looking_jwt_claims(pool: PgPool) {
    use firecrow_backend::services::auth::create_access_token;

    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "claims").await;
    seed_housekeeping_targets(&pool, &user.id).await;
    let before = snapshot(&pool).await;

    // username="admin" / token_type="admin" / tenant_id carrying the admin role.
    let uname = user.username.clone();
    for (username, token_type, tenant) in [
        ("admin", "access", "ops-admin"),
        ("root", "admin", "ops-admin"),
        (uname.as_str(), "admin", ""),
        (uname.as_str(), "access", "ops-admin"),
    ] {
        let token = create_access_token(&user.id, username, support::TEST_SECRET_KEY, tenant, 60)
            .expect("mint token")
            .0;

        let res = app
            .post(HOUSEKEEPING)
            .add_header("authorization", format!("Bearer {token}"))
            .await;
        assert_eq!(
            res.status_code(),
            403,
            "claims ({username}, {token_type}, {tenant}) must not grant admin"
        );

        let res = app
            .get(STATS)
            .add_header("authorization", format!("Bearer {token}"))
            .await;
        assert_eq!(res.status_code(), 403, "claims must not grant stats access");
    }

    assert_eq!(
        snapshot(&pool).await,
        before,
        "no token variant may mutate data"
    );
}

/// A token signed with the wrong key must not work, and neither must a token
/// whose subject is an administrator while being signed by an attacker.
#[sqlx::test(migrations = "./migrations")]
async fn system_endpoints_reject_forged_and_wrong_key_tokens(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let admin = support::seed_user(&pool, "forged_admin").await;
    support::grant_admin(&pool, &admin).await;

    // Correct subject, wrong signing key.
    let forged = firecrow_backend::services::auth::create_access_token(
        &admin.id,
        &admin.username,
        "attacker-controlled-key-that-is-long-enough-1234",
        "",
        60,
    )
    .expect("mint")
    .0;

    for res in [
        app.get(STATS)
            .add_header("authorization", format!("Bearer {forged}"))
            .await,
        app.post(HOUSEKEEPING)
            .add_header("authorization", format!("Bearer {forged}"))
            .await,
    ] {
        assert_eq!(
            res.status_code(),
            401,
            "a token signed with another key must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Scope: the other two /system routes must be untouched
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn system_status_and_metrics_keep_their_existing_access(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "scope").await;

    // Deliberately unchanged in Phase 8: /system/status reports only database
    // connectivity (the same fact the public /health endpoint reports), and
    // /system/metrics is a scrape endpoint that an external Prometheus cannot
    // authenticate as an administrator.
    for path in ["/api/v1/system/status", "/api/v1/system/metrics"] {
        let anon = app.get(path).await;
        assert_eq!(
            anon.status_code(),
            401,
            "{path} must still require authentication"
        );

        let authed = app
            .get(path)
            .add_header("authorization", user.auth_header())
            .await;
        assert_eq!(
            authed.status_code(),
            200,
            "{path} access for an ordinary authenticated user is unchanged by Phase 8"
        );
    }
}

/// Guards the fix at the source level: a future edit must not silently revert the
/// extractor on these two handlers.
#[test]
fn system_database_handlers_declare_adminuser() {
    let src = include_str!("../src/api/routes_system.rs");

    for handler in ["database_stats", "trigger_housekeeping"] {
        let start = src
            .find(&format!("pub async fn {handler}"))
            .unwrap_or_else(|| panic!("{handler} must exist"));
        // The signature ends at the first ") -> Result" after the parameters.
        let sig = &src[start..];
        let end = sig.find(") -> Result").expect("signature must terminate");
        assert!(
            sig[..end].contains("auth::AdminUser"),
            "{handler} must take AdminUser, not AuthenticatedUser (Phase 8)"
        );
        assert!(
            !sig[..end].contains("auth::AuthenticatedUser"),
            "{handler} must not take AuthenticatedUser"
        );
    }
}
