//! F3: exchange codes must be consumed atomically, exactly once.
//!
//! `verify_and_consume_exchange_code` previously ran SELECT-then-DELETE with
//! the DELETE outcome swallowed by `.ok()`, so two concurrent redemptions
//! could both succeed. These tests use the real PostgreSQL engine (the
//! concurrency guarantee is a database-snapshot property, not a mock-able
//! one) via `#[sqlx::test]`, which gives each test a migrated throwaway
//! database.

mod support;

use firecrow_backend::services::auth::{create_exchange_code, verify_and_consume_exchange_code};
use firecrow_backend::services::crypto::{crypto_manager, CryptoManager};
use sqlx::PgPool;
use std::sync::Arc;
use support::{SeededUser, TEST_ENCRYPTION_KEY, TEST_SECRET_KEY};

fn crypto() -> Arc<CryptoManager> {
    crypto_manager(TEST_SECRET_KEY, TEST_ENCRYPTION_KEY).expect("test crypto manager")
}

/// A synthetic access token; it round-trips through the test manager's
/// encryption and is never a real credential.
const SYNTHETIC_TOKEN: &str = "synthetic-access-token-not-a-real-credential";

async fn seed_code(pool: &PgPool, user: &SeededUser, ttl_seconds: i64) -> String {
    let crypto = crypto();
    let code = uuid::Uuid::new_v4().to_string();
    create_exchange_code(
        pool,
        &code,
        &user.id,
        &user.username,
        SYNTHETIC_TOKEN,
        ttl_seconds,
        &crypto,
    )
    .await
    .expect("seed exchange code");
    code
}

#[sqlx::test(migrations = "./migrations")]
async fn security_f3_valid_unexpired_code_redeems_exactly_once(pool: PgPool) {
    let user = support::seed_user(&pool, "f3valid").await;
    let crypto = crypto();
    let code = seed_code(&pool, &user, 120).await;

    let first = verify_and_consume_exchange_code(&pool, &code, &crypto)
        .await
        .expect("redeem must not error");
    let (user_id, username, token) = first.expect("a valid unexpired code must redeem");
    assert_eq!(user_id, user.id);
    assert_eq!(username, user.username);
    assert_eq!(
        token, SYNTHETIC_TOKEN,
        "the decrypted stored token must round-trip"
    );

    // Single-use: the second attempt finds nothing and does not error.
    let second = verify_and_consume_exchange_code(&pool, &code, &crypto)
        .await
        .expect("a consumed code is a clean miss, not an error");
    assert!(second.is_none(), "a consumed code must not redeem twice");

    // And the row is physically gone, not merely ignored.
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_exchange_codes WHERE code = $1")
        .bind(&code)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0, "the code row must be deleted on redemption");
}

#[sqlx::test(migrations = "./migrations")]
async fn security_f3_expired_code_is_rejected(pool: PgPool) {
    let user = support::seed_user(&pool, "f3exp").await;
    let crypto = crypto();
    // Negative TTL → expires_at in the past.
    let code = seed_code(&pool, &user, -10).await;

    let out = verify_and_consume_exchange_code(&pool, &code, &crypto)
        .await
        .expect("expired code must be a clean miss");
    assert!(out.is_none(), "an expired code must not redeem");
}

#[sqlx::test(migrations = "./migrations")]
async fn security_f3_unknown_code_is_rejected(pool: PgPool) {
    let crypto = crypto();
    let out = verify_and_consume_exchange_code(&pool, "definitely-not-a-code", &crypto)
        .await
        .expect("unknown code must be a clean miss");
    assert!(out.is_none(), "an unknown code must not redeem");
}

#[sqlx::test(migrations = "./migrations")]
async fn security_f3_concurrent_redeem_attempts_yield_exactly_one_success(pool: PgPool) {
    let user = support::seed_user(&pool, "f3conc").await;
    let crypto = crypto();
    let code = seed_code(&pool, &user, 120).await;

    // Eight simultaneous redemptions of one code, on separate pool
    // connections. The atomic DELETE guarantees exactly one gets the row.
    let attempts = (0..8).map(|_| verify_and_consume_exchange_code(&pool, &code, &crypto));
    let results = futures::future::join_all(attempts).await;
    let successes = results
        .into_iter()
        .map(|r| r.expect("redemption must not error"))
        .filter(Option::is_some)
        .count();
    assert_eq!(
        successes, 1,
        "exactly one concurrent redemption may consume the code"
    );

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auth_exchange_codes WHERE code = $1")
        .bind(&code)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(rows, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn security_f3_database_errors_propagate(pool: PgPool) {
    let user = support::seed_user(&pool, "f3err").await;
    let crypto = crypto();
    let code = seed_code(&pool, &user, 120).await;

    // Force the consumption statement itself to fail. A regression that
    // swallows database errors (the old `.ok()` on the DELETE) would turn
    // this into a silent `Ok(None)`/`Ok(Some)` instead of an Err.
    sqlx::query("DROP TABLE auth_exchange_codes")
        .execute(&pool)
        .await
        .expect("drop table");

    let res = verify_and_consume_exchange_code(&pool, &code, &crypto).await;
    assert!(
        res.is_err(),
        "a failed consumption must propagate the database error, got {res:?}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn security_f3_failed_exchange_endpoint_mints_no_session(pool: PgPool) {
    let app = support::test_app(pool).await;
    let res = app
        .post("/api/v1/auth/exchange")
        .json(&serde_json::json!({ "code": "definitely-not-a-code" }))
        .await;
    assert!(
        res.status_code() == 400 || res.status_code() == 401,
        "an invalid exchange must be rejected, got {}",
        res.status_code()
    );
    let set_cookies: Vec<String> = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(String::from)
        .collect();
    assert!(
        set_cookies.is_empty(),
        "a failed exchange must not mint a session cookie: {set_cookies:?}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn security_f3_successful_exchange_still_issues_a_session(pool: PgPool) {
    // Compatibility: the atomic rewrite must not break the happy path or the
    // cookie contract (HttpOnly + Secure + SameSite, per settings defaults).
    let user = support::seed_user(&pool, "f3ok").await;
    let code = seed_code(&pool, &user, 120).await;
    let app = support::test_app(pool).await;

    let res = app
        .post("/api/v1/auth/exchange")
        .json(&serde_json::json!({ "code": code }))
        .await;
    assert_eq!(
        res.status_code(),
        200,
        "exchange must succeed: {}",
        res.text()
    );

    let cookies: Vec<String> = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(String::from)
        .collect();
    let access = cookies
        .iter()
        .find(|c| c.starts_with("fc_access_token="))
        .expect("exchange must set the access cookie");
    assert!(
        access.contains("HttpOnly"),
        "access cookie must be HttpOnly: {access}"
    );
    assert!(
        access.contains("Secure"),
        "access cookie must be Secure: {access}"
    );
    assert!(
        access.contains("SameSite=Strict"),
        "default SameSite=Strict must be preserved: {access}"
    );
}
