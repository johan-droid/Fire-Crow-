//! /auth rate-limit buckets: a successful login must not be failed by its own
//! follow-up.
//!
//! The SPA follows a successful POST /auth/login with an immediate
//! GET /auth/me. Both endpoints used to share one 5/minute per-IP bucket for
//! the whole `/auth` nest, so after a few requests that follow-up could be
//! rejected with 429 while the session cookie was already valid — the UI then
//! reported a login failure for a login that had succeeded.
//!
//! Contract now:
//! - credential routes (login/register/logout/exchange/refresh/…) keep the
//!   strict 5/minute brute-force ceiling;
//! - the read-only session checks (me/session/activities) have their own
//!   30/minute bucket, so six rapid reads are answered with 401, not 429.

mod support;

use sqlx::PgPool;

/// Six rapid unauthenticated session reads must be answered as
/// unauthenticated (401), never throttled (429): they no longer share a
/// bucket with login.
#[sqlx::test(migrations = "./migrations")]
async fn auth_me_reads_are_not_throttled_by_the_login_bucket(pool: PgPool) {
    let app = support::test_app_rate_limited(pool).await;

    for read in 1..=6 {
        let res = app.get("/api/v1/auth/me").await;
        assert_eq!(
            res.status_code(),
            401,
            "session read {read} must be rejected as unauthenticated, not throttled: {}",
            res.text()
        );
    }
}

/// The split must not weaken brute-force protection: the sixth rapid login
/// attempt from one IP still hits the 5/minute credential ceiling.
#[sqlx::test(migrations = "./migrations")]
async fn login_keeps_the_strict_five_per_minute_ceiling(pool: PgPool) {
    let app = support::test_app_rate_limited(pool).await;
    let payload = serde_json::json!({ "username": "nobody", "password": "wrong-password" });

    let mut limited = 0;
    for attempt in 1..=6 {
        let res = app.post("/api/v1/auth/login").json(&payload).await;
        if res.status_code() == 429 {
            limited += 1;
        } else {
            assert_eq!(
                res.status_code(),
                401,
                "attempt {attempt} must be rejected as invalid credentials, got: {}",
                res.text()
            );
        }
    }
    assert!(
        limited > 0,
        "the sixth rapid login attempt must hit the 5/minute credential ceiling"
    );
}
