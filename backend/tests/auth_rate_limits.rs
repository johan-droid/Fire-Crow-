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

/// FC-RELEASE-017 (review findings 1+2): each failed login records EXACTLY
/// one failure against the account key in the default topology (no trusted
/// proxy, no TRUST_DIRECT_PEER, no shared-ingress signal).
///
/// Why four attempts and not six: the credential routes carry an
/// unconditional 5/minute governor, so the 6th rapid attempt answers 429
/// before lockout logic runs. Four fits the burst — and it is exactly the
/// attempt where the old double-record defect bit (two rows per attempt
/// tripped `count >= 5` at the 4th password). A reintroduced duplicate record
/// fails here; the key-resolution decision itself is pinned by the
/// `lockout_key_tests` unit tests in `routes_auth.rs`, where the aliased and
/// shared-ingress topologies are representable.
#[sqlx::test(migrations = "./migrations")]
async fn four_failures_do_not_lock_before_the_documented_limit(pool: PgPool) {
    let app = support::test_app(pool.clone()).await;
    let user = support::seed_user(&pool, "lockout-count").await;
    let payload = serde_json::json!({ "username": user.username, "password": "Wrong-Password-1!" });

    for attempt in 1..=4 {
        let res = app.post("/api/v1/auth/login").json(&payload).await;
        let body = res.text();
        assert_eq!(res.status_code(), 401, "attempt {attempt} must be rejected");
        assert!(
            !body.to_lowercase().contains("locked"),
            "attempt {attempt} must be invalid-credentials, not locked: {body}"
        );
    }
}

/// FC-RELEASE-017 (independent review): the trusted-proxy `Some` path must be
/// live end to end, not just unit-tested. Calls `login()` directly with an
/// explicit `ConnectInfo` — the exact extractor production uses — and counts
/// failure rows: a Cloudflare peer with a visitor header must land TWO rows
/// under distinct keys (account + per-client IP); an untrusted peer lands
/// exactly ONE row (account key only, no shared bucket).
#[sqlx::test(migrations = "./migrations")]
async fn trusted_proxy_peer_records_a_distinct_ip_failure_row(pool: PgPool) {
    use axum::extract::{ConnectInfo, State};
    use axum_extra::extract::cookie::CookieJar;

    // Hermetic w.r.t. the operator signal: no other test uses it, and an
    // ambient value would change which keys this login records.
    std::env::remove_var("TRUST_DIRECT_PEER");

    let user = support::seed_user(&pool, "peer-aware").await;
    let state = firecrow_backend::app::build_state(support::test_settings(), pool.clone(), None)
        .await
        .expect("state builds");
    let payload = || {
        axum::Json(
            serde_json::json!({ "username": user.username, "password": "Wrong-Password-1!" }),
        )
    };

    // Cloudflare edge peer + visitor header: proven client identity.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "cf-connecting-ip",
        axum::http::HeaderValue::from_static("203.0.113.7"),
    );
    let cf_peer: std::net::SocketAddr = "104.16.0.1:443".parse().unwrap();
    let res = firecrow_backend::api::routes_auth::login(
        State(state),
        CookieJar::default(),
        headers,
        Some(ConnectInfo(cf_peer)),
        payload(),
    )
    .await;
    assert!(res.is_err(), "wrong password must fail");

    let (rows, distinct): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COUNT(DISTINCT key_hash) FROM login_failures")
            .fetch_one(&pool)
            .await
            .expect("count rows");
    assert_eq!(
        (rows, distinct),
        (2, 2),
        "trusted-proxy peer must record account + distinct IP key"
    );
}

/// Same direct call with an untrusted peer: exactly one row, so no shared
/// bucket exists that could become a global lockout.
#[sqlx::test(migrations = "./migrations")]
async fn untrusted_peer_records_only_the_account_key(pool: PgPool) {
    use axum::extract::{ConnectInfo, State};
    use axum_extra::extract::cookie::CookieJar;

    std::env::remove_var("TRUST_DIRECT_PEER");

    let user = support::seed_user(&pool, "peer-single").await;
    let state = firecrow_backend::app::build_state(support::test_settings(), pool.clone(), None)
        .await
        .expect("state builds");
    let unknown_lb: std::net::SocketAddr = "10.0.4.21:51234".parse().unwrap();
    let res = firecrow_backend::api::routes_auth::login(
        State(state),
        CookieJar::default(),
        axum::http::HeaderMap::new(),
        Some(ConnectInfo(unknown_lb)),
        axum::Json(
            serde_json::json!({ "username": user.username, "password": "Wrong-Password-1!" }),
        ),
    )
    .await;
    assert!(res.is_err(), "wrong password must fail");

    let (rows, distinct): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COUNT(DISTINCT key_hash) FROM login_failures")
            .fetch_one(&pool)
            .await
            .expect("count rows");
    assert_eq!(
        (rows, distinct),
        (1, 1),
        "unproven peer must record only the account key"
    );
}
