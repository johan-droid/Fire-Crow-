//! F4: CSRF origin policy for cookie-authenticated mutations.
//!
//! Documents and enforces the policy written in `middleware/csrf.rs`:
//! an allowed Origin passes, a disallowed Origin is 403, a cookie-bearing
//! mutation without an Origin is 403, and cookie-less callers (bearer-token
//! clients, health probes) are unaffected. Read-only methods stay exempt.

mod support;

use axum_test::TestServer;
use firecrow_backend::app::{build_app, build_state};
use firecrow_backend::config::Settings;
use firecrow_backend::state::AppState;
use sqlx::PgPool;
use std::sync::Arc;

const ALLOWED_ORIGIN: &str = "https://app.firecrow.test";

async fn csrf_app(pool: PgPool) -> (TestServer, Arc<AppState>) {
    let settings = Settings {
        csrf_enabled: true,
        ..support::test_settings()
    };
    let state = build_state(settings, pool, None)
        .await
        .expect("state must build");
    let app = TestServer::new(build_app(state.clone(), false)).expect("test server");
    (app, state)
}

/// An allowed Origin lets the mutation reach the handler (its own validation
/// answers 400 for the empty body — not the CSRF gate's 403).
#[sqlx::test(migrations = "./migrations")]
async fn security_f4_allowed_origin_mutation_passes_the_csrf_gate(pool: PgPool) {
    let (app, _state) = csrf_app(pool).await;
    let res = app
        .post("/api/v1/auth/exchange")
        .add_header("origin", ALLOWED_ORIGIN)
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(
        res.status_code(),
        400,
        "an allowed Origin must reach the handler"
    );
}

/// A disallowed Origin on a cookie-capable mutation is refused outright.
#[sqlx::test(migrations = "./migrations")]
async fn security_f4_disallowed_origin_mutation_is_rejected(pool: PgPool) {
    let (app, _state) = csrf_app(pool).await;
    let res = app
        .post("/api/v1/auth/exchange")
        .add_header("origin", "https://evil.example")
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(res.status_code(), 403, "a foreign Origin must be refused");
}

/// `Origin: null` (sandboxed iframe / redirect) is not an allowed origin.
#[sqlx::test(migrations = "./migrations")]
async fn security_f4_null_origin_mutation_is_rejected(pool: PgPool) {
    let (app, _state) = csrf_app(pool).await;
    let res = app
        .post("/api/v1/auth/exchange")
        .add_header("origin", "null")
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(res.status_code(), 403);
}

/// A mutation carrying the auth cookie but no Origin is a non-browser client
/// forging a browser-shaped request: refused.
#[sqlx::test(migrations = "./migrations")]
async fn security_f4_cookie_bearing_mutation_without_origin_is_rejected(pool: PgPool) {
    let (app, state) = csrf_app(pool).await;
    let name = state.settings().auth_cookie_name.clone();
    let res = app
        .post("/api/v1/auth/exchange")
        .add_header("cookie", format!("{name}=forged-garbage-token"))
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(
        res.status_code(),
        403,
        "a cookie-authenticated mutation without Origin must be refused"
    );
}

/// The refresh cookie counts as an auth cookie for the same reason.
#[sqlx::test(migrations = "./migrations")]
async fn security_f4_refresh_cookie_mutation_without_origin_is_rejected(pool: PgPool) {
    let (app, state) = csrf_app(pool).await;
    let name = state.settings().auth_cookie_name.clone();
    let res = app
        .post("/api/v1/auth/refresh")
        .add_header("cookie", format!("{name}_refresh=forged-garbage-token"))
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(res.status_code(), 403);
}

/// Cookie-less callers without an Origin are not a CSRF vector and keep
/// working: a cross-site page cannot attach an `Authorization` header.
#[sqlx::test(migrations = "./migrations")]
async fn security_f4_cookieless_mutation_without_origin_passes(pool: PgPool) {
    let (app, _state) = csrf_app(pool).await;
    for headers in [None, Some(("authorization", "Bearer forged-garbage"))] {
        let mut req = app.post("/api/v1/auth/exchange");
        if let Some((k, v)) = headers {
            req = req.add_header(k, v);
        }
        let res = req.json(&serde_json::json!({})).await;
        assert_eq!(
            res.status_code(),
            400,
            "a cookie-less caller must reach the handler"
        );
    }
    // Non-auth cookies are not session credentials and do not trigger the rule.
    let res = app
        .post("/api/v1/auth/exchange")
        .add_header("cookie", "theme=dark")
        .json(&serde_json::json!({}))
        .await;
    assert_eq!(res.status_code(), 400);
}

/// Read-only traffic (health probe, OAuth callback) is exempt regardless of
/// Origin — CSRF applies to state changes only.
#[sqlx::test(migrations = "./migrations")]
async fn security_f4_read_only_requests_ignore_the_origin_policy(pool: PgPool) {
    let (app, _state) = csrf_app(pool).await;
    let res = app
        .get("/health")
        .add_header("origin", "https://evil.example")
        .await;
    assert_eq!(res.status_code(), 200, "/health must stay reachable");
}
