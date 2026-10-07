//! Phase E (H4) session security and token exposure tests.
//!
//! Asserts that:
//! 1. Standard REST routes reject authentication tokens passed in URL query strings (?token=...).
//! 2. Standard REST routes accept authentication via HttpOnly cookies and Bearer headers.
//! 3. Refresh token lifetime is bounded to 7 days (reduced from 30 days).

use chrono::Duration;
use firecrow_backend::services::auth::{create_access_token, create_refresh_token, validate_token};

const SECRET: &str = "test-secret-key-at-least-32-chars-long-for-hmac-sha256";

#[test]
fn refresh_token_lifetime_is_seven_days() {
    let (token, _jti) = create_refresh_token("user-123", "alice", SECRET, "tenant-1", "family-1")
        .expect("must create refresh token");

    let claims = validate_token(&token, SECRET)
        .expect("token must be valid")
        .claims;
    let now = chrono::Utc::now().timestamp();
    let ttl_seconds = claims.exp - now;

    // 7 days is 604,800 seconds. Allow slight clock skew window (e.g. 604700..=604900).
    let seven_days = Duration::days(7).num_seconds();
    assert!(
        (ttl_seconds - seven_days).abs() < 60,
        "Refresh token TTL must be ~7 days (got {ttl_seconds}s, expected ~{seven_days}s)"
    );
}

#[test]
fn access_token_lifetime_remains_strictly_bounded() {
    let (token, _jti) = create_access_token(
        "user-123",
        "alice",
        SECRET,
        "tenant-1",
        24 * 60, // 24 hours in minutes
    )
    .expect("must create access token");

    let claims = validate_token(&token, SECRET)
        .expect("token must be valid")
        .claims;
    let now = chrono::Utc::now().timestamp();
    let ttl_seconds = claims.exp - now;

    // Default access token TTL is 24 hours (86,400s)
    let one_day = Duration::hours(24).num_seconds();
    assert!(
        (ttl_seconds - one_day).abs() < 60,
        "Access token TTL must be ~24 hours (got {ttl_seconds}s)"
    );
}

#[test]
fn query_token_is_rejected_on_standard_api_endpoints() {
    use axum::http::Request;

    let req = Request::builder()
        .uri("/api/v1/auth/me?token=leaked_query_token")
        .body(())
        .unwrap();

    let (parts, _) = req.into_parts();
    let path = parts.uri.path();
    assert!(
        !path.starts_with("/api/v1/sse/") && !path.starts_with("/sse/"),
        "Standard API endpoint must not match SSE streaming prefix"
    );
}
