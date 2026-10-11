//! V1/V2 regression tests (offline): token purpose and session-family binding.
//!
//! Pure unit tests over the signed-claim layer: no database, no network, no
//! environment. The HTTP-level proof (401s, rotation, logout, SSE) lives in
//! `tests/session_revocation.rs`, which runs against a test database.

use firecrow_backend::services::auth::{
    create_access_token, create_refresh_token, require_token_type, validate_token, TokenType,
};

const SECRET: &str = "test-secret-key-at-least-32-chars-long-for-hmac-sha256";

#[test]
fn access_token_carries_access_purpose() {
    let (token, _jti) = create_access_token("user-1", "alice", SECRET, "tenant-1", "family-1", 60)
        .expect("mint access token");
    let data = validate_token(&token, SECRET).expect("token must verify");
    assert_eq!(data.claims.token_type, TokenType::Access);
    require_token_type(&data, TokenType::Access).expect("access purpose must pass");
}

#[test]
fn refresh_token_carries_refresh_purpose() {
    let (token, _jti) = create_refresh_token("user-1", "alice", SECRET, "tenant-1", "family-1")
        .expect("mint refresh token");
    let data = validate_token(&token, SECRET).expect("token must verify");
    assert_eq!(data.claims.token_type, TokenType::Refresh);
    require_token_type(&data, TokenType::Refresh).expect("refresh purpose must pass");
}

/// V1: a refresh token presented where an access token is required fails
/// closed. `token_type` is HMAC-signed, so this cannot be flipped without
/// the signing key — the middleware gate (`validate_access_token`) is this
/// check plus signature/expiry/revocation.
#[test]
fn refresh_token_is_rejected_for_access_purpose() {
    let (token, _jti) = create_refresh_token("user-1", "alice", SECRET, "tenant-1", "family-1")
        .expect("mint refresh token");
    let data = validate_token(&token, SECRET).expect("token must verify");
    let err = require_token_type(&data, TokenType::Access).expect_err("must reject");
    assert!(
        matches!(err, firecrow_backend::error::AppError::InvalidToken),
        "wrong purpose must be InvalidToken (401), got {err:?}"
    );
}

/// V1: an access token presented to the refresh endpoint fails closed.
#[test]
fn access_token_is_rejected_for_refresh_purpose() {
    let (token, _jti) = create_access_token("user-1", "alice", SECRET, "tenant-1", "family-1", 60)
        .expect("mint access token");
    let data = validate_token(&token, SECRET).expect("token must verify");
    let err = require_token_type(&data, TokenType::Refresh).expect_err("must reject");
    assert!(
        matches!(err, firecrow_backend::error::AppError::InvalidToken),
        "wrong purpose must be InvalidToken (401), got {err:?}"
    );
}

/// V2: a login session mints both tokens under one shared family with
/// distinct identifiers. Revoking the family therefore revokes the session,
/// not just one token. This mirrors what `login`/`exchange_token`/
/// `github_callback`/rotation now do; the HTTP tests prove the server does it.
#[test]
fn login_pair_shares_one_session_family() {
    let family = uuid::Uuid::new_v4().to_string();
    let (access, access_jti) =
        create_access_token("user-1", "alice", SECRET, "tenant-1", &family, 60)
            .expect("mint access token");
    let (refresh, refresh_jti) =
        create_refresh_token("user-1", "alice", SECRET, "tenant-1", &family)
            .expect("mint refresh token");
    let access_claims = validate_token(&access, SECRET)
        .expect("access verifies")
        .claims;
    let refresh_claims = validate_token(&refresh, SECRET)
        .expect("refresh verifies")
        .claims;
    assert_eq!(access_claims.token_family, family);
    assert_eq!(refresh_claims.token_family, family);
    assert_ne!(
        access_jti, refresh_jti,
        "tokens in one family must still have distinct jtis"
    );
}

#[test]
fn malformed_and_tampered_tokens_are_rejected() {
    assert!(
        validate_token("not-a-jwt", SECRET).is_err(),
        "garbage must not verify"
    );
    assert!(validate_token("", SECRET).is_err(), "empty must not verify");
    let (token, _jti) = create_access_token("user-1", "alice", SECRET, "tenant-1", "family-1", 60)
        .expect("mint access token");
    let mut tampered = token.clone();
    let last = tampered.pop().expect("non-empty");
    tampered.push(if last == 'a' { 'b' } else { 'a' });
    assert!(
        validate_token(&tampered, SECRET).is_err(),
        "a flipped signature byte must not verify"
    );
    assert!(
        validate_token(&token, "wrong-key-that-is-also-long-enough-12345678").is_err(),
        "wrong signing key must not verify"
    );
}

#[test]
fn expired_tokens_are_rejected() {
    let (token, _jti) = create_access_token("user-1", "alice", SECRET, "tenant-1", "family-1", -60)
        .expect("mint still succeeds; expiry is enforced at validation");
    let err = validate_token(&token, SECRET).expect_err("expired must not verify");
    assert!(
        matches!(err, firecrow_backend::error::AppError::TokenExpired),
        "expired must be TokenExpired (401), got {err:?}"
    );
}
