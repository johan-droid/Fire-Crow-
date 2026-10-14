use crate::error::{AppError, Result};
use crate::models::AuthExchangeCode;
use crate::services::crypto::CryptoManager;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use redis::aio::MultiplexedConnection;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String, // user_id
    pub username: String,
    pub exp: i64,
    pub nbf: i64,
    pub iat: i64,
    pub jti: String,
    pub token_family: String,
    pub token_type: TokenType,
    // NEW: tenant_id for multi-tenancy isolation
    pub tenant_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    pub state: String,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash: {e}")))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

pub async fn check_login_lockout(
    pool: &sqlx::PgPool,
    key: &str,
    window_minutes: i64,
    limit: i32,
) -> Result<bool> {
    let window_start = (Utc::now() - Duration::minutes(window_minutes)).naive_utc();
    // HIGH-01: the key MUST be hashed identically to what record_login_failure stores,
    // otherwise the lockout check never matches and brute-force protection is disabled.
    let key_hash = format!("{:x}", sha2::Sha256::digest(key.as_bytes()));
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM login_failures WHERE key_hash = $1 AND attempted_at > $2",
    )
    .bind(key_hash)
    .bind(window_start)
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(count >= limit as i64)
}

pub async fn record_login_failure(pool: &sqlx::PgPool, key: &str) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let key_hash = format!("{:x}", sha2::Sha256::digest(key.as_bytes()));
    sqlx::query("INSERT INTO login_failures (id, key_hash, attempted_at) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(key_hash)
        .bind(Utc::now().naive_utc())
        .execute(pool)
        .await
        .map_err(AppError::Database)?;
    Ok(())
}

pub async fn clear_login_failures(pool: &sqlx::PgPool, key: &str) -> Result<()> {
    let key_hash = format!("{:x}", sha2::Sha256::digest(key.as_bytes()));
    sqlx::query("DELETE FROM login_failures WHERE key_hash = $1")
        .bind(key_hash)
        .execute(pool)
        .await
        .map_err(AppError::Database)?;
    Ok(())
}

pub fn build_jwt_keys(secret: &str) -> Result<(EncodingKey, DecodingKey)> {
    Ok((
        EncodingKey::from_secret(secret.as_bytes()),
        DecodingKey::from_secret(secret.as_bytes()),
    ))
}

/// Refresh-token lifetime: revocation records for a session family must
/// outlive any refresh token the family can still hold (V2 logout hardening).
pub const REFRESH_TOKEN_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
/// Small margin so a revocation record never expires before the token it
/// covers when clocks disagree by seconds.
const REVOCATION_TTL_MARGIN_SECONDS: i64 = 3600;

pub fn create_access_token(
    user_id: &str,
    username: &str,
    secret: &str,
    tenant_id: &str,
    token_family: &str,
    expire_minutes: i64,
) -> Result<(String, String)> {
    let (encoding_key, _) = build_jwt_keys(secret)?;
    let now = Utc::now();
    let jti = Uuid::new_v4().to_string();
    let claims = TokenClaims {
        sub: user_id.into(),
        username: username.into(),
        exp: (now + Duration::minutes(expire_minutes)).timestamp(),
        nbf: now.timestamp() - 5,
        iat: now.timestamp(),
        jti: jti.clone(),
        token_family: token_family.to_string(),
        token_type: TokenType::Access,
        tenant_id: tenant_id.into(),
    };
    let token = jsonwebtoken::encode(&Header::default(), &claims, &encoding_key)
        .map_err(|e| AppError::Internal(format!("JWT encode error: {e}")))?;
    Ok((token, jti))
}

pub fn create_refresh_token(
    user_id: &str,
    username: &str,
    secret: &str,
    tenant_id: &str,
    token_family: &str,
) -> Result<(String, String)> {
    let (encoding_key, _) = build_jwt_keys(secret)?;
    let now = Utc::now();
    let jti = Uuid::new_v4().to_string();
    let claims = TokenClaims {
        sub: user_id.into(),
        username: username.into(),
        // Phase E (H4): Reduced from 30 days to 7 days with continuous rotation on every refresh.
        exp: (now + Duration::days(7)).timestamp(),
        nbf: now.timestamp() - 5,
        iat: now.timestamp(),
        jti: jti.clone(),
        token_family: token_family.into(),
        token_type: TokenType::Refresh,
        tenant_id: tenant_id.into(),
    };
    let token = jsonwebtoken::encode(&Header::default(), &claims, &encoding_key)
        .map_err(|e| AppError::Internal(format!("JWT encode error: {e}")))?;
    Ok((token, jti))
}

pub fn validate_token(token: &str, secret: &str) -> Result<TokenData<TokenClaims>> {
    let (_, decoding_key) = build_jwt_keys(secret)?;
    let mut validation = Validation::default();
    validation.validate_exp = true;
    validation.validate_nbf = true;
    let data = jsonwebtoken::decode::<TokenClaims>(token, &decoding_key, &validation).map_err(
        |e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
            _ => AppError::InvalidToken,
        },
    )?;
    Ok(data)
}

pub async fn validate_token_with_anti_replay(
    token: &str,
    secret: &str,
    redis: Option<&MultiplexedConnection>,
    pool: &sqlx::PgPool,
) -> Result<TokenData<TokenClaims>> {
    let data = validate_token(token, secret)?;
    let revoked = if let Some(r) = redis {
        let mut conn = r.clone();
        let mut is_revoked: bool = redis::AsyncCommands::exists(
            &mut conn,
            format!("firecrow:revoked_jti:{}", data.claims.jti),
        )
        .await
        .unwrap_or(false);
        if !is_revoked {
            is_revoked = redis::AsyncCommands::exists(
                &mut conn,
                format!("firecrow:revoked_family:{}", data.claims.token_family),
            )
            .await
            .unwrap_or(false);
        }
        is_revoked
    } else {
        // HIGH-02: without Redis, fall back to the database revocation table so
        // logout / rotation still take effect immediately.
        is_revoked_in_db(pool, &data.claims.jti, &data.claims.token_family).await?
    };
    if revoked {
        return Err(AppError::TokenRevoked);
    }
    Ok(data)
}

async fn is_revoked_in_db(pool: &sqlx::PgPool, jti: &str, token_family: &str) -> Result<bool> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM token_revocations WHERE (jti = $1 OR token_family = $2) AND expires_at > NOW()")
        .bind(jti)
        .bind(token_family)
        .fetch_one(pool)
        .await
        .map_err(AppError::Database)?;
    Ok(count > 0)
}

/// V1: enforce the signed token-purpose claim. Missing, unknown, or
/// mismatched purposes fail closed. `TokenType` is part of the HMAC-signed
/// claims, so an attacker cannot flip it without the signing key.
pub fn require_token_type(data: &TokenData<TokenClaims>, expected: TokenType) -> Result<()> {
    if data.claims.token_type != expected {
        return Err(AppError::InvalidToken);
    }
    Ok(())
}

/// V1: the single gate for REST and SSE bearer authentication. Signature,
/// expiry, revocation, *and* purpose (`Access`) are all enforced, so a
/// refresh token presented as a bearer credential is rejected with 401.
pub async fn validate_access_token(
    token: &str,
    secret: &str,
    redis: Option<&MultiplexedConnection>,
    pool: &sqlx::PgPool,
) -> Result<TokenData<TokenClaims>> {
    let data = validate_token_with_anti_replay(token, secret, redis, pool).await?;
    require_token_type(&data, TokenType::Access)?;
    Ok(data)
}

/// Atomically consume a refresh-token `jti` so concurrent presentations of
/// the same token cannot both succeed (V2 rotation single-flight).
///
/// Returns `true` when this call is the first consumer. Redis uses a single
/// `SET .. NX EX` round-trip; the database path relies on the unique `jti`
/// constraint with `ON CONFLICT DO NOTHING` and inspects `rows_affected`.
async fn consume_jti_once(
    redis: Option<&MultiplexedConnection>,
    pool: &sqlx::PgPool,
    jti: &str,
    token_family: &str,
    ttl_seconds: i64,
) -> Result<bool> {
    if let Some(r) = redis {
        let mut conn = r.clone();
        let key = format!("firecrow:revoked_jti:{jti}");
        let set: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("EX")
            .arg(ttl_seconds)
            .arg("NX")
            .query_async(&mut conn)
            .await
            .map_err(|e| AppError::RedisError(e.to_string()))?;
        Ok(set.as_deref() == Some("OK"))
    } else {
        let id = Uuid::new_v4().to_string();
        let expires_at = Utc::now().naive_utc() + Duration::seconds(ttl_seconds);
        let n = sqlx::query("INSERT INTO token_revocations (id, jti, token_family, expires_at) VALUES ($1, $2, $3, $4) ON CONFLICT (jti) DO NOTHING")
            .bind(id)
            .bind(jti)
            .bind(token_family)
            .bind(expires_at)
            .execute(pool)
            .await
            .map_err(AppError::Database)?
            .rows_affected();
        Ok(n == 1)
    }
}

async fn is_family_revoked(
    redis: Option<&MultiplexedConnection>,
    pool: &sqlx::PgPool,
    token_family: &str,
) -> Result<bool> {
    if let Some(r) = redis {
        let mut conn = r.clone();
        let exists: bool = redis::AsyncCommands::exists(
            &mut conn,
            format!("firecrow:revoked_family:{token_family}"),
        )
        .await
        .unwrap_or(false);
        if exists {
            return Ok(true);
        }
    }
    // The database is always consulted: a family revoked while Redis was
    // down (or via the DB fallback path) must stay dead after failover.
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM token_revocations WHERE token_family = $1 AND expires_at > NOW()",
    )
    .bind(token_family)
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(count > 0)
}

/// V1+V2: the single gate for the refresh endpoint. Enforces signature,
/// expiry, purpose (`Refresh`), single-use rotation, and session liveness.
///
/// Ordering is load-bearing. The family-liveness check runs *before* the
/// atomic consume: two tabs refreshing one session concurrently must yield
/// exactly one successor, not zero. (Burning the family on a lost consume
/// race would kill the legitimate winner too, turning a routine double
/// refresh into a logout.) Replays still fail closed — a rotated family is
/// already revoked by the rotation itself, and a consumed `jti` can never be
/// consumed twice — but a lost race costs only the loser, never the session.
pub async fn consume_refresh_token(
    token: &str,
    secret: &str,
    redis: Option<&MultiplexedConnection>,
    pool: &sqlx::PgPool,
) -> Result<TokenData<TokenClaims>> {
    let data = validate_token(token, secret)?;
    require_token_type(&data, TokenType::Refresh)?;
    if is_family_revoked(redis, pool, &data.claims.token_family).await? {
        return Err(AppError::TokenRevoked);
    }
    let now = Utc::now().timestamp();
    let ttl_seconds = (data.claims.exp - now).clamp(
        60,
        REFRESH_TOKEN_TTL_SECONDS + REVOCATION_TTL_MARGIN_SECONDS,
    );
    let first = consume_jti_once(
        redis,
        pool,
        &data.claims.jti,
        &data.claims.token_family,
        ttl_seconds,
    )
    .await?;
    if !first {
        return Err(AppError::TokenRevoked);
    }
    Ok(data)
}

pub async fn revoke_token_jti(
    redis: &MultiplexedConnection,
    jti: &str,
    ttl_seconds: i64,
) -> Result<()> {
    let mut conn = redis.clone();
    let _: () = conn
        .set_ex(
            format!("firecrow:revoked_jti:{jti}"),
            "1",
            ttl_seconds as u64,
        )
        .await
        .map_err(|e| AppError::RedisError(e.to_string()))?;
    Ok(())
}

pub async fn revoke_token_family(
    redis: &MultiplexedConnection,
    token_family: &str,
    ttl_seconds: i64,
) -> Result<()> {
    let mut conn = redis.clone();
    let _: () = conn
        .set_ex(
            format!("firecrow:revoked_family:{token_family}"),
            "1",
            ttl_seconds as u64,
        )
        .await
        .map_err(|e| AppError::RedisError(e.to_string()))?;
    Ok(())
}

/// Database-backed token revocation used whenever Redis is unavailable.
pub async fn revoke_token_in_db(
    pool: &sqlx::PgPool,
    jti: &str,
    token_family: &str,
    ttl_seconds: i64,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let expires_at = chrono::Utc::now().naive_utc() + chrono::Duration::seconds(ttl_seconds);
    sqlx::query("INSERT INTO token_revocations (id, jti, token_family, expires_at) VALUES ($1, $2, $3, $4) ON CONFLICT (jti) DO NOTHING")
        .bind(id)
        .bind(jti)
        .bind(token_family)
        .bind(expires_at)
        .execute(pool)
        .await
        .map_err(AppError::Database)?;
    Ok(())
}

pub fn create_oauth_state() -> String {
    Uuid::new_v4().to_string()
}

pub async fn verify_and_consume_exchange_code(
    pool: &sqlx::PgPool,
    code: &str,
    crypto: &Arc<CryptoManager>,
) -> Result<Option<(String, String, String)>> {
    // F3: atomic single-use consumption. The previous SELECT-then-DELETE had
    // two defects: (1) two concurrent redemptions could both read the row
    // before either deleted it, minting two sessions from one code; (2) the
    // DELETE's outcome was swallowed with `.ok()`, so a failed delete still
    // yielded a session and the code stayed redeemable. `DELETE ... WHERE
    // ... RETURNING` is a single statement under PostgreSQL's snapshot
    // semantics: exactly one concurrent caller gets the row, unexpired codes
    // only, and a database error propagates instead of being ignored.
    //
    // `id` is included because the active `models::AuthExchangeCode`
    // (models/user.rs — the one `models::mod` re-exports) carries
    // `id: Option<String>`; FromRow requires every field to be present.
    let record = sqlx::query_as::<_, AuthExchangeCode>(
        "DELETE FROM auth_exchange_codes
         WHERE code = $1 AND expires_at > NOW()
         RETURNING id, code, user_id, username, access_token, created_at, expires_at",
    )
    .bind(code)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;

    let Some(record) = record else {
        return Ok(None);
    };

    // The stored access token is encrypted; decrypt before handing it back.
    // A decryption failure happens after the code is consumed — the code is
    // not reusable, and the error carries no token material.
    let decrypted = crypto
        .decrypt_secret(&record.access_token)
        .map_err(|e| AppError::Internal(format!("Token decryption failed: {e}")))?;
    Ok(Some((record.user_id, record.username, decrypted)))
}

pub async fn create_exchange_code(
    pool: &sqlx::PgPool,
    code: &str,
    user_id: &str,
    username: &str,
    access_token: &str,
    ttl_seconds: i64,
    crypto: &Arc<CryptoManager>,
) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().naive_utc();
    let expires_at = now + chrono::Duration::seconds(ttl_seconds);

    // Encrypt the access token before storing
    let encrypted_token = crypto
        .encrypt_secret(access_token)
        .map_err(|e| AppError::Internal(format!("Token encryption failed: {}", e)))?;

    // NOTE: schema column is `access_token` (stores the encrypted blob).
    sqlx::query("INSERT INTO auth_exchange_codes (id, code, user_id, username, access_token, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(id)
        .bind(code)
        .bind(user_id)
        .bind(username)
        .bind(encrypted_token)
        .bind(now)
        .bind(expires_at)
        .execute(pool).await.map_err(AppError::Database)?;
    Ok(())
}

pub fn verify_oauth_state(state: &str, stored: &str) -> bool {
    use subtle::ConstantTimeEq;
    state.as_bytes().ct_eq(stored.as_bytes()).unwrap_u8() == 1
}

pub fn encrypt_provider_token(crypto: &Arc<CryptoManager>, token: &str) -> Result<String> {
    crypto
        .encrypt_secret(token)
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub fn decrypt_provider_token(crypto: &Arc<CryptoManager>, token: &str) -> Result<String> {
    crypto
        .decrypt_secret(token)
        .map_err(|e| AppError::Internal(e.to_string()))
}
