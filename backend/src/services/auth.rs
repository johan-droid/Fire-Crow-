use crate::error::{AppError, Result};
use crate::models::AuthExchangeCode;
use crate::services::crypto::CryptoManager;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
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
    pub sub: String,                 // user_id
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
pub enum TokenType { Access, Refresh }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    pub state: String,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash: {e}")))?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
}

pub fn password_needs_rehash(_hash: &str) -> bool { false }

pub async fn check_login_lockout(pool: &sqlx::PgPool, key: &str, window_minutes: i64, limit: i32) -> Result<bool> {
    let window_start = (Utc::now() - Duration::minutes(window_minutes)).naive_utc();
    // HIGH-01: the key MUST be hashed identically to what record_login_failure stores,
    // otherwise the lockout check never matches and brute-force protection is disabled.
    let key_hash = format!("{:x}", sha2::Sha256::digest(key.as_bytes()));
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM login_failures WHERE key_hash = $1 AND attempted_at > $2")
        .bind(key_hash).bind(window_start).fetch_one(pool).await.map_err(AppError::Database)?;
    Ok(count >= limit as i64)
}

pub async fn record_login_failure(pool: &sqlx::PgPool, key: &str) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let key_hash = format!("{:x}", sha2::Sha256::digest(key.as_bytes()));
    sqlx::query("INSERT INTO login_failures (id, key_hash, attempted_at) VALUES ($1, $2, $3)")
        .bind(id).bind(key_hash).bind(Utc::now().naive_utc())
        .execute(pool).await.map_err(AppError::Database)?;
    Ok(())
}

pub async fn clear_login_failures(pool: &sqlx::PgPool, key: &str) -> Result<()> {
    let key_hash = format!("{:x}", sha2::Sha256::digest(key.as_bytes()));
    sqlx::query("DELETE FROM login_failures WHERE key_hash = $1")
        .bind(key_hash)
        .execute(pool).await.map_err(AppError::Database)?;
    Ok(())
}

pub fn build_jwt_keys(secret: &str) -> Result<(EncodingKey, DecodingKey)> {
    Ok((EncodingKey::from_secret(secret.as_bytes()), DecodingKey::from_secret(secret.as_bytes())))
}

pub fn create_access_token(user_id: &str, username: &str, secret: &str, tenant_id: &str, expire_minutes: i64) -> Result<(String, String)> {
    let (encoding_key, _) = build_jwt_keys(secret)?;
    let now = Utc::now();
    let token_family = Uuid::new_v4().to_string();
    let jti = Uuid::new_v4().to_string();
    let claims = TokenClaims {
        sub: user_id.into(),
        username: username.into(),
        exp: (now + Duration::minutes(expire_minutes)).timestamp(),
        nbf: now.timestamp() - 5, iat: now.timestamp(),
        jti: jti.clone(),
        token_family: token_family.clone(),
        token_type: TokenType::Access,
        tenant_id: tenant_id.into(),
    };
    let token = jsonwebtoken::encode(&Header::default(), &claims, &encoding_key)
        .map_err(|e| AppError::Internal(format!("JWT encode error: {e}")))?;
    Ok((token, jti))
}

pub fn create_refresh_token(user_id: &str, username: &str, secret: &str, tenant_id: &str, token_family: &str) -> Result<(String, String)> {
    let (encoding_key, _) = build_jwt_keys(secret)?;
    let now = Utc::now();
    let jti = Uuid::new_v4().to_string();
    let claims = TokenClaims {
        sub: user_id.into(),
        username: username.into(),
        exp: (now + Duration::days(30)).timestamp(),
        nbf: now.timestamp() - 5, iat: now.timestamp(),
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
    let data = jsonwebtoken::decode::<TokenClaims>(token, &decoding_key, &validation)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
            _ => AppError::InvalidToken,
        })?;
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
        let mut is_revoked: bool = redis::AsyncCommands::exists(&mut conn, format!("firecrow:revoked_jti:{}", data.claims.jti))
            .await
            .unwrap_or(false);
        if !is_revoked {
            is_revoked = redis::AsyncCommands::exists(&mut conn, format!("firecrow:revoked_family:{}", data.claims.token_family))
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

pub async fn revoke_token_jti(redis: &MultiplexedConnection, jti: &str, ttl_seconds: i64) -> Result<()> {
    let mut conn = redis.clone();
    let _: () = conn.set_ex(format!("firecrow:revoked_jti:{jti}"), "1", ttl_seconds as u64)
        .await.map_err(|e| AppError::RedisError(e.to_string()))?;
    Ok(())
}

pub async fn revoke_token_family(redis: &MultiplexedConnection, token_family: &str, ttl_seconds: i64) -> Result<()> {
    let mut conn = redis.clone();
    let _: () = conn.set_ex(format!("firecrow:revoked_family:{token_family}"), "1", ttl_seconds as u64)
        .await.map_err(|e| AppError::RedisError(e.to_string()))?;
    Ok(())
}

/// Database-backed token revocation used whenever Redis is unavailable.
pub async fn revoke_token_in_db(pool: &sqlx::PgPool, jti: &str, token_family: &str, ttl_seconds: i64) -> Result<()> {
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

pub fn create_oauth_state() -> String { Uuid::new_v4().to_string() }

pub async fn verify_and_consume_exchange_code(pool: &sqlx::PgPool, code: &str, crypto: &Arc<CryptoManager>) -> Result<Option<(String, String, String)>> {
    let record = sqlx::query_as::<_, AuthExchangeCode>("SELECT * FROM auth_exchange_codes WHERE code = $1 AND expires_at > NOW()")
        .bind(code)
        .fetch_optional(pool).await.map_err(AppError::Database)?;
    if let Some(record) = record {
        sqlx::query("DELETE FROM auth_exchange_codes WHERE code = $1")
            .bind(code)
            .execute(pool).await.ok();
        // The stored access token is encrypted; decrypt before handing it back.
        let decrypted = crypto.decrypt_secret(&record.access_token)
            .map_err(|e| AppError::Internal(format!("Token decryption failed: {e}")))?;
        Ok(Some((record.user_id, record.username, decrypted)))
    } else { Ok(None) }
}

pub async fn create_exchange_code(pool: &sqlx::PgPool, code: &str, user_id: &str, username: &str, access_token: &str, ttl_seconds: i64, crypto: &Arc<CryptoManager>) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().naive_utc();
    let expires_at = now + chrono::Duration::seconds(ttl_seconds);

    // Encrypt the access token before storing
    let encrypted_token = crypto.encrypt_secret(access_token)
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
    crypto.encrypt_secret(token).map_err(|e| AppError::Internal(e.to_string()))
}

pub fn decrypt_provider_token(crypto: &Arc<CryptoManager>, token: &str) -> Result<String> {
    crypto.decrypt_secret(token).map_err(|e| AppError::Internal(e.to_string()))
}
