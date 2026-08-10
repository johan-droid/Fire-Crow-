use crate::error::{AppError, Result};
use crate::services::redaction::redact_text;
use chrono::Utc;
use sha2::Digest;

pub async fn record_security_event(
    pool: &sqlx::PgPool, user_id: Option<&str>, tenant_id: Option<&str>,
    action: &str, details: Option<&str>, ip_hash: Option<&str>,
) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let details_json = details.map(|d| redact_text(d, 2048));
    sqlx::query("INSERT INTO security_logs (id, user_id, tenant_id, action, details_json, ip_hash, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(id).bind(user_id).bind(tenant_id).bind(action).bind(details_json).bind(ip_hash).bind(Utc::now().naive_utc())
        .execute(pool).await.map_err(AppError::Database)?;
    Ok(())
}

pub async fn record_user_activity(
    pool: &sqlx::PgPool, user_id: &str, action: &str, details: Option<&str>,
) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO user_activity_events (id, user_id, action, details_json, created_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(id).bind(user_id).bind(action).bind(details).bind(Utc::now().naive_utc())
        .execute(pool).await.map_err(AppError::Database)?;
    Ok(())
}

pub fn hash_ip(ip: &str) -> String { format!("{:x}", sha2::Sha256::digest(ip.as_bytes())) }
pub fn hash_user_agent(ua: &str) -> String { format!("{:x}", sha2::Sha256::digest(ua.as_bytes())) }
