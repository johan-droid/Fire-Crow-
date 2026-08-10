use crate::error::{AppError, Result};
use crate::models::UserSession;
use chrono::Utc;

pub async fn create_session(pool: &sqlx::PgPool, user_id: &str, token_family: &str, ip_hash: &str, user_agent_hash: &str, expires_at: chrono::NaiveDateTime) -> Result<UserSession> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query_as::<_, UserSession>(
        "INSERT INTO user_sessions (id, user_id, token_family, ip_hash, user_agent_hash, created_at, expires_at, is_revoked) VALUES ($1,$2,$3,$4,$5,$6,$7,false) RETURNING *"
    )
    .bind(id).bind(user_id).bind(token_family).bind(ip_hash).bind(user_agent_hash).bind(Utc::now().naive_utc()).bind(expires_at)
    .fetch_one(pool).await.map_err(AppError::Database)
}
pub async fn revoke_session(pool: &sqlx::PgPool, session_id: &str, reason: Option<&str>) -> Result<bool> {
    let r = sqlx::query("UPDATE user_sessions SET is_revoked=true, revocation_reason=$1 WHERE id=$2")
        .bind(reason).bind(session_id)
        .execute(pool).await.map_err(AppError::Database)?;
    Ok(r.rows_affected() > 0)
}
