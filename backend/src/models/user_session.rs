use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserSession {
    pub id: String,
    pub user_id: String,
    pub token_family: String,
    pub ip_hash: String,
    pub user_agent_hash: String,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub is_revoked: bool,
    pub revocation_reason: Option<String>,
}
