use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PrivilegedAccessRequest {
    pub id: String,
    pub user_id: String,
    pub role_name: String,
    pub permission: String,
    pub reason: String,
    pub requested_duration_minutes: i32,
    pub ticket_ref: Option<String>,
    pub status: String,
    pub approver_id: Option<String>,
    pub deny_reason: Option<String>,
    pub started_at: Option<NaiveDateTime>,
    pub ends_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PrivilegedAccessGrant {
    pub id: String,
    pub request_id: String,
    pub granted_by: String,
    pub expires_at: NaiveDateTime,
    pub revoked: bool,
    pub revoked_at: Option<NaiveDateTime>,
    pub revoked_by: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PrivilegedAccessAudit {
    pub id: String,
    pub request_id: String,
    pub action: String,
    pub actor_id: String,
    pub details: Option<String>,
    pub created_at: NaiveDateTime,
}
