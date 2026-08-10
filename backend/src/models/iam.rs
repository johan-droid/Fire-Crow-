use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct IamPolicy {
    pub id: String,
    pub name: String,
    pub effect: String,
    pub actions: String,
    pub resources: String,
    pub description: Option<String>,
    pub conditions: Option<String>,
    pub priority: i32,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct RolePermission {
    pub id: String,
    pub role_id: String,
    pub permission: String,
    pub resource_pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AccountAuditLog {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub details: Option<String>,
    pub actor_id: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ServiceAccount {
    pub id: String,
    pub name: String,
    pub token_hash: String,
    pub permissions: String,
    pub description: Option<String>,
    pub expires_at: Option<NaiveDateTime>,
    pub created_by: String,
    pub is_active: bool,
    pub created_at: NaiveDateTime,
}
