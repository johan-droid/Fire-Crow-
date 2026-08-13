use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PrivacyAuditLog {
    pub id: String,
    pub user_id: String,
    pub tenant_id: Option<String>,
    pub event_type: String,
    pub anonymized_ip: String,
    pub user_agent_hash: Option<String>,
    pub details_json: Option<serde_json::Value>,
    pub is_brand_visible: bool,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePrivacyAuditRequest {
    pub tenant_id: Option<String>,
    pub event_type: String,
    pub details_json: Option<serde_json::Value>,
    pub is_brand_visible: Option<bool>,
}
