use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SecurityLog {
    pub id: String,
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub action: String,
    pub details_json: Option<String>,
    pub ip_hash: Option<String>,
    pub user_agent_hash: Option<String>,
    pub created_at: NaiveDateTime,
}
