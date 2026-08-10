use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub domain: Option<String>,
    pub plan: String,
    pub max_users: Option<i32>,
    pub max_storage_gb: Option<i32>,
    pub is_active: bool,
    pub created_at: NaiveDateTime,
}
