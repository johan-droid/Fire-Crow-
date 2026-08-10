use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Option<String>,
    pub is_system_role: bool,
    pub created_at: NaiveDateTime,
}
