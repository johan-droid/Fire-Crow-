use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserActivityEvent {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub details_json: Option<String>,
    pub created_at: NaiveDateTime,
}
