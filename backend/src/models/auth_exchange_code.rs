use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthExchangeCode {
    pub code: String,
    pub user_id: String,
    pub username: String,
    pub access_token: String,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}
