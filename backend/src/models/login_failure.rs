use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LoginFailure {
    pub id: String,
    pub key_hash: String,
    pub attempted_at: NaiveDateTime,
}
