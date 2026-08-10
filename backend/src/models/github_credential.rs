use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GithubCredential {
    pub id: String,
    pub user_id: String,
    pub github_id: String,
    pub access_token: String,
    pub scopes: Option<String>,
    pub created_at: NaiveDateTime,
}
