use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DomainVerification {
    pub id: String,
    pub user_id: String,
    pub domain: String,
    pub verification_token: String,
    pub verified: bool,
    pub verified_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub dns_txt_name: String,
    pub dns_txt_value: String,
    pub html_meta_name: String,
    pub html_meta_content: String,
    pub well_known_path: String,
    pub well_known_content: String,
}
