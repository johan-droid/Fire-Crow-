use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct DomainVerifyRequest {
    pub domain: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainVerifyResponse {
    pub id: String,
    pub domain: String,
    pub verification_token: String,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub dns_txt_name: String,
    pub dns_txt_value: String,
    pub html_meta_name: String,
    pub html_meta_content: String,
    pub well_known_path: String,
    pub well_known_content: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainCheckRequest {
    pub domain: String,
    #[serde(default = "default_method")]
    pub method: String,
}

fn default_method() -> String { "dns".into() }

#[derive(Debug, Clone, Serialize)]
pub struct DomainCheckResponse {
    pub verified: bool,
    pub message: String,
}
