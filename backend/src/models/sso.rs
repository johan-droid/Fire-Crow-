use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SsoProvider {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub jwks_url: Option<String>,
    pub certificate: Option<String>,
    pub attribute_mapping: Option<String>,
    pub domains: Option<String>,
    pub enforce_mfa: bool,
    pub auto_provision: bool,
    pub default_role_id: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SsoSession {
    pub id: String,
    pub user_id: String,
    pub provider_id: String,
    pub external_id: String,
    pub created_at: NaiveDateTime,
    pub last_used_at: Option<NaiveDateTime>,
}
