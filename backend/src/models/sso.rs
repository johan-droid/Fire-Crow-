use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SsoProvider {
    pub id: String,
    pub name: String,
    pub provider_type: String,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    /// security_p0_4: write-only. Deserialization still accepts it on create,
    /// but it is never serialized back out, so no read endpoint can leak it and
    /// no dashboard payload can carry it.
    #[serde(skip_serializing)]
    pub client_secret: Option<String>,
    /// Lets a UI show whether a secret is configured without disclosing it.
    ///
    /// `sqlx(skip)` because this is a response-only flag, not a column. Without it
    /// `FromRow` tries to read it from the table and every SSO read fails with
    /// "no column found for name: client_secret_set". The service sets it after
    /// loading the row.
    #[sqlx(skip)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_set: Option<bool>,
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
