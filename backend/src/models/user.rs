//! Core user and auth models.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::Type;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type, Default)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    #[default]
    Queued, Running, Completed, Failed, Cancelled, Partial,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self { Self::Queued => "queued", Self::Running => "running", Self::Completed => "completed", Self::Failed => "failed", Self::Cancelled => "cancelled", Self::Partial => "partial" }
    }
}

impl std::str::FromStr for JobStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "queued" => Ok(Self::Queued), "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed), "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled), "partial" => Ok(Self::Partial),
            _ => Err(format!("Unknown job status: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type, Default)]
#[sqlx(type_name = "text", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical, High, Medium, Low, #[default] Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self { Self::Critical => "critical", Self::High => "high", Self::Medium => "medium", Self::Low => "low", Self::Info => "info" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: Option<String>,
    pub credit_balance: f64,
    pub email: Option<String>,
    pub tenant_id: Option<String>,
    pub role_id: Option<String>,
    pub is_active: bool,
    pub github_id: Option<String>,
    pub google_id: Option<String>,
    pub github_access_token: Option<String>,
    pub github_token_scopes: Option<String>,
    pub github_token_updated_at: Option<NaiveDateTime>,
    pub privacy_policy_version: Option<String>,
    pub privacy_policy_accepted_at: Option<NaiveDateTime>,
    pub terms_version: Option<String>,
    pub terms_accepted_at: Option<NaiveDateTime>,
    pub first_login_at: Option<NaiveDateTime>,
    pub last_login_at: Option<NaiveDateTime>,
    pub last_logout_at: Option<NaiveDateTime>,
    pub region: Option<String>,
    pub timezone: Option<String>,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LoginFailure {
    pub id: String,
    pub key_hash: String,
    pub attempted_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserSession {
    pub id: String,
    pub user_id: String,
    pub token_family: String,
    pub ip_hash: String,
    pub user_agent_hash: String,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
    pub is_revoked: bool,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthExchangeCode {
    pub id: Option<String>,
    pub code: String,
    pub user_id: String,
    pub username: String,
    pub access_token: String,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PushSubscription {
    pub id: String,
    pub user_id: String,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserActivityEvent {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub details_json: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GithubCredential {
    pub id: String,
    pub user_id: String,
    pub github_id: String,
    pub access_token: String,
    pub scopes: Option<String>,
    pub created_at: NaiveDateTime,
}
