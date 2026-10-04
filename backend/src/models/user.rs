//! Core user and auth models.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{encode::IsNull, error::BoxDynError, postgres::PgArgumentBuffer, TypeInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    #[default]
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Partial,
    /// The job ran, but no vulnerability analysis was performed because no scan
    /// engine is installed in this build. Distinct from `Completed`, which means
    /// an engine executed. A client must never read this as "no vulnerabilities".
    ///
    /// Stored in the existing `audit_jobs.status` varchar column, which carries no
    /// CHECK constraint, so no migration is required.
    #[serde(rename = "engine_unavailable")]
    EngineUnavailable,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Partial => "partial",
            Self::EngineUnavailable => "engine_unavailable",
        }
    }

    /// Terminal job outcomes: nothing may leave them.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Failed
                | Self::Cancelled
                | Self::Partial
                | Self::EngineUnavailable
        )
    }

    /// Whether `self -> next` is a legal job-status step.
    ///
    /// `Queued -> Running` is the worker claim; `Running` fans out to every
    /// terminal outcome. `Queued` may also go straight to `Failed` (claim-time
    /// error, reaper) or `Cancelled` (user cancels before start). Terminal
    /// states transition nowhere — a finished job is immutable.
    pub fn can_transition(&self, next: &Self) -> bool {
        if self.is_terminal() {
            return false;
        }
        matches!(
            (self, next),
            (Self::Queued, Self::Running | Self::Failed | Self::Cancelled)
                | (
                    Self::Running,
                    Self::Completed
                        | Self::Partial
                        | Self::Failed
                        | Self::Cancelled
                        | Self::EngineUnavailable,
                )
        )
    }
}

impl std::str::FromStr for JobStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "partial" => Ok(Self::Partial),
            "engine_unavailable" => Ok(Self::EngineUnavailable),
            _ => Err(format!("Unknown job status: {s}")),
        }
    }
}

impl sqlx::Type<sqlx::Postgres> for JobStatus {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        let name = ty.name().to_lowercase();
        name == "jobstatus" || name == "job_status" || name == "text" || name == "varchar"
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for JobStatus {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let s = <&str as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        s.parse::<JobStatus>().map_err(|e| e.into())
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for JobStatus {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&str as sqlx::Encode<sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    #[default]
    Info,
    /// No trustworthy severity signal. Dependency advisories (OSV) do not
    /// uniformly carry severity; reporting `Unknown` is honest, while mapping
    /// every such finding to High would invent urgency.
    Unknown,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
            Self::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "unknown" => Ok(Self::Unknown),
            "info" => Ok(Self::Info),
            _ => Ok(Self::Info),
        }
    }
}

impl sqlx::Type<sqlx::Postgres> for Severity {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        let name = ty.name().to_lowercase();
        name == "severity" || name == "text" || name == "varchar"
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Severity {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let s = <&str as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        s.parse::<Severity>().map_err(|e| e.into())
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Postgres> for Severity {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&str as sqlx::Encode<sqlx::Postgres>>::encode_by_ref(&self.as_str(), buf)
    }
}

/// Secret-safe `Debug` for credential-bearing rows (Phase 20).
///
/// These models travel through logs, panics, and test snapshots. The derived
/// `Debug` printed password hashes, OAuth tokens, MFA secrets, and push keys
/// verbatim. Each impl below renders `[REDACTED]` for credential fields and
/// keeps operational fields visible.
macro_rules! redact_debug {
    ($name:ident, { $( $field:ident ),* }, { $( $secret:ident ),* }) => {
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($field), &self.$field))*
                    $(.field(stringify!($secret), &"[REDACTED]"))*
                    .finish()
            }
        }
    };
}

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
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

redact_debug!(User,
    { id, username, credit_balance, email, tenant_id, role_id, is_active,
      github_id, google_id, github_token_scopes, github_token_updated_at,
      privacy_policy_version, privacy_policy_accepted_at, terms_version,
      terms_accepted_at, first_login_at, last_login_at, last_logout_at,
      region, timezone, mfa_enabled, created_at },
    { password_hash, github_access_token, mfa_secret });

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LoginFailure {
    pub id: String,
    pub key_hash: String,
    pub attempted_at: NaiveDateTime,
}

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
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

redact_debug!(UserSession,
    { id, user_id, ip_hash, user_agent_hash, created_at, expires_at,
      is_revoked, revocation_reason },
    { token_family });

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuthExchangeCode {
    pub id: Option<String>,
    pub code: String,
    pub user_id: String,
    pub username: String,
    pub access_token: String,
    pub created_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}

redact_debug!(AuthExchangeCode,
    { id, user_id, username, created_at, expires_at },
    { code, access_token });

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PushSubscription {
    pub id: String,
    pub user_id: String,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub created_at: NaiveDateTime,
}

redact_debug!(PushSubscription,
    { id, user_id, endpoint, created_at },
    { p256dh, auth });

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserActivityEvent {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub details_json: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GithubCredential {
    pub id: String,
    pub user_id: String,
    pub github_id: String,
    pub access_token: String,
    pub scopes: Option<String>,
    pub created_at: NaiveDateTime,
}

redact_debug!(GithubCredential,
    { id, user_id, github_id, scopes, created_at },
    { access_token });
