use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MfaConfiguration {
    pub id: String,
    pub user_id: String,
    pub enabled: bool,
    pub secret: Option<String>,
    pub backup_codes_consumed: i32,
    pub last_verified_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MfaRecoveryCode {
    pub id: String,
    pub mfa_config_id: String,
    pub code_hash: String,
    pub used_at: Option<NaiveDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MfaAuditLog {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub success: bool,
    pub ip_hash: Option<String>,
    pub created_at: NaiveDateTime,
}
