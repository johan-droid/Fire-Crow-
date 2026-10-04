use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MfaConfiguration {
    pub id: String,
    pub user_id: String,
    pub enabled: bool,
    pub secret: Option<String>,
    pub backup_codes_consumed: i32,
    pub last_verified_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
}

/// Secret-safe `Debug` (Phase 20): the derived impl printed the TOTP secret.
impl std::fmt::Debug for MfaConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaConfiguration")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("enabled", &self.enabled)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field("backup_codes_consumed", &self.backup_codes_consumed)
            .field("last_verified_at", &self.last_verified_at)
            .field("created_at", &self.created_at)
            .finish()
    }
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
