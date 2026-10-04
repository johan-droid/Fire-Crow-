use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, sqlx::FromRow)]
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

/// Secret-safe `Debug` (Phase 20): the derived impl printed `client_secret`
/// even though the wire format already skips it — `skip_serializing` does not
/// affect `Debug`.
impl std::fmt::Debug for SsoProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoProvider")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("provider_type", &self.provider_type)
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("client_secret_set", &self.client_secret_set)
            .field("authorization_url", &self.authorization_url)
            .field("token_url", &self.token_url)
            .field("userinfo_url", &self.userinfo_url)
            .field("jwks_url", &self.jwks_url)
            .field("certificate", &self.certificate)
            .field("attribute_mapping", &self.attribute_mapping)
            .field("domains", &self.domains)
            .field("enforce_mfa", &self.enforce_mfa)
            .field("auto_provision", &self.auto_provision)
            .field("default_role_id", &self.default_role_id)
            .field("created_at", &self.created_at)
            .finish()
    }
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
