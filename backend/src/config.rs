//! Application configuration — loads from env vars with secure defaults.

use config::{Config, ConfigError, Environment};
use serde::Deserialize;

pub const BACKEND_DIR: &str = env!("CARGO_MANIFEST_DIR");
pub const WORKSPACE_DIR: &str = BACKEND_DIR;

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default)]
    pub debug: bool,
    pub secret_key: String,
    #[serde(default)]
    pub encryption_key: String,
    pub frontend_url: String,
    #[serde(default = "default_backend_base_url")]
    pub backend_base_url: String,
    pub cors_origins: String,
    pub database_url: String,
    #[serde(default = "default_pool_size")]
    pub database_pool_size: u32,
    #[serde(default = "default_pool_timeout")]
    pub database_pool_timeout: u32,
    #[serde(default = "default_pool_recycle")]
    pub database_pool_recycle: u32,
    #[serde(default)]
    pub redis_url: String,
    #[serde(default)]
    pub redis_password: String,
    #[serde(default = "default_rate_limit")]
    pub default_rate_limit: String,
    #[serde(default = "default_login_failure_window")]
    pub login_failure_window_minutes: i64,
    #[serde(default = "default_login_failure_limit")]
    pub login_failure_limit: i32,
    #[serde(default = "default_jwt_expire")]
    pub jwt_access_token_expire_minutes: i64,
    #[serde(default = "default_auth_cookie_name")]
    pub auth_cookie_name: String,
    #[serde(default = "default_true")]
    pub auth_cookie_secure: bool,
    #[serde(default = "default_true")]
    pub auth_cookie_httponly: bool,
    #[serde(default = "default_samesite_strict")]
    pub auth_cookie_samesite: String,
    #[serde(default = "default_true")]
    pub csrf_enabled: bool,
    #[serde(default = "default_mfa_enforce")]
    pub mfa_enforce_for_admins: bool,
    #[serde(default = "default_mfa_issuer")]
    pub mfa_totp_issuer: String,
    #[serde(default = "default_mfa_max_attempts")]
    pub mfa_max_failed_attempts: i32,
    #[serde(default = "default_mfa_recovery_codes")]
    pub mfa_recovery_code_count: i32,
    #[serde(default = "default_sso_scopes")]
    pub sso_oidc_scopes: String,
    #[serde(default)]
    pub sso_allow_auto_provision: bool,
    #[serde(default)]
    pub sso_default_role_id: String,
    #[serde(default)]
    pub github_client_id: String,
    #[serde(default)]
    pub github_client_secret: String,
    #[serde(default)]
    pub github_token: String,
    #[serde(default, deserialize_with = "deserialize_comma_separated")]
    pub github_oauth_scopes: Vec<String>,
    #[serde(default)]
    pub google_client_id: String,
    #[serde(default)]
    pub google_client_secret: String,
    #[serde(default)]
    pub resend_api_key: String,
    #[serde(default)]
    pub brevo_api_key: String,
    #[serde(default)]
    pub sender_email: String,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_user: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub r2_access_key_id: String,
    #[serde(default)]
    pub r2_secret_access_key: String,
    #[serde(default)]
    pub r2_endpoint_url: String,
    #[serde(default)]
    pub r2_bucket_name: String,
    #[serde(default)]
    pub cf_turnstile_secret_key: String,
    #[serde(default)]
    pub cf_turnstile_site_key: String,
    #[serde(default)]
    pub cf_turnstile_enabled: bool,
    #[serde(default)]
    pub dodo_payments_api_key: String,
    #[serde(default)]
    pub dodo_payments_webhook_secret: String,
    #[serde(default = "default_dodo_env")]
    pub dodo_payments_environment: String,
    #[serde(default)]
    pub gemini_api_key: String,
    #[serde(default = "default_gemini_fallback")]
    pub gemini_fallback_model: String,
    #[serde(default = "default_true")]
    pub gemini_enable_fallback_model: bool,
    #[serde(default = "default_gemini_max_attempts")]
    pub gemini_max_attempts: i32,
    #[serde(default = "default_gemini_timeout")]
    pub gemini_timeout_seconds: i64,
    #[serde(default = "default_gemini_max_findings")]
    pub gemini_max_findings_per_call: i32,
    #[serde(default = "default_gemini_max_prompt_chars")]
    pub gemini_max_prompt_chars: i32,
    #[serde(default = "default_gemini_daily_limit")]
    pub gemini_daily_soft_limit: i32,
    #[serde(default = "default_gemini_min_seconds")]
    pub gemini_min_seconds_between_calls: i64,
    #[serde(default = "default_max_active_jobs")]
    pub max_active_jobs_per_user: i32,
    #[serde(default = "default_broker_timeout")]
    pub broker_connection_timeout: f64,
    #[serde(default = "default_sse_poll_interval")]
    pub sse_poll_interval: f64,
    #[serde(default = "default_sse_heartbeat")]
    pub sse_heartbeat_interval: f64,
    #[serde(default = "default_report_ttl")]
    pub report_presigned_ttl: i64,
    #[serde(default = "default_true")]
    pub report_local_fallback: bool,
    #[serde(default = "default_max_scan_duration")]
    pub max_scan_duration: i32,
    #[serde(default = "default_budget_usd")]
    pub default_budget_usd: f64,
    #[serde(default = "default_scanner_timeout")]
    pub scanner_command_timeout: i32,
    #[serde(default = "default_scanner_output_max")]
    pub scanner_output_max_length: i32,
    #[serde(default = "default_api_discovery_limit")]
    pub api_discovery_limit: i32,
    #[serde(default = "default_housekeeping_interval")]
    pub housekeeping_interval_seconds: i64,
    #[serde(default = "default_max_request_body")]
    pub max_request_body_bytes: i64,
    #[serde(default = "default_max_json_body")]
    pub max_json_body_bytes: i64,
    #[serde(default = "default_report_max_pages")]
    pub report_max_pages: i32,
    #[serde(default = "default_report_max_findings")]
    pub report_max_findings_in_pdf: i32,
    #[serde(default = "default_report_max_evidence")]
    pub report_max_evidence_chars: i32,
    #[serde(default = "default_report_max_remediation")]
    pub report_max_remediation_chars: i32,
    #[serde(default = "default_true")]
    pub report_include_detailed_findings: bool,
    #[serde(default = "default_scoring_critical")]
    pub scoring_critical: f64,
    #[serde(default = "default_scoring_high")]
    pub scoring_high: f64,
    #[serde(default = "default_scoring_medium")]
    pub scoring_medium: f64,
    #[serde(default = "default_scoring_low")]
    pub scoring_low: f64,
    #[serde(default = "default_scoring_info")]
    pub scoring_info: f64,
    #[serde(default)]
    pub privacy_policy_version: String,
    #[serde(default)]
    pub terms_version: String,
}

fn default_port() -> u16 { 8000 }
fn default_host() -> String { "0.0.0.0".into() }
fn default_pool_size() -> u32 { 10 }
fn default_pool_timeout() -> u32 { 30 }
fn default_pool_recycle() -> u32 { 3600 }
fn default_true() -> bool { true }
fn default_rate_limit() -> String { "100/hour".into() }
fn default_backend_base_url() -> String { "http://localhost:8000".into() }
fn default_login_failure_window() -> i64 { 10 }
fn default_login_failure_limit() -> i32 { 5 }
fn default_jwt_expire() -> i64 { 60 * 24 }
fn default_auth_cookie_name() -> String { "fc_access_token".into() }
fn default_samesite_strict() -> String { "strict".into() }
fn default_mfa_enforce() -> bool { true }
fn default_mfa_issuer() -> String { "Fire Crow".into() }
fn default_mfa_max_attempts() -> i32 { 5 }
fn default_mfa_recovery_codes() -> i32 { 8 }
fn default_sso_scopes() -> String { "openid email profile".into() }
fn default_smtp_port() -> u16 { 587 }
fn default_gemini_fallback() -> String { "gemini-1.5-pro".into() }
fn default_gemini_max_attempts() -> i32 { 3 }
fn default_gemini_timeout() -> i64 { 30 }
fn default_gemini_max_findings() -> i32 { 50 }
fn default_gemini_max_prompt_chars() -> i32 { 100_000 }
fn default_gemini_daily_limit() -> i32 { 1000 }
fn default_gemini_min_seconds() -> i64 { 1 }
fn default_max_active_jobs() -> i32 { 2 }
fn default_broker_timeout() -> f64 { 0.5 }
fn default_sse_poll_interval() -> f64 { 0.5 }
fn default_sse_heartbeat() -> f64 { 15.0 }
fn default_report_ttl() -> i64 { 900 }
fn default_max_scan_duration() -> i32 { 1800 }
fn default_budget_usd() -> f64 { 1.0 }
fn default_scanner_timeout() -> i32 { 300 }
fn default_scanner_output_max() -> i32 { 20000 }
fn default_api_discovery_limit() -> i32 { 30 }
fn default_housekeeping_interval() -> i64 { 3600 }
fn default_max_request_body() -> i64 { 10 * 1024 * 1024 }
fn default_max_json_body() -> i64 { 2 * 1024 * 1024 }
fn default_report_max_pages() -> i32 { 30 }
fn default_report_max_findings() -> i32 { 50 }
fn default_report_max_evidence() -> i32 { 1200 }
fn default_report_max_remediation() -> i32 { 1200 }
fn default_scoring_critical() -> f64 { 9.8 }
fn default_scoring_high() -> f64 { 8.5 }
fn default_scoring_medium() -> f64 { 5.5 }
fn default_scoring_low() -> f64 { 2.5 }
fn default_scoring_info() -> f64 { 0.0 }

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let _ = dotenvy::from_filename(".env.local");
        let _ = dotenvy::from_filename("../.env.local");
        let _ = dotenvy::dotenv();
        let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "production".into());

        let config = Config::builder()
            .set_default("port", default_port())?
            .set_default("host", default_host())?
            .set_default("debug", run_mode == "development")?
            .add_source(Environment::default())
            .build()?;

        let mut settings: Settings = config.try_deserialize()?;
        Self::validate(&mut settings)?;
        Ok(settings)
    }

    fn validate(settings: &mut Self) -> Result<(), ConfigError> {
        let insecure_dev_values = [
            "dev_secret_key_change_in_production_1234567890",
            "change_me", "changeme", "secret", "development",
            "local_dev_secret_key_change_me_1234567890",
            "local_dev_encryption_key_change_me_1234567890",
        ];

        if settings.debug {
            if settings.secret_key.is_empty() {
                settings.secret_key = "local_dev_secret_key_change_me_1234567890".into();
            }
            if settings.encryption_key.is_empty() {
                settings.encryption_key = "local_dev_encryption_key_change_me_1234567890".into();
            }
        } else {
            if settings.secret_key.is_empty() {
                return Err(ConfigError::Message("SECRET_KEY is required. Set a strong random value (min 32 chars).".into()));
            }
            if insecure_dev_values.contains(&settings.secret_key.as_str()) {
                return Err(ConfigError::Message("SECRET_KEY cannot use a known development value.".into()));
            }
            if settings.secret_key.len() < 32 {
                return Err(ConfigError::Message("SECRET_KEY must be at least 32 characters.".into()));
            }

            if settings.encryption_key.is_empty() {
                return Err(ConfigError::Message("ENCRYPTION_KEY is required. Set a strong random value (min 32 chars).".into()));
            }
            if insecure_dev_values.contains(&settings.encryption_key.as_str())
                || settings.encryption_key.len() < 32
            {
                return Err(ConfigError::Message("ENCRYPTION_KEY must be at least 32 characters and not a dev value.".into()));
            }
        }

        // CRIT-02: SECRET_KEY and ENCRYPTION_KEY must never be identical.
        // Reusing one key for JWT signing AND data encryption collapses the
        // security boundary — compromising one key compromises both.
        if !settings.encryption_key.is_empty()
            && !settings.secret_key.is_empty()
            && settings.encryption_key == settings.secret_key
        {
            return Err(ConfigError::Message(
                "SECRET_KEY and ENCRYPTION_KEY must be different values. Using the same \
                 value for both collapses crypto separation (CWE-326)."
                    .into(),
            ));
        }

        Ok(())
    }

    pub fn cors_origins(&self) -> Vec<String> {
        let mut origins: std::collections::HashSet<String> = std::collections::HashSet::new();
        if !self.frontend_url.is_empty() {
            origins.insert(self.frontend_url.trim_end_matches('/').into());
        }
        if !self.cors_origins.is_empty() {
            for origin in self.cors_origins.split(',') {
                let o = origin.trim().trim_end_matches('/');
                if !o.is_empty() && o != "*" {
                    origins.insert(o.into());
                }
            }
        }
        if self.debug {
            origins.insert("http://localhost:3000".into());
            origins.insert("http://127.0.0.1:3000".into());
            origins.insert("http://localhost:3001".into());
            origins.insert("http://127.0.0.1:3001".into());
            origins.insert("http://localhost:5173".into());
            origins.insert("http://127.0.0.1:5173".into());
        }
        origins.into_iter().collect()
    }
}

pub fn ensure_workspace_dirs(_settings: &Settings) -> std::io::Result<()> {
    let base = std::path::PathBuf::from(WORKSPACE_DIR);
    for dir in ["workspace/reports", "workspace/temp", "workspace/storage", "workspace/scans"] {
        std::fs::create_dir_all(base.join(dir))?;
    }
    Ok(())
}

fn deserialize_comma_separated<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum VecOrString {
        Vec(Vec<String>),
        String(String),
    }
    match Option::<VecOrString>::deserialize(deserializer)? {
        Some(VecOrString::Vec(v)) => Ok(v),
        Some(VecOrString::String(s)) => Ok(s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()),
        None => Ok(Vec::new()),
    }
}

fn default_dodo_env() -> String {
    "test_mode".to_string()
}
