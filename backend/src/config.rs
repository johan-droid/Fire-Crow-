//! Application configuration — loads from env vars with secure defaults.

use config::{Config, ConfigError, Environment};
use serde::Deserialize;

pub const BACKEND_DIR: &str = env!("CARGO_MANIFEST_DIR");
pub const WORKSPACE_DIR: &str = BACKEND_DIR;

#[derive(Clone, Deserialize)]
pub struct Settings {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_host")]
    pub host: String,
    /// Verbose error/log detail. Affects **presentation only** — never whether a
    /// security control runs. security_p0_3.
    #[serde(default)]
    pub debug: bool,
    /// Global request rate limiting. Governed independently of `debug` so that
    /// enabling debug logging can never disable rate limiting. security_p0_3.
    #[serde(default = "default_true")]
    pub rate_limit_enabled: bool,
    /// HMAC signing key for JWTs and encrypted-at-rest secrets.
    ///
    /// security_p0_3 / phase7: this field deliberately carries `#[serde(default)]`
    /// so that an *absent* SECRET_KEY deserializes to an empty string and is then
    /// rejected by `validate()` with an actionable message naming the environment
    /// variable. Without the default, deserialization failed first with serde's
    /// "missing field" error naming the Rust field rather than the environment
    /// variable, with no guidance. The encryption_key field below already worked
    /// this way; this brings SECRET_KEY in line with it.
    ///
    /// The default changes nothing about the outcome: both paths fail closed, and
    /// both refuse to start the process.
    #[serde(default)]
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
    /// GitHub App identity (Phase 19B.1). `0` / empty means the App
    /// integration is disabled: startup succeeds and the OAuth + platform
    /// token paths are unaffected. Setting only one of the two is a
    /// configuration error, and a key that is not an RSA private key PEM is
    /// rejected at startup rather than at first mint.
    ///
    /// The App ID is public (it appears in JWT claims and API URLs); the
    /// private key is secret and never logged (see the manual `Debug` impl).
    #[serde(default)]
    pub github_app_id: u64,
    #[serde(default)]
    pub github_app_private_key: String,
    /// Webhook signature secret (Phase 19B.5). Empty means the webhook route
    /// is unconfigured and refuses every delivery; it never degrades to
    /// unverified acceptance.
    #[serde(default)]
    pub github_app_webhook_secret: String,
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
    // Telegram delivery (Phase 17.3). Both are operator configuration and both are
    // optional: an absent token or chat leaves the channel unconfigured, which
    // fails a delivery request cleanly instead of breaking startup. Neither is
    // ever derived from request input.
    #[serde(default)]
    pub telegram_bot_token: String,
    #[serde(default)]
    pub telegram_chat_id: String,
    #[serde(default = "default_telegram_timeout")]
    pub telegram_timeout_seconds: i64,
    #[serde(default = "default_telegram_max_attempts")]
    pub telegram_max_attempts: i32,
    #[serde(default = "default_telegram_max_response_bytes")]
    pub telegram_max_response_bytes: usize,
    /// Ceiling on a Telegram message before it becomes a summary instead of the
    /// full report. Defaults to the provider's own message ceiling; lowering it is
    /// an operator choice, raising it above the ceiling would only produce
    /// rejections.
    #[serde(default = "default_telegram_message_limit")]
    pub telegram_message_limit_chars: usize,
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
    /// The model used for a generation. Recorded for observability only: it
    /// names the model that produced a narrative without ever becoming part of
    /// the narrative itself.
    ///
    /// Intentionally defaulted to *empty* rather than to a model name. An unset
    /// model fails generation loudly instead of silently substituting one, and
    /// the backend still starts with the AI layer disabled.
    #[serde(default)]
    pub gemini_model: String,
    // Phase 19.1: the fallback-model settings were removed. They were never
    // read by any generation path (a single model is configured and used), so
    // they only suggested a failover that does not exist. Environments that
    // still set GEMINI_FALLBACK_MODEL / GEMINI_ENABLE_FALLBACK_MODEL load
    // unchanged: unknown env keys are ignored.
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
    #[serde(default)]
    pub osv_egress_proxy: Option<String>,
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

/// Secret-safe `Debug`: credentials and credential-bearing URLs render as
/// `[REDACTED]`, never their values.
///
/// `Settings` holds every credential the process uses (signing keys, database
/// URLs that embed passwords, provider tokens). A derived `Debug` would print
/// all of them into any log line, panic message, or test snapshot that formats
/// the struct. Non-secret operational fields stay visible so the output is
/// still useful for diagnosing configuration problems.
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const HIDDEN: &str = "[REDACTED]";
        f.debug_struct("Settings")
            .field("port", &self.port)
            .field("host", &self.host)
            .field("debug", &self.debug)
            .field("rate_limit_enabled", &self.rate_limit_enabled)
            .field("secret_key", &HIDDEN)
            .field("encryption_key", &HIDDEN)
            .field("frontend_url", &self.frontend_url)
            .field("backend_base_url", &self.backend_base_url)
            .field("cors_origins", &self.cors_origins)
            .field("database_url", &HIDDEN)
            .field("database_pool_size", &self.database_pool_size)
            .field("database_pool_timeout", &self.database_pool_timeout)
            .field("database_pool_recycle", &self.database_pool_recycle)
            .field("redis_url", &HIDDEN)
            .field("redis_password", &HIDDEN)
            .field("default_rate_limit", &self.default_rate_limit)
            .field(
                "login_failure_window_minutes",
                &self.login_failure_window_minutes,
            )
            .field("login_failure_limit", &self.login_failure_limit)
            .field(
                "jwt_access_token_expire_minutes",
                &self.jwt_access_token_expire_minutes,
            )
            .field("auth_cookie_name", &self.auth_cookie_name)
            .field("auth_cookie_secure", &self.auth_cookie_secure)
            .field("auth_cookie_httponly", &self.auth_cookie_httponly)
            .field("auth_cookie_samesite", &self.auth_cookie_samesite)
            .field("csrf_enabled", &self.csrf_enabled)
            .field("mfa_enforce_for_admins", &self.mfa_enforce_for_admins)
            .field("mfa_totp_issuer", &self.mfa_totp_issuer)
            .field("mfa_max_failed_attempts", &self.mfa_max_failed_attempts)
            .field("mfa_recovery_code_count", &self.mfa_recovery_code_count)
            .field("sso_oidc_scopes", &self.sso_oidc_scopes)
            .field("sso_allow_auto_provision", &self.sso_allow_auto_provision)
            .field("sso_default_role_id", &self.sso_default_role_id)
            .field("github_client_id", &self.github_client_id)
            .field("github_client_secret", &HIDDEN)
            .field("github_token", &HIDDEN)
            .field("github_app_id", &self.github_app_id)
            .field("github_app_private_key", &HIDDEN)
            .field("github_app_webhook_secret", &HIDDEN)
            .field("github_oauth_scopes", &self.github_oauth_scopes)
            .field("google_client_id", &self.google_client_id)
            .field("google_client_secret", &HIDDEN)
            .field("resend_api_key", &HIDDEN)
            .field("brevo_api_key", &HIDDEN)
            .field("sender_email", &self.sender_email)
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("smtp_user", &self.smtp_user)
            .field("smtp_password", &HIDDEN)
            .field("telegram_bot_token", &HIDDEN)
            .field("telegram_chat_id", &self.telegram_chat_id)
            .field("telegram_timeout_seconds", &self.telegram_timeout_seconds)
            .field("telegram_max_attempts", &self.telegram_max_attempts)
            .field(
                "telegram_max_response_bytes",
                &self.telegram_max_response_bytes,
            )
            .field(
                "telegram_message_limit_chars",
                &self.telegram_message_limit_chars,
            )
            .field("r2_access_key_id", &HIDDEN)
            .field("r2_secret_access_key", &HIDDEN)
            .field("r2_endpoint_url", &self.r2_endpoint_url)
            .field("r2_bucket_name", &self.r2_bucket_name)
            .field("cf_turnstile_secret_key", &HIDDEN)
            .field("cf_turnstile_site_key", &self.cf_turnstile_site_key)
            .field("cf_turnstile_enabled", &self.cf_turnstile_enabled)
            .field("dodo_payments_api_key", &HIDDEN)
            .field("dodo_payments_webhook_secret", &HIDDEN)
            .field("dodo_payments_environment", &self.dodo_payments_environment)
            .field("gemini_api_key", &HIDDEN)
            .field("gemini_model", &self.gemini_model)
            .field("gemini_max_attempts", &self.gemini_max_attempts)
            .field("gemini_timeout_seconds", &self.gemini_timeout_seconds)
            .field(
                "gemini_max_findings_per_call",
                &self.gemini_max_findings_per_call,
            )
            .field("gemini_max_prompt_chars", &self.gemini_max_prompt_chars)
            .field("gemini_daily_soft_limit", &self.gemini_daily_soft_limit)
            .field(
                "gemini_min_seconds_between_calls",
                &self.gemini_min_seconds_between_calls,
            )
            .field("max_active_jobs_per_user", &self.max_active_jobs_per_user)
            .field("broker_connection_timeout", &self.broker_connection_timeout)
            .field("sse_poll_interval", &self.sse_poll_interval)
            .field("sse_heartbeat_interval", &self.sse_heartbeat_interval)
            .field("report_presigned_ttl", &self.report_presigned_ttl)
            .field("report_local_fallback", &self.report_local_fallback)
            .field("max_scan_duration", &self.max_scan_duration)
            .field("default_budget_usd", &self.default_budget_usd)
            .field("scanner_command_timeout", &self.scanner_command_timeout)
            .field("osv_egress_proxy", &self.osv_egress_proxy)
            .field("scanner_output_max_length", &self.scanner_output_max_length)
            .field("api_discovery_limit", &self.api_discovery_limit)
            .field(
                "housekeeping_interval_seconds",
                &self.housekeeping_interval_seconds,
            )
            .field("max_request_body_bytes", &self.max_request_body_bytes)
            .field("max_json_body_bytes", &self.max_json_body_bytes)
            .field("report_max_pages", &self.report_max_pages)
            .field(
                "report_max_findings_in_pdf",
                &self.report_max_findings_in_pdf,
            )
            .field("report_max_evidence_chars", &self.report_max_evidence_chars)
            .field(
                "report_max_remediation_chars",
                &self.report_max_remediation_chars,
            )
            .field(
                "report_include_detailed_findings",
                &self.report_include_detailed_findings,
            )
            .field("scoring_critical", &self.scoring_critical)
            .field("scoring_high", &self.scoring_high)
            .field("scoring_medium", &self.scoring_medium)
            .field("scoring_low", &self.scoring_low)
            .field("scoring_info", &self.scoring_info)
            .field("privacy_policy_version", &self.privacy_policy_version)
            .field("terms_version", &self.terms_version)
            .finish()
    }
}

fn default_port() -> u16 {
    8000
}
fn default_host() -> String {
    "0.0.0.0".into()
}
fn default_pool_size() -> u32 {
    10
}
fn default_pool_timeout() -> u32 {
    30
}
fn default_pool_recycle() -> u32 {
    3600
}
fn default_true() -> bool {
    true
}
fn default_rate_limit() -> String {
    "100/hour".into()
}
fn default_backend_base_url() -> String {
    "http://localhost:8000".into()
}
fn default_login_failure_window() -> i64 {
    10
}
fn default_login_failure_limit() -> i32 {
    5
}
fn default_jwt_expire() -> i64 {
    60 * 24
}
fn default_auth_cookie_name() -> String {
    "fc_access_token".into()
}
fn default_samesite_strict() -> String {
    "strict".into()
}
fn default_mfa_enforce() -> bool {
    true
}
fn default_mfa_issuer() -> String {
    "Fire Crow".into()
}
fn default_mfa_max_attempts() -> i32 {
    5
}
fn default_mfa_recovery_codes() -> i32 {
    8
}
fn default_sso_scopes() -> String {
    "openid email profile".into()
}
fn default_smtp_port() -> u16 {
    587
}
fn default_telegram_timeout() -> i64 {
    20
}
fn default_telegram_max_attempts() -> i32 {
    2
}
fn default_telegram_max_response_bytes() -> usize {
    64 * 1024
}
fn default_telegram_message_limit() -> usize {
    // Telegram's documented ceiling for a text message. Reused rather than
    // duplicated so the default can never drift from the transport's contract.
    crate::services::telegram_artifact::TELEGRAM_MAX_MESSAGE_CHARS
}
fn default_gemini_max_attempts() -> i32 {
    3
}
fn default_gemini_timeout() -> i64 {
    30
}
fn default_gemini_max_findings() -> i32 {
    50
}
fn default_gemini_max_prompt_chars() -> i32 {
    100_000
}
fn default_gemini_daily_limit() -> i32 {
    1000
}
fn default_gemini_min_seconds() -> i64 {
    1
}
fn default_max_active_jobs() -> i32 {
    2
}
fn default_broker_timeout() -> f64 {
    0.5
}
fn default_sse_poll_interval() -> f64 {
    0.5
}
fn default_sse_heartbeat() -> f64 {
    15.0
}
fn default_report_ttl() -> i64 {
    900
}
fn default_max_scan_duration() -> i32 {
    1800
}
fn default_budget_usd() -> f64 {
    1.0
}
fn default_scanner_timeout() -> i32 {
    300
}
fn default_scanner_output_max() -> i32 {
    20000
}
fn default_api_discovery_limit() -> i32 {
    30
}
fn default_housekeeping_interval() -> i64 {
    3600
}
fn default_max_request_body() -> i64 {
    10 * 1024 * 1024
}
fn default_max_json_body() -> i64 {
    2 * 1024 * 1024
}
fn default_report_max_pages() -> i32 {
    30
}
fn default_report_max_findings() -> i32 {
    50
}
fn default_report_max_evidence() -> i32 {
    1200
}
fn default_report_max_remediation() -> i32 {
    1200
}
fn default_scoring_critical() -> f64 {
    9.8
}
fn default_scoring_high() -> f64 {
    8.5
}
fn default_scoring_medium() -> f64 {
    5.5
}
fn default_scoring_low() -> f64 {
    2.5
}
fn default_scoring_info() -> f64 {
    0.0
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let _ = dotenvy::from_filename(".env.local");
        let _ = dotenvy::from_filename("../.env.local");
        let _ = dotenvy::dotenv();
        let config = Config::builder()
            .set_default("port", default_port())?
            .set_default("host", default_host())?
            // security_p0_3: production is the default. This was
            // `RUN_MODE == "development"`, so an unset RUN_MODE implied development
            // mode, which disabled the global rate limiter, disabled error
            // sanitization, and substituted a source-visible signing key.
            .set_default("debug", false)?
            .add_source(Environment::default())
            .build()?;

        let mut settings: Settings = config.try_deserialize()?;
        Self::validate(&mut settings)?;
        Ok(settings)
    }

    fn validate(settings: &mut Self) -> Result<(), ConfigError> {
        let insecure_dev_values = [
            "dev_secret_key_change_in_production_1234567890",
            "change_me",
            "changeme",
            "secret",
            "development",
            "local_dev_secret_key_change_me_1234567890",
            "local_dev_encryption_key_change_me_1234567890",
            // Was substituted as a development fallback before security_p0_3.
            "local_dev_secret_key_change_me_1234567890_DO_NOT_USE_IN_PRODUCTION",
            // Committed as the docker-compose default. security_p0_2. Any
            // environment that ever used it must treat it as compromised.
            "a7f3b8c29e4d5f6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a",
        ];

        // security_p0_3: secrets are required and validated in every mode. There
        // is deliberately no development fallback, so a missing key is a loud
        // startup failure rather than a silently substituted constant.
        if settings.secret_key.trim().is_empty() {
            return Err(ConfigError::Message(
                "SECRET_KEY is required. Generate one with: openssl rand -base64 48".into(),
            ));
        }
        if insecure_dev_values.contains(&settings.secret_key.as_str()) {
            return Err(ConfigError::Message(
                "SECRET_KEY is set to a known development or previously-committed value. \
                 Treat it as compromised and rotate it."
                    .into(),
            ));
        }
        if settings.secret_key.len() < 32 {
            return Err(ConfigError::Message(
                "SECRET_KEY must be at least 32 characters.".into(),
            ));
        }

        if settings.encryption_key.trim().is_empty() {
            return Err(ConfigError::Message(
                "ENCRYPTION_KEY is required. Generate one with: openssl rand -base64 48".into(),
            ));
        }
        if insecure_dev_values.contains(&settings.encryption_key.as_str())
            || settings.encryption_key.len() < 32
        {
            return Err(ConfigError::Message(
                "ENCRYPTION_KEY must be at least 32 characters and not a known development \
                 or previously-committed value."
                    .into(),
            ));
        }

        // A non-positive housekeeping interval would make
        // `tokio::time::interval` panic. The housekeeping task is spawned
        // without supervision, so that panic would be silent. Reject it at
        // startup instead of crashing a background task later.
        if settings.housekeeping_interval_seconds <= 0 {
            return Err(ConfigError::Message(format!(
                "housekeeping_interval_seconds must be greater than 0, got {}",
                settings.housekeeping_interval_seconds
            )));
        }

        // CRIT-02: SECRET_KEY and ENCRYPTION_KEY must never be identical.
        // Reusing one key for JWT signing AND data encryption collapses the
        // security boundary — compromising one key compromises both.
        if settings.encryption_key == settings.secret_key {
            return Err(ConfigError::Message(
                "SECRET_KEY and ENCRYPTION_KEY must be different values. Using the same \
                 value for both collapses crypto separation (CWE-326)."
                    .into(),
            ));
        }

        // Phase 19B.1: the GitHub App identity is all-or-nothing. Half an
        // identity (an ID with no key, or a key with no ID) fails startup
        // loudly instead of producing authentication failures at first use.
        // A key that is not an RSA private key PEM is rejected here too; the
        // mint path re-validates, so this is the early, actionable error.
        let app_id_set = settings.github_app_id != 0;
        let app_key_set = !settings.github_app_private_key.trim().is_empty();
        if app_id_set != app_key_set {
            return Err(ConfigError::Message(
                "GitHub App identity is incomplete: set both GITHUB_APP_ID and \
                 GITHUB_APP_PRIVATE_KEY, or neither to leave the App integration disabled."
                    .into(),
            ));
        }
        if app_key_set && !is_rsa_private_key_pem(&settings.github_app_private_key) {
            return Err(ConfigError::Message(
                "GITHUB_APP_PRIVATE_KEY is not an RSA private key PEM.".into(),
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
    for dir in [
        "workspace/reports",
        "workspace/temp",
        "workspace/storage",
        "workspace/scans",
    ] {
        std::fs::create_dir_all(base.join(dir))?;
    }
    Ok(())
}

/// Structural check that `value` is an RSA private key PEM.
///
/// Accepts PKCS#1 (`BEGIN RSA PRIVATE KEY`) and PKCS#8 (`BEGIN PRIVATE KEY`);
/// encrypted (`ENCRYPTED PRIVATE KEY`) and non-PEM values are refused. This
/// is the startup gate only — the mint path parses the key for real and would
/// refuse anything this check let through. Env-provided PEMs often carry
/// literal `\n` escapes instead of newlines; those are normalized first.
fn is_rsa_private_key_pem(value: &str) -> bool {
    normalize_pem(value)
        .map(|pem| pem.contains("BEGIN RSA PRIVATE KEY") || pem.contains("BEGIN PRIVATE KEY"))
        .unwrap_or(false)
}

/// Normalize an env-provided PEM: literal `\n` escapes become newlines when
/// the value has no real ones. Returns `None` when the body is not decodable
/// base64, so random strings fail the gate.
fn normalize_pem(value: &str) -> Option<String> {
    let mut text = value.trim().to_string();
    if !text.contains('\n') && text.contains("\\n") {
        text = text.replace("\\n", "\n");
    }
    if !(text.contains("-----BEGIN") && text.contains("-----END")) {
        return None;
    }
    // The body between the armor lines must be base64.
    let body: String = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .collect();
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &body)
        .ok()
        .map(|_| text)
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
        Some(VecOrString::String(s)) => Ok(s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()),
        None => Ok(Vec::new()),
    }
}

fn default_dodo_env() -> String {
    "test_mode".to_string()
}
