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
    #[serde(default)]
    pub frontend_url: String,
    #[serde(default = "default_backend_base_url")]
    pub backend_base_url: String,
    #[serde(default)]
    pub cors_origins: String,
    /// Comma-separated CIDRs or bare IPs of reverse proxies whose forwarding
    /// headers (`X-Forwarded-For`, `X-Real-IP`) may be trusted when
    /// attributing a client address for rate limiting and audit logging (F1).
    ///
    /// Empty — the default — trusts no proxy: every peer is treated as a
    /// direct client, so a spoofed header can never mint a fresh rate-limit
    /// bucket. Deployments behind a platform proxy (e.g. Render) must list
    /// the proxy's addresses here explicitly; private and loopback ranges are
    /// never trusted implicitly. Malformed values fail startup.
    #[serde(default)]
    pub trusted_proxy_cidrs: String,
    pub database_url: String,
    #[serde(default = "default_pool_size")]
    pub database_pool_size: u32,
    #[serde(default)]
    pub redis_url: String,
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
    #[serde(default = "default_samesite_strict")]
    pub auth_cookie_samesite: String,
    #[serde(default = "default_true")]
    pub csrf_enabled: bool,
    #[serde(default = "default_mfa_issuer")]
    pub mfa_totp_issuer: String,
    #[serde(default = "default_mfa_recovery_codes")]
    pub mfa_recovery_code_count: i32,
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
    #[serde(default)]
    pub resend_api_key: String,
    /// Sender address for the Resend transport (`RESEND_FROM_EMAIL`).
    ///
    /// Falls back to `sender_email` when empty, so one verified sender identity
    /// can serve both transports. FC-OPS-EMAIL-001.
    #[serde(default)]
    pub resend_from_email: String,
    #[serde(default)]
    pub sender_email: String,
    /// Resend webhook signing secret, used to verify delivery webhook events
    /// (`delivered` / `bounced` / `complained`). Optional: unset means webhook
    /// delivery tracking is disabled and the webhook route returns 501.
    #[serde(default)]
    pub resend_webhook_secret: String,
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
    #[serde(default = "default_gemini_max_prompt_chars")]
    pub gemini_max_prompt_chars: i32,
    #[serde(default = "default_max_active_jobs")]
    pub max_active_jobs_per_user: i32,
    /// Filtering proxy the OSV scanner must egress through (same operator
    /// knob as `OSV_EGRESS_PROXY`; the prefix-less environment source maps
    /// that variable here). Since V3 the dependency scan refuses to run
    /// without a valid value — unfettered bridge egress stays disabled
    /// rather than silently allowed.
    #[serde(default)]
    pub osv_egress_proxy: Option<String>,
    #[serde(default = "default_housekeeping_interval")]
    pub housekeeping_interval_seconds: i64,
    #[serde(default = "default_max_request_body")]
    pub max_request_body_bytes: i64,
    #[serde(default = "default_max_json_body")]
    pub max_json_body_bytes: i64,
    #[serde(default)]
    pub privacy_policy_version: String,
    #[serde(default)]
    pub terms_version: String,
    /// Scanner execution backend: `"container"` (Docker daemon, full
    /// isolation) or `"native"` (direct subprocesses, reduced isolation,
    /// opt-in). Validated fail-closed at startup; `ExecutionMode::resolve`
    /// defaults anything unset to the strongest boundary (`container`).
    #[serde(default = "default_scanner_execution_mode")]
    pub scanner_execution_mode: String,
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
            .field("trusted_proxy_cidrs", &self.trusted_proxy_cidrs)
            .field("database_url", &HIDDEN)
            .field("database_pool_size", &self.database_pool_size)
            .field("redis_url", &HIDDEN)
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
            .field("auth_cookie_samesite", &self.auth_cookie_samesite)
            .field("csrf_enabled", &self.csrf_enabled)
            .field("mfa_totp_issuer", &self.mfa_totp_issuer)
            .field("mfa_recovery_code_count", &self.mfa_recovery_code_count)
            .field("github_client_id", &self.github_client_id)
            .field("github_client_secret", &HIDDEN)
            .field("github_token", &HIDDEN)
            .field("github_app_id", &self.github_app_id)
            .field("github_app_private_key", &HIDDEN)
            .field("github_app_webhook_secret", &HIDDEN)
            .field("resend_api_key", &HIDDEN)
            .field("resend_from_email", &self.resend_from_email)
            .field("sender_email", &self.sender_email)
            .field("resend_webhook_secret", &HIDDEN)
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
            .field("gemini_max_prompt_chars", &self.gemini_max_prompt_chars)
            .field("max_active_jobs_per_user", &self.max_active_jobs_per_user)
            .field("osv_egress_proxy", &self.osv_egress_proxy)
            .field(
                "housekeeping_interval_seconds",
                &self.housekeeping_interval_seconds,
            )
            .field("max_request_body_bytes", &self.max_request_body_bytes)
            .field("max_json_body_bytes", &self.max_json_body_bytes)
            .field("privacy_policy_version", &self.privacy_policy_version)
            .field("terms_version", &self.terms_version)
            .field("scanner_execution_mode", &self.scanner_execution_mode)
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
    25
}
fn default_true() -> bool {
    true
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
    // FC-AUTH-02 fix: Was 60 * 24 = 1440 minutes (24 hours), reduced to 15 minutes.
    // Long-lived access tokens stay valid even after logout if Redis is unavailable.
    // 15 minutes is the standard industry practice for short-lived access tokens
    // paired with longer-lived refresh tokens.
    15
}
fn default_auth_cookie_name() -> String {
    "fc_access_token".into()
}
fn default_samesite_strict() -> String {
    "strict".into()
}
fn default_mfa_issuer() -> String {
    "Fire Crow".into()
}
fn default_mfa_recovery_codes() -> i32 {
    8
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
fn default_gemini_max_prompt_chars() -> i32 {
    100_000
}
fn default_max_active_jobs() -> i32 {
    2
}
fn default_scanner_execution_mode() -> String {
    // Safe default: the container boundary. `native` requires an explicit,
    // validated opt-in — it is never the implicit choice.
    "container".into()
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
impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        if std::env::var("FIRECROW_SKIP_DOTENV").is_err() {
            let _ = dotenvy::from_filename(".env.local");
            let _ = dotenvy::from_filename("../.env.local");
            let _ = dotenvy::dotenv();
        }
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

        // The scanner execution mode must be a recognized value. An unknown
        // string is a typo that would otherwise silently fall back to the
        // container path while the operator believes they enabled native mode
        // (or vice versa). Reject it at startup so the deployment's actual
        // isolation boundary is never ambiguous.
        {
            let mode = settings.scanner_execution_mode.trim();
            if mode != "container" && mode != "native" {
                return Err(ConfigError::Message(format!(
                    "SCANNER_EXECUTION_MODE must be \"container\" or \"native\", got {:?}",
                    settings.scanner_execution_mode
                )));
            }
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

        // FC-OPS-EMAIL-001: a Resend key with no sender address anywhere fails
        // startup loudly instead of surfacing at first delivery. SMTP stays the
        // fallback transport when no Resend key is configured.
        if !settings.resend_api_key.trim().is_empty()
            && settings.resend_from_email.trim().is_empty()
            && settings.sender_email.trim().is_empty()
        {
            return Err(ConfigError::Message(
                "RESEND_API_KEY is set but no sender address is configured: set \
                 RESEND_FROM_EMAIL (or SENDER_EMAIL), or unset RESEND_API_KEY."
                    .into(),
            ));
        }

        // Render and containerized deployments fail closed/timeout if bound to loopback (127.0.0.1).
        // If an operator accidentally sets HOST=127.0.0.1 in the Render dashboard (e.g. copied from .env.local),
        // override it to 0.0.0.0 so Render's port detection and reverse proxy can connect.
        if (std::env::var("RENDER").is_ok()
            || std::env::var("CONTAINER").is_ok()
            || std::path::Path::new("/.dockerenv").exists())
            && (settings.host == "127.0.0.1" || settings.host == "localhost")
        {
            tracing::warn!(
                "Container or Render environment detected with loopback HOST='{}'. \
                 Overriding host to '0.0.0.0' so Render port scanner and load balancer can connect.",
                settings.host
            );
            settings.host = "0.0.0.0".into();
        }

        // Auto-adopt Render's public service URL for OAuth callbacks if BACKEND_BASE_URL was omitted.
        if settings.backend_base_url.is_empty()
            || settings.backend_base_url == "http://localhost:8000"
        {
            if let Ok(render_url) = std::env::var("RENDER_EXTERNAL_URL") {
                if !render_url.trim().is_empty() {
                    tracing::info!(
                        "Using RENDER_EXTERNAL_URL as backend_base_url: {}",
                        render_url
                    );
                    settings.backend_base_url = render_url.trim().trim_end_matches('/').to_string();
                }
            }
        }

        // In cross-origin deployments (e.g. Vercel frontend on vercel.app and Render backend on onrender.com),
        // default SameSite=Strict blocks cookies in modern browsers for cross-origin fetch/credentials requests.
        // If AUTH_COOKIE_SAMESITE was not explicitly configured in the environment, auto-promote to "none"
        // and ensure auth_cookie_secure=true so browser sends credentials across origins.
        if std::env::var("AUTH_COOKIE_SAMESITE").is_err() {
            let is_cross_origin = !settings.frontend_url.is_empty()
                && settings.frontend_url.trim_end_matches('/')
                    != settings.backend_base_url.trim_end_matches('/');
            if is_cross_origin || std::env::var("RENDER").is_ok() {
                tracing::info!(
                    "Cross-origin or cloud environment detected (frontend: '{}', backend: '{}'). Defaulting auth_cookie_samesite to 'none' and auth_cookie_secure to true.",
                    settings.frontend_url,
                    settings.backend_base_url
                );
                settings.auth_cookie_samesite = "none".into();
                settings.auth_cookie_secure = true;
            }
        }

        // F1: client-IP attribution is only as trustworthy as the proxy list
        // behind it. A malformed TRUSTED_PROXY_CIDRS must fail loudly at
        // startup instead of silently degrading to "trust nobody" — which
        // would put every user behind the proxy into one shared rate-limit
        // bucket, or worse, tempt an operator to "fix" it by trusting
        // arbitrary private ranges.
        let trusted_proxies = match crate::middleware::cloudflare::parse_trusted_proxy_cidrs(
            &settings.trusted_proxy_cidrs,
        ) {
            Err(e) => return Err(ConfigError::Message(e)),
            Ok(proxies) => proxies,
        };

        // P1-B (ZT-06-7): on Render the platform ingress IP is not published
        // as a stable CIDR list, so a fresh deployment ships with an empty
        // TRUSTED_PROXY_CIDRS. That default is safe (forwarding headers are
        // ignored, so rate-limit buckets key on the shared ingress IP —
        // coarse for every user, but spoof-proof), yet it is easy to miss and
        // operators may be tempted to "fix" it by trusting arbitrary ranges.
        // Warn once; set the list from Render's authoritative docs — do not
        // guess CIDRs here.
        if trusted_proxies.is_empty()
            && (std::env::var("RENDER").is_ok() || std::env::var("RENDER_EXTERNAL_URL").is_ok())
        {
            tracing::warn!(
                "TRUSTED_PROXY_CIDRS is empty on Render: rate-limit buckets will be keyed by the \
                 shared ingress IP (coarse but spoof-proof). Set TRUSTED_PROXY_CIDRS from Render's \
                 authoritative proxy-CIDR documentation to restore per-client buckets."
            );
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

fn default_dodo_env() -> String {
    "test_mode".to_string()
}

// Phase 24: platform-port contract. Render injects PORT at runtime; the
// service must listen wherever the platform says (config crate Environment
// source, no prefix, layered over the 8000 default), defaulting to 8000
// locally. These tests replay that exact layering with isolated builders —
// no process-env mutation, no dotenv files, no secrets — plus static guards
// over the two files that caused the Phase 23 contradiction.
#[cfg(test)]
mod port_contract_tests {
    use super::Settings;

    /// Deserialize Settings the way `Settings::new()` does: defaults first,
    /// then one environment layer on top. `injected_port` stands in for the
    /// platform's PORT injection; `None` is a local run with no injection.
    fn settings_from_env(injected_port: Option<&str>) -> Settings {
        let mut builder = config::Config::builder()
            .set_default("port", super::default_port())
            .expect("port default")
            .set_default("host", super::default_host())
            .expect("host default")
            // Required string fields with no serde defaults: dummy values only.
            // They are irrelevant to the port contract; `validate()` is never
            // called here, so they carry no semantic weight.
            .set_default("secret_key", "port-contract-dummy")
            .expect("secret default")
            .set_default("encryption_key", "port-contract-dummy")
            .expect("encryption default")
            .set_default("frontend_url", "http://localhost:3000")
            .expect("frontend default")
            .set_default("cors_origins", "http://localhost:3000")
            .expect("cors default")
            .set_default("database_url", "postgres://localhost/firecrow")
            .expect("db default");
        if let Some(v) = injected_port {
            // Same precedence position as the Environment source in
            // `Settings::new()`: an override beats the default, exactly as a
            // platform-injected PORT beats the compiled-in 8000.
            builder = builder.set_override("port", v).expect("port override");
        }
        let s: Settings = builder
            .build()
            .expect("config builds")
            .try_deserialize()
            .expect("port/host deserialize");
        s
    }

    #[test]
    fn port_defaults_to_8000_without_platform_injection() {
        let s = settings_from_env(None);
        assert_eq!(s.port, 8000, "local default must stay 8000");
        assert_eq!(s.host, "0.0.0.0", "bind must be externally reachable");
    }

    #[test]
    fn platform_injected_port_wins_over_the_default() {
        let s = settings_from_env(Some("10000"));
        assert_eq!(
            s.port, 10000,
            "platform PORT must be honored, not the default"
        );
    }

    #[test]
    fn render_yaml_must_not_pin_a_conflicting_port() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../render.yaml"))
            .expect("render.yaml must be readable");
        assert!(
            !text.lines().any(|l| l.trim_start().starts_with("- key: PORT")),
            "render.yaml must not pin PORT: Render injects it and a pinned value fights the platform"
        );
    }

    /// Every env key `render.yaml` sets must actually be read by the backend.
    ///
    /// The `config` crate's prefix-less Environment source maps `CORS_ORIGINS`
    /// onto the `cors_origins` field and **silently ignores** any key that maps
    /// to nothing. A typo or a field rename therefore leaves the variable set
    /// but inert — CORS off, cookie flags wrong, rate limiting unconfigured —
    /// with no error anywhere. Assert the contract rather than trusting the two
    /// files to stay in step by hand.
    #[test]
    fn every_render_yaml_env_key_is_read_by_the_backend() {
        // Read directly via std::env, not through Settings.
        const DIRECT_ENV: &[&str] = &[
            "DOCKER_HOST",
            "SCANNER_EXECUTION_MODE",
            "GITLEAKS_BIN",
            "OSV_SCANNER_BIN",
            "SEMGREP_BIN",
        ];

        let manifest = env!("CARGO_MANIFEST_DIR");
        let render = std::fs::read_to_string(format!("{manifest}/../render.yaml"))
            .expect("render.yaml must be readable");
        let source = std::fs::read_to_string(format!("{manifest}/src/config.rs"))
            .expect("config.rs must be readable");

        // Field names are the env names, lowercased: `cors_origins` <- CORS_ORIGINS.
        let known: std::collections::HashSet<String> = source
            .lines()
            .filter_map(|l| l.trim().strip_prefix("pub "))
            .filter_map(|rest| rest.split(':').next())
            .map(|field| field.trim().to_uppercase())
            .collect();

        let mut checked = 0;
        for line in render.lines() {
            let Some(rest) = line.trim().strip_prefix("- key: ") else {
                continue;
            };
            let key = rest.trim();
            checked += 1;
            assert!(
                known.contains(key) || DIRECT_ENV.contains(&key),
                "render.yaml sets {key}, but nothing in Settings or std::env reads it — \
                 the variable would be set and silently ignored"
            );
        }
        assert!(
            checked >= 10,
            "expected render.yaml to declare its env keys, found {checked}"
        );
    }

    #[test]
    fn docker_healthcheck_must_follow_the_runtime_port() {
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Dockerfile"))
            .expect("Dockerfile must be readable");
        let probe = text
            .lines()
            .find(|l| l.trim_start().starts_with("CMD") && l.contains("/health"))
            .expect("Dockerfile needs a /health probe");
        assert!(
            probe.contains("${PORT"),
            "healthcheck must expand $PORT at runtime, not hardcode a port: {probe}"
        );
        assert!(
            !probe.contains("localhost:8000/health"),
            "healthcheck must not hardcode :8000: {probe}"
        );
    }
}
