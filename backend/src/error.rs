//! Centralized error types for the Fire Crow backend.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

/// Why an AI narrative could not be produced.
///
/// The provider's failure classes are kept distinct rather than collapsed into
/// one "LLM error", because the operator action differs for each: a rejected
/// credential is a configuration fix, a rate limit is a wait, an unreachable
/// provider is an incident, and an oversized response is a limit change.
/// Collapsing them would make an AI outage undiagnosable.
///
/// Every message here is fixed text written by Fire Crow. Provider response
/// bodies are never interpolated into an error, because they can echo the
/// prompt, internal diagnostics, or request identifiers back to the caller.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum GenerationError {
    #[error("AI narrative generation is not configured (missing provider credential or model)")]
    NotConfigured,
    #[error("AI provider rejected the configured credential")]
    Authentication,
    #[error("AI provider denied access for the configured credential")]
    Authorization,
    #[error("AI provider rejected the request as invalid")]
    InvalidRequest,
    #[error("AI provider rate limit exceeded")]
    RateLimited,
    #[error("AI provider unavailable")]
    Unavailable,
    #[error("AI provider request timed out")]
    Timeout,
    #[error("AI provider response exceeded {cap_bytes} bytes")]
    ResponseTooLarge { cap_bytes: usize },
    #[error("AI provider connection failed")]
    Transport,
    #[error("AI provider returned a response with no usable model text")]
    Malformed,
}

impl GenerationError {
    /// Log-safe class name. Used for observability instead of the message, so a
    /// failure is diagnosable without retaining provider or model content.
    pub fn category(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Authentication => "provider_authentication",
            Self::Authorization => "provider_authorization",
            Self::InvalidRequest => "provider_invalid_request",
            Self::RateLimited => "provider_rate_limited",
            Self::Unavailable => "provider_unavailable",
            Self::Timeout => "provider_timeout",
            Self::ResponseTooLarge { .. } => "provider_response_too_large",
            Self::Transport => "provider_transport",
            Self::Malformed => "provider_malformed_response",
        }
    }

    /// Whether retrying the same request could plausibly succeed.
    ///
    /// Only genuinely transient conditions qualify. A rejected credential, a
    /// malformed request, and a model-output validation failure never do, and
    /// retrying them would amplify load without any chance of a different
    /// outcome.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::RateLimited | Self::Unavailable)
    }
}

/// Why an email could not be delivered.
///
/// SMTP replies are classified rather than flattened, because the caller and the
/// operator need to tell a rejected credential from an invalid recipient from a
/// temporary congestion. Like [`GenerationError`], every message is fixed text
/// written by Fire Crow: an SMTP server's reply can echo addresses and internal
/// diagnostics, and that never reaches a caller.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
    #[error("Email delivery is not configured on this server")]
    NotConfigured,
    #[error("Email recipient address is not a valid address")]
    InvalidRecipient,
    #[error("Email provider rejected the configured credential")]
    Authentication,
    #[error("Email provider rejected the recipient")]
    RecipientRejected,
    #[error("Email provider rate limited the request")]
    RateLimited,
    #[error("Email provider unavailable")]
    Unavailable,
    #[error("Email delivery timed out")]
    Timeout,
    #[error("Email provider connection failed")]
    Transport,
    #[error("Email provider returned an unexpected response")]
    Malformed,
    /// A provider response exceeded the configured ceiling.
    ///
    /// Rejected, never truncated: half a provider response is not a delivery, and
    /// for a report artifact it would risk a reader seeing a summary that silently
    /// omits findings.
    #[error("Delivery provider response exceeded {cap_bytes} bytes")]
    ResponseTooLarge { cap_bytes: usize },
}

impl DeliveryError {
    /// Log-safe class name for delivery observability.
    pub fn category(&self) -> &'static str {
        match self {
            // Channel-neutral on purpose. These classes are recorded on the
            // delivery row next to its `channel`, so an SMTP-prefixed name on a
            // Telegram delivery would point an incident responder at the wrong
            // provider.
            Self::NotConfigured => "not_configured",
            Self::InvalidRecipient => "destination_invalid",
            Self::Authentication => "provider_authentication",
            Self::RecipientRejected => "destination_rejected",
            Self::RateLimited => "provider_rate_limited",
            Self::Unavailable => "provider_unavailable",
            Self::Timeout => "provider_timeout",
            Self::Transport => "provider_transport",
            Self::Malformed => "provider_malformed_response",
            Self::ResponseTooLarge { .. } => "provider_response_too_large",
        }
    }

    /// Whether retrying could plausibly succeed.
    ///
    /// Congestion and rate limiting only. A rejected credential, an invalid
    /// recipient, and a permanent rejection are the operator's problem, and
    /// retrying them would amplify a misconfiguration into load.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::RateLimited | Self::Unavailable)
    }
}

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Email delivery failed: {0}")]
    Delivery(#[from] DeliveryError),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Cancelled: {0}")]
    Cancelled(String),
    #[error("Payload too large")]
    PayloadTooLarge,
    #[error("Rate limit exceeded")]
    RateLimited,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Token revoked")]
    TokenRevoked,
    #[error("Account locked due to too many failed attempts")]
    AccountLocked,
    #[error("MFA required")]
    MfaRequired,
    #[error("MFA verification failed")]
    MfaVerificationFailed,
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Migration error: {0}")]
    MigrationError(String),
    #[error("Graph database error: {0}")]
    GraphDatabase(String),
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Redis error: {0}")]
    RedisError(String),
    #[error("Email error: {0}")]
    EmailError(String),
    #[error("LLM error: {0}")]
    LlmError(String),
    /// An AI narrative could not be generated. Never a scanner, audit, or
    /// coverage failure: the deterministic audit is already committed and
    /// stays exactly as it was.
    #[error("AI generation failed: {0}")]
    Generation(#[from] GenerationError),
    #[error("HTTP client error: {0}")]
    HttpClientError(String),
    /// A bounded operation exceeded its wall-clock ceiling.
    ///
    /// Distinct from [`AppError::Internal`] so a scanner timeout can be
    /// reported as `TIMEOUT` rather than a generic failure. It must never be
    /// downgraded to "no findings": see `agents::scanner`.
    #[error("Operation timed out: {0}")]
    Timeout(String),
    /// A sandboxed process exceeded its stdout/stderr ceiling.
    ///
    /// A scanner that floods its output is truncated as unknown coverage, not
    /// accepted: reporting it as a scan result would let a hostile repository
    /// dictate how much worker memory the backend consumes.
    #[error("Output limit exceeded on {stream} (cap {cap_bytes} bytes)")]
    OutputLimitExceeded { stream: String, cap_bytes: usize },
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Internal server error: {0}")]
    Internal(String),
    #[error("Service unavailable: {0}")]
    Unavailable(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

impl AppError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            // A cancelled fetch never surfaces as a failure: the worker asked
            // for it to stop. 409 keeps it distinct from 4xx client errors.
            AppError::Cancelled(_) => StatusCode::CONFLICT,
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AppError::InvalidCredentials
            | AppError::TokenExpired
            | AppError::InvalidToken
            | AppError::TokenRevoked
            | AppError::AccountLocked => StatusCode::UNAUTHORIZED,
            AppError::MfaRequired | AppError::MfaVerificationFailed => StatusCode::FORBIDDEN,
            AppError::Database(_) | AppError::MigrationError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AppError::GraphDatabase(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::RedisError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::EmailError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::LlmError(_) => StatusCode::BAD_GATEWAY,
            AppError::Delivery(error) => match error {
                // A delivery failure is never an audit failure, so it is never
                // reported as one: the audit itself is complete and valid.
                DeliveryError::NotConfigured => StatusCode::NOT_IMPLEMENTED,
                DeliveryError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
                DeliveryError::Timeout => StatusCode::GATEWAY_TIMEOUT,
                DeliveryError::InvalidRecipient => StatusCode::BAD_REQUEST,
                _ => StatusCode::BAD_GATEWAY,
            },
            AppError::Generation(error) => match error {
                // The AI layer is an optional dependency: unavailable
                // configuration is a service problem, not a client one.
                GenerationError::NotConfigured => StatusCode::SERVICE_UNAVAILABLE,
                GenerationError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
                GenerationError::Timeout => StatusCode::GATEWAY_TIMEOUT,
                _ => StatusCode::BAD_GATEWAY,
            },
            AppError::HttpClientError(_) => StatusCode::BAD_GATEWAY,
            AppError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            AppError::OutputLimitExceeded { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::ValidationError(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AppError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
        }
    }

    pub fn is_internal(&self) -> bool {
        matches!(
            self,
            AppError::Database(_)
                | AppError::GraphDatabase(_)
                | AppError::Internal(_)
                | AppError::StorageError(_)
                | AppError::RedisError(_)
                | AppError::EmailError(_)
                | AppError::MigrationError(_)
        )
    }

    pub fn safe_message(&self, debug: bool) -> String {
        if debug {
            return self.to_string();
        }
        match self {
            AppError::BadRequest(msg) => msg.clone(),
            AppError::Unauthorized(msg) => msg.clone(),
            AppError::Forbidden(msg) => msg.clone(),
            AppError::NotFound(msg) => msg.clone(),
            AppError::Conflict(msg) => msg.clone(),
            AppError::Cancelled(msg) => msg.clone(),
            AppError::PayloadTooLarge => "Payload too large".into(),
            AppError::RateLimited => "Rate limit exceeded".into(),
            AppError::InvalidCredentials => "Invalid credentials".into(),
            AppError::TokenExpired => "Token expired".into(),
            AppError::InvalidToken => "Invalid token".into(),
            AppError::TokenRevoked => "Token revoked".into(),
            AppError::AccountLocked => "Account locked due to too many failed attempts".into(),
            AppError::MfaRequired => "MFA required".into(),
            AppError::MfaVerificationFailed => "MFA verification failed".into(),
            AppError::Database(_) => "Internal database error".into(),
            AppError::MigrationError(_) => "Internal migration error".into(),
            AppError::GraphDatabase(_) => "Internal graph database error".into(),
            AppError::StorageError(_) => "Internal storage error".into(),
            AppError::RedisError(_) => "Internal cache error".into(),
            AppError::EmailError(_) => "Internal email error".into(),
            AppError::LlmError(_) => "Internal LLM error".into(),
            // Fixed text only; the SMTP reply is never forwarded.
            AppError::Delivery(error) => error.to_string(),
            // The message is Fire Crow's own fixed text, never a provider body.
            AppError::Generation(error) => error.to_string(),
            AppError::HttpClientError(_) => "Internal HTTP client error".into(),
            AppError::Timeout(msg) => msg.clone(),
            AppError::OutputLimitExceeded { stream, cap_bytes } => {
                format!("Sandbox output limit exceeded on {stream} (cap {cap_bytes} bytes)")
            }
            AppError::ValidationError(msg) => msg.clone(),
            AppError::Internal(_) => "Internal server error".into(),
            AppError::Unavailable(msg) => msg.clone(),
            AppError::NotImplemented(_) => "Not implemented".into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let is_debug = std::env::var("APP_DEBUG")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        let detail = self.safe_message(is_debug);
        if self.is_internal() {
            tracing::error!(status = %status, error = %self, "Internal server error encountered");
        }
        let body = Json(json!({ "detail": detail }));
        (status, body).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Internal(format!("JSON error: {err}"))
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        AppError::HttpClientError(err.to_string())
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        AppError::RedisError(err.to_string())
    }
}

impl From<lettre::error::Error> for AppError {
    fn from(err: lettre::error::Error) -> Self {
        AppError::EmailError(err.to_string())
    }
}
