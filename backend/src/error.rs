//! Centralized error types for the Fire Crow backend.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Error, Debug)]
pub enum AppError {
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
    #[error("HTTP client error: {0}")]
    HttpClientError(String),
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
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AppError::InvalidCredentials
            | AppError::TokenExpired
            | AppError::InvalidToken
            | AppError::TokenRevoked
            | AppError::AccountLocked => StatusCode::UNAUTHORIZED,
            AppError::MfaRequired | AppError::MfaVerificationFailed => StatusCode::FORBIDDEN,
            AppError::Database(_) | AppError::MigrationError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::GraphDatabase(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::StorageError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::RedisError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::EmailError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::LlmError(_) => StatusCode::BAD_GATEWAY,
            AppError::HttpClientError(_) => StatusCode::BAD_GATEWAY,
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
            AppError::HttpClientError(_) => "Internal HTTP client error".into(),
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
        // In dev, expose the real error message so we can debug
        let detail = self.to_string();
        if self.is_internal() {
            tracing::error!(error = %detail, "Internal error");
        }
        let body = Json(json!({ "detail": detail }));
        (status, body).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self { AppError::Internal(err.to_string()) }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self { AppError::Internal(format!("JSON error: {err}")) }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self { AppError::HttpClientError(err.to_string()) }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self { AppError::RedisError(err.to_string()) }
}

impl From<lettre::error::Error> for AppError {
    fn from(err: lettre::error::Error) -> Self { AppError::EmailError(err.to_string()) }
}

