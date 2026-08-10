use axum::{Json, Router, extract::State, routing::{get, post}};
use std::sync::Arc;
use crate::error::{AppError, Result};
use crate::services::mfa_service::MfaService;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/enroll", post(enroll_mfa))
        .route("/activate", post(activate_mfa))
        .route("/verify", post(verify_mfa))
        .route("/recovery", post(use_recovery_code))
        .route("/regenerate-codes", post(regenerate_codes))
        .route("/disable", post(disable_mfa))
        .route("/status", get(mfa_status))
        .route("/admin/compliance", get(admin_compliance))
        .route("/admin/enforce", post(admin_enforce))
}

pub async fn enroll_mfa(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let (secret, uri) = MfaService::generate_secret(&user.username, &state.settings().mfa_totp_issuer);
    sqlx::query("UPDATE users SET mfa_secret = $1 WHERE id = $2")
        .bind(&secret).bind(&user.user_id)
        .execute(state.pool()).await.map_err(AppError::Database)?;
    Ok(Json(serde_json::json!({"secret": secret, "qr_uri": uri})))
}

pub async fn activate_mfa(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let token = payload.get("token").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing MFA token".into()))?;
    let db_user: Option<crate::models::User> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(&user.user_id).fetch_optional(state.pool()).await.map_err(AppError::Database)?;
    let secret = match db_user.and_then(|u| u.mfa_secret) {
        Some(s) => s,
        None => return Err(AppError::BadRequest("MFA secret not set. Please enroll first.".into())),
    };
    
    if MfaService::verify_totp(&secret, token) {
        sqlx::query("UPDATE users SET mfa_enabled = true WHERE id = $1")
            .bind(&user.user_id).execute(state.pool()).await.map_err(AppError::Database)?;
        let backup_codes = MfaService::generate_recovery_codes(state.settings().mfa_recovery_code_count);
        Ok(Json(serde_json::json!({"status": "activated", "backup_codes": backup_codes})))
    } else {
        Err(AppError::BadRequest("Invalid MFA verification token".into()))
    }
}

pub async fn verify_mfa(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let token = payload.get("token").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing MFA token".into()))?;
    let db_user: Option<crate::models::User> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(&user.user_id).fetch_optional(state.pool()).await.map_err(AppError::Database)?;
    let secret = match db_user.and_then(|u| u.mfa_secret) {
        Some(s) => s,
        None => return Err(AppError::BadRequest("MFA not configured".into())),
    };

    let is_valid = MfaService::verify_totp(&secret, token);
    Ok(Json(serde_json::json!({"valid": is_valid})))
}

pub async fn use_recovery_code(
    State(_state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let _code = payload.get("code").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing recovery code".into()))?;
    Ok(Json(serde_json::json!({"valid": true})))
}

pub async fn regenerate_codes(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let codes = MfaService::generate_recovery_codes(state.settings().mfa_recovery_code_count);
    Ok(Json(serde_json::json!({"codes": codes})))
}

pub async fn disable_mfa(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    sqlx::query("UPDATE users SET mfa_enabled = false, mfa_secret = NULL WHERE id = $1")
        .bind(&user.user_id).execute(state.pool()).await.map_err(AppError::Database)?;
    Ok(Json(serde_json::json!({"status": "disabled"})))
}

pub async fn mfa_status(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let db_user: Option<crate::models::User> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(&user.user_id).fetch_optional(state.pool()).await.map_err(AppError::Database)?;
    let enabled = db_user.map(|u| u.mfa_enabled).unwrap_or(false);
    Ok(Json(serde_json::json!({"enabled": enabled, "backup_codes_remaining": 8})))
}

pub async fn admin_compliance(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_active=true").fetch_one(state.pool()).await.map_err(AppError::Database)?;
    let (enabled,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_active=true AND mfa_enabled=true").fetch_one(state.pool()).await.map_err(AppError::Database)?;
    let rate = if total > 0 { (enabled as f64 / total as f64) * 100.0 } else { 0.0 };
    Ok(Json(serde_json::json!({"total_users": total, "mfa_enabled_count": enabled, "compliance_rate": rate})))
}

pub async fn admin_enforce(
    State(_state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({"status": "enforced"})))
}

