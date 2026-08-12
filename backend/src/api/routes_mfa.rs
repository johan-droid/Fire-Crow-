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
    // CRIT-07: the MFA secret must be stored encrypted, never in plaintext.
    let encrypted_secret = state.crypto().encrypt_secret(&secret)?;
    sqlx::query("UPDATE users SET mfa_secret = $1 WHERE id = $2")
        .bind(&encrypted_secret)
        .bind(&user.user_id)
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
    let encrypted = db_user.and_then(|u| u.mfa_secret).ok_or_else(|| AppError::BadRequest("MFA secret not set. Please enroll first.".into()))?;
    let secret = state.crypto().decrypt_secret(&encrypted)?;

    if MfaService::verify_totp(&secret, token) {
        sqlx::query("UPDATE users SET mfa_enabled = true WHERE id = $1")
            .bind(&user.user_id).execute(state.pool()).await.map_err(AppError::Database)?;

        // Persist an MFA configuration + hashed recovery codes so they can
        // actually be used later. Previously they were generated but never stored.
        let config_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO mfa_configurations (id, user_id, enabled, secret, backup_codes_consumed, created_at) \
             VALUES ($1, $2, true, $3, 0, $4) \
             ON CONFLICT (user_id) DO UPDATE SET enabled = true, secret = EXCLUDED.secret")
            .bind(&config_id)
            .bind(&user.user_id)
            .bind(&encrypted)
            .bind(chrono::Utc::now().naive_utc())
            .execute(state.pool()).await.map_err(AppError::Database)?;

        let (codes, code_hashes) = MfaService::generate_recovery_codes(state.settings().mfa_recovery_code_count);
        persist_recovery_codes(state.pool(), &config_id, &code_hashes).await?;

        Ok(Json(serde_json::json!({"status": "activated", "backup_codes": codes})))
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
    let encrypted = db_user.and_then(|u| u.mfa_secret).ok_or_else(|| AppError::BadRequest("MFA not configured".into()))?;
    let secret = state.crypto().decrypt_secret(&encrypted)?;

    let is_valid = MfaService::verify_totp(&secret, token);
    Ok(Json(serde_json::json!({"valid": is_valid})))
}

pub async fn use_recovery_code(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let code = payload.get("code").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing recovery code".into()))?;

    // HIGH-09: enforce a 5-failure / 10-minute lockout on recovery code guesses.
    let rl_key = format!("mfa_recovery:{}", user.user_id);
    if crate::services::auth::check_login_lockout(state.pool(), &rl_key, 10, 5).await? {
        return Err(AppError::RateLimited);
    }

    let mfa_config: Option<crate::models::MfaConfiguration> = sqlx::query_as("SELECT * FROM mfa_configurations WHERE user_id = $1")
        .bind(&user.user_id)
        .fetch_optional(state.pool())
        .await
        .map_err(AppError::Database)?;

    let mfa_config = mfa_config.ok_or_else(|| AppError::BadRequest("MFA not configured".into()))?;

    let recovery_codes: Vec<crate::models::MfaRecoveryCode> = sqlx::query_as("SELECT * FROM mfa_recovery_codes WHERE mfa_config_id = $1 AND used_at IS NULL")
        .bind(&mfa_config.id)
        .fetch_all(state.pool())
        .await
        .map_err(AppError::Database)?;

    if recovery_codes.is_empty() {
        return Err(AppError::BadRequest("No recovery codes available".into()));
    }

    let code_hash = crate::services::mfa_service::MfaService::hash_recovery_code(code);
    let mut valid_code = None;
    for rc in &recovery_codes {
        if rc.code_hash == code_hash {
            valid_code = Some(rc);
            break;
        }
    }

    if let Some(valid_rc) = valid_code {
        crate::services::auth::clear_login_failures(state.pool(), &rl_key).await?;
        sqlx::query("UPDATE mfa_recovery_codes SET used_at = NOW() WHERE id = $1")
            .bind(&valid_rc.id)
            .execute(state.pool())
            .await
            .map_err(AppError::Database)?;

        let _ = sqlx::query("UPDATE mfa_configurations SET backup_codes_consumed = $1 WHERE id = $2")
            .bind(mfa_config.backup_codes_consumed + 1)
            .bind(&mfa_config.id)
            .execute(state.pool())
            .await
            .map_err(AppError::Database)?;

        Ok(Json(serde_json::json!({"valid": true, "message": "Recovery code used successfully"})))
    } else {
        let _ = crate::services::auth::record_login_failure(state.pool(), &rl_key).await;
        Err(AppError::BadRequest("Invalid recovery code".into()))
    }
}

pub async fn regenerate_codes(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let mfa_config: Option<crate::models::MfaConfiguration> = sqlx::query_as("SELECT * FROM mfa_configurations WHERE user_id = $1")
        .bind(&user.user_id)
        .fetch_optional(state.pool())
        .await
        .map_err(AppError::Database)?;
    let mfa_config = mfa_config.ok_or_else(|| AppError::BadRequest("MFA not configured".into()))?;

    let (codes, code_hashes) = MfaService::generate_recovery_codes(state.settings().mfa_recovery_code_count);
    // Invalidate old codes and persist the new hashes (was: returned codes, never stored).
    sqlx::query("DELETE FROM mfa_recovery_codes WHERE mfa_config_id = $1")
        .bind(&mfa_config.id)
        .execute(state.pool()).await.map_err(AppError::Database)?;
    persist_recovery_codes(state.pool(), &mfa_config.id, &code_hashes).await?;

    Ok(Json(serde_json::json!({"codes": codes})))
}

pub async fn disable_mfa(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    sqlx::query("UPDATE users SET mfa_enabled = false, mfa_secret = NULL WHERE id = $1")
        .bind(&user.user_id).execute(state.pool()).await.map_err(AppError::Database)?;
    if let Some(cfg) = sqlx::query_as::<_, crate::models::MfaConfiguration>("SELECT * FROM mfa_configurations WHERE user_id = $1")
        .bind(&user.user_id).fetch_optional(state.pool()).await
        .map_err(AppError::Database)?
    {
        let _ = sqlx::query("DELETE FROM mfa_recovery_codes WHERE mfa_config_id = $1").bind(&cfg.id).execute(state.pool()).await;
        let _ = sqlx::query("DELETE FROM mfa_configurations WHERE id = $1").bind(&cfg.id).execute(state.pool()).await;
    }
    Ok(Json(serde_json::json!({"status": "disabled"})))
}

pub async fn mfa_status(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let db_user: Option<crate::models::User> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(&user.user_id).fetch_optional(state.pool()).await.map_err(AppError::Database)?;
    let enabled = db_user.map(|u| u.mfa_enabled).unwrap_or(false);
    // Report the real number of unused recovery codes (was hardcoded to 8).
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mfa_recovery_codes rc \
         JOIN mfa_configurations cfg ON rc.mfa_config_id = cfg.id \
         WHERE cfg.user_id = $1 AND rc.used_at IS NULL")
        .bind(&user.user_id)
        .fetch_one(state.pool()).await
        .map_err(AppError::Database)?;
    Ok(Json(serde_json::json!({"enabled": enabled, "backup_codes_remaining": remaining})))
}

pub async fn admin_compliance(
    State(state): State<Arc<crate::AppState>>,
    _admin: crate::middleware::auth::AdminUser,
) -> Result<Json<serde_json::Value>> {
    let (total,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_active=true").fetch_one(state.pool()).await.map_err(AppError::Database)?;
    let (enabled,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE is_active=true AND mfa_enabled=true").fetch_one(state.pool()).await.map_err(AppError::Database)?;
    let rate = if total > 0 { (enabled as f64 / total as f64) * 100.0 } else { 0.0 };
    Ok(Json(serde_json::json!({"total_users": total, "mfa_enabled_count": enabled, "compliance_rate": rate})))
}

pub async fn admin_enforce(
    State(state): State<Arc<crate::AppState>>,
    _admin: crate::middleware::auth::AdminUser,
) -> Result<Json<serde_json::Value>> {
    // Actually enforce MFA for all active users rather than being a no-op.
    let affected = sqlx::query("UPDATE users SET mfa_enforced = true WHERE is_active = true")
        .execute(state.pool()).await.map_err(AppError::Database)?;
    Ok(Json(serde_json::json!({"status": "enforced", "users_affected": affected.rows_affected()})))
}

async fn persist_recovery_codes(
    pool: &sqlx::PgPool,
    config_id: &str,
    code_hashes: &[String],
) -> Result<()> {
    for hash in code_hashes {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO mfa_recovery_codes (id, mfa_config_id, code_hash) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(config_id)
            .bind(hash)
            .execute(pool).await.map_err(AppError::Database)?;
    }
    Ok(())
}