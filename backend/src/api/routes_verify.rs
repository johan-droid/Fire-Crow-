use axum::{Json, Router, Extension, extract::{Path, State}, routing::{get, post, delete}};
use std::sync::Arc;
use crate::error::{AppError, Result};
use crate::models::DomainVerification;
use crate::services::domain_verify::DomainVerifyService;
use crate::services::turnstile::TurnstileService;
use crate::middleware::cloudflare::CloudflareInfo;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/domains", get(list_domains))
        .route("/domains/initiate", post(initiate_domain))
        .route("/domains/:id/check", post(check_domain))
        .route("/domains/:id", delete(delete_domain))
        .route("/turnstile/verify", post(check_turnstile))
        .route("/cloudflare/status", get(cloudflare_status))
}

pub async fn list_domains(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<DomainVerification>>> {
    DomainVerifyService::list(state.pool(), &user.user_id).await.map(Json)
}

pub async fn initiate_domain(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<DomainVerification>> {
    let domain = payload.get("domain").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing domain".into()))?;
    DomainVerifyService::initiate(state.pool(), state.crypto(), &user.user_id, domain).await.map(Json)
}

pub async fn check_domain(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<DomainVerification>> {
    let method = payload.get("method").and_then(|v| v.as_str()).unwrap_or("dns");
    DomainVerifyService::check(state.pool(), state.crypto(), &id, &user.user_id, method).await.map(Json)
}

pub async fn delete_domain(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let ok = DomainVerifyService::delete(state.pool(), &id, &user.user_id).await?;
    if ok {
        Ok(Json(serde_json::json!({"status": "deleted", "id": id})))
    } else {
        Err(AppError::NotFound("Domain verification not found".into()))
    }
}

pub async fn check_turnstile(
    State(state): State<Arc<crate::AppState>>,
    Extension(cf_info): Extension<CloudflareInfo>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let token = payload.get("token").and_then(|v| v.as_str()).unwrap_or("");
    let turnstile = TurnstileService::new(
        state.settings().cf_turnstile_secret_key.clone(),
        state.settings().cf_turnstile_enabled,
    );
    let resp = turnstile.verify_token(token, Some(&cf_info.client_ip)).await?;
    Ok(Json(serde_json::json!({
        "success": resp.success,
        "hostname": resp.hostname,
        "cdata": resp.cdata,
        "client_ip": cf_info.client_ip,
        "ray_id": cf_info.ray_id,
        "country": cf_info.country,
    })))
}

pub async fn cloudflare_status(
    State(state): State<Arc<crate::AppState>>,
    Extension(cf_info): Extension<CloudflareInfo>,
) -> Result<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({
        "behind_cloudflare": cf_info.is_behind_cloudflare,
        "client_ip": cf_info.client_ip,
        "ray_id": cf_info.ray_id,
        "country": cf_info.country,
        "scheme": cf_info.scheme,
        "turnstile_enabled": state.settings().cf_turnstile_enabled,
        "turnstile_site_key": state.settings().cf_turnstile_site_key,
        "r2_configured": state.storage.s3_backend.is_some(),
    })))
}
