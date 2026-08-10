use axum::{Json, Router, extract::{Path, State}, routing::{get, post, delete}};
use std::sync::Arc;
use crate::error::{AppError, Result};
use crate::models::DomainVerification;
use crate::services::domain_verify::DomainVerifyService;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/domains", get(list_domains))
        .route("/domains/initiate", post(initiate_domain))
        .route("/domains/:id/check", post(check_domain))
        .route("/domains/:id", delete(delete_domain))
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
    DomainVerifyService::initiate(state.pool(), &user.user_id, domain).await.map(Json)
}

pub async fn check_domain(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<DomainVerification>> {
    let method = payload.get("method").and_then(|v| v.as_str()).unwrap_or("dns");
    DomainVerifyService::check(state.pool(), &id, method).await.map(Json)
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

