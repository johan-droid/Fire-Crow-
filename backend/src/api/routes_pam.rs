use axum::{Json, Router, extract::{Path, State}, routing::{get, post}};
use std::sync::Arc;
use crate::error::Result;
use crate::models::{PrivilegedAccessGrant, PrivilegedAccessRequest};
use crate::services::pam_service::PamService;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/requests", get(list_requests).post(create_request))
        .route("/requests/:id/approve", post(approve_request))
        .route("/grants", get(list_grants))
        .route("/grants/:id/revoke", post(revoke_grant))
}

pub async fn list_requests(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<PrivilegedAccessRequest>>> {
    PamService::list_requests(state.pool(), None).await.map(Json)
}

pub async fn create_request(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(mut req): Json<PrivilegedAccessRequest>,
) -> Result<Json<PrivilegedAccessRequest>> {
    if req.id.is_empty() {
        req.id = uuid::Uuid::new_v4().to_string();
    }
    req.user_id = user.user_id;
    PamService::create_request(state.pool(), req).await.map(Json)
}

pub async fn approve_request(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AdminUser,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<PrivilegedAccessGrant>> {
    let duration_minutes = payload.get("duration_minutes").and_then(|v| v.as_i64()).unwrap_or(60) as i32;
    PamService::approve_request(state.pool(), &id, &user.0.user_id, duration_minutes).await.map(Json)
}

pub async fn list_grants(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<PrivilegedAccessGrant>>> {
    PamService::list_grants(state.pool()).await.map(Json)
}

pub async fn revoke_grant(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AdminUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    PamService::revoke_grant(state.pool(), &id, &user.0.user_id).await?;
    Ok(Json(serde_json::json!({"status": "revoked", "id": id})))
}

