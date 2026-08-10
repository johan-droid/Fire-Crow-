use axum::{Json, Router, extract::{Path, State}, routing::{get, post, delete}};
use std::sync::Arc;
use crate::error::{AppError, Result};
use crate::models::{IamPolicy, RolePermission, ServiceAccount};
use crate::services::iam_service::IamService;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/policies", get(list_policies).post(create_policy))
        .route("/policies/:id", delete(delete_policy))
        .route("/permissions", post(assign_permission))
        .route("/permissions/:id", delete(remove_permission))
        .route("/service-accounts", post(create_service_account))
        .route("/service-accounts/:id/revoke", post(revoke_service_account))
}

pub async fn list_policies(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<IamPolicy>>> {
    IamService::list_policies(state.pool()).await.map(Json)
}

pub async fn create_policy(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Json(mut policy): Json<IamPolicy>,
) -> Result<Json<IamPolicy>> {
    if policy.id.is_empty() {
        policy.id = uuid::Uuid::new_v4().to_string();
    }
    IamService::create_policy(state.pool(), policy).await.map(Json)
}

pub async fn delete_policy(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let ok = IamService::delete_policy(state.pool(), &id).await?;
    if ok {
        Ok(Json(serde_json::json!({"status": "deleted", "id": id})))
    } else {
        Err(AppError::NotFound("IAM policy not found".into()))
    }
}

pub async fn assign_permission(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<RolePermission>> {
    let role_id = payload.get("role_id").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing role_id".into()))?;
    let permission = payload.get("permission").and_then(|v| v.as_str()).ok_or_else(|| AppError::BadRequest("Missing permission".into()))?;
    let resource_pattern = payload.get("resource_pattern").and_then(|v| v.as_str()).unwrap_or("*");

    IamService::assign_permission(state.pool(), role_id, permission, resource_pattern).await.map(Json)
}

pub async fn remove_permission(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let ok = IamService::remove_permission(state.pool(), &id).await?;
    if ok {
        Ok(Json(serde_json::json!({"status": "removed", "id": id})))
    } else {
        Err(AppError::NotFound("Role permission not found".into()))
    }
}

pub async fn create_service_account(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(mut account): Json<ServiceAccount>,
) -> Result<Json<ServiceAccount>> {
    if account.id.is_empty() {
        account.id = uuid::Uuid::new_v4().to_string();
    }
    account.created_by = user.user_id;
    IamService::create_service_account(state.pool(), account).await.map(Json)
}

pub async fn revoke_service_account(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let ok = IamService::revoke_service_account(state.pool(), &id).await?;
    if ok {
        Ok(Json(serde_json::json!({"status": "revoked", "id": id})))
    } else {
        Err(AppError::NotFound("Service account not found".into()))
    }
}

