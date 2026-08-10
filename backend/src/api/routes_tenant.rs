use axum::{Json, Router, extract::{Path, State}, routing::{get, post}};
use std::sync::Arc;
use crate::error::{AppError, Result};
use crate::models::Tenant;
use crate::services::tenant_service::{TenantService, TenantUpdate};

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/", get(list_tenants).post(create_tenant))
        .route("/:id", get(get_tenant).put(update_tenant))
        .route("/:id/deactivate", post(deactivate_tenant))
}

pub async fn list_tenants(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<Tenant>>> {
    TenantService::list(state.pool()).await.map(Json)
}

pub async fn create_tenant(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Json(mut tenant): Json<Tenant>,
) -> Result<Json<Tenant>> {
    if tenant.id.is_empty() {
        tenant.id = uuid::Uuid::new_v4().to_string();
    }
    TenantService::create(state.pool(), tenant).await.map(Json)
}

pub async fn get_tenant(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<Tenant>> {
    let t = TenantService::get_by_id(state.pool(), &id).await?;
    if let Some(tenant) = t {
        Ok(Json(tenant))
    } else {
        TenantService::get_by_slug(state.pool(), &id)
            .await?
            .map(Json)
            .ok_or_else(|| AppError::NotFound("Tenant not found".into()))
    }
}

pub async fn update_tenant(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<Tenant>> {
    let updates = TenantUpdate {
        name: payload.get("name").and_then(|v| v.as_str()).map(String::from),
        domain: payload.get("domain").and_then(|v| v.as_str()).map(String::from),
        plan: payload.get("plan").and_then(|v| v.as_str()).map(String::from),
        max_users: payload.get("max_users").and_then(|v| v.as_i64()).map(|v| v as i32),
        max_storage_gb: payload.get("max_storage_gb").and_then(|v| v.as_i64()).map(|v| v as i32),
    };

    TenantService::update(state.pool(), &id, &updates)
        .await?
        .map(Json)
        .ok_or_else(|| AppError::NotFound("Tenant not found".into()))
}

pub async fn deactivate_tenant(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let ok = TenantService::deactivate(state.pool(), &id).await?;
    if ok {
        Ok(Json(serde_json::json!({"status": "deactivated", "id": id})))
    } else {
        Err(AppError::NotFound("Tenant not found".into()))
    }
}

