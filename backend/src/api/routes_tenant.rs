use axum::{Json, Router, extract::{Path, State}, routing::{get, post}};
use std::sync::Arc;
use crate::error::{AppError, Result};
use crate::models::{CreatePaymentRequest, PaymentRecord, Tenant};
use crate::services::payment_service::PaymentService;
use crate::services::tenant_service::{TenantService, TenantUpdate};

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/", get(list_tenants).post(create_tenant))
        .route("/:id", get(get_tenant).put(update_tenant))
        .route("/:id/deactivate", post(deactivate_tenant))
        .route("/payments", get(list_payments).post(record_payment))
}

pub async fn list_tenants(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<Tenant>>> {
    let tenants = if user.tenant_id.is_empty() {
        Vec::new()
    } else {
        TenantService::list_for_tenant(state.pool(), &user.tenant_id).await?
    };
    Ok(Json(tenants))
}

pub async fn create_tenant(
    State(state): State<Arc<crate::AppState>>,
    _admin: crate::middleware::auth::AdminUser,
    Json(mut tenant): Json<Tenant>,
) -> Result<Json<Tenant>> {
    if tenant.id.is_empty() {
        tenant.id = uuid::Uuid::new_v4().to_string();
    }
    TenantService::create(state.pool(), tenant).await.map(Json)
}

pub async fn get_tenant(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<Tenant>> {
    if user.tenant_id.is_empty() || user.tenant_id != id {
        return Err(AppError::Forbidden("Tenant access denied".into()));
    }
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
    _admin: crate::middleware::auth::AdminUser,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<Tenant>> {
    let updates = TenantUpdate {
        name: payload.get("name").and_then(|v| v.as_str()).map(String::from),
        domain: payload.get("domain").and_then(|v| v.as_str()).map(String::from),
        plan: payload.get("plan").and_then(|v| v.as_str()).map(String::from),
        usecase: payload.get("usecase").and_then(|v| v.as_str()).map(String::from),
        industry_type: payload.get("industry_type").and_then(|v| v.as_str()).map(String::from),
        billing_email: payload.get("billing_email").and_then(|v| v.as_str()).map(String::from),
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
    _admin: crate::middleware::auth::AdminUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let ok = TenantService::deactivate(state.pool(), &id).await?;
    if ok {
        Ok(Json(serde_json::json!({"status": "deactivated", "id": id})))
    } else {
        Err(AppError::NotFound("Tenant not found".into()))
    }
}

pub async fn list_payments(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<PaymentRecord>>> {
    let records = PaymentService::list_user_payments(state.pool(), &user.user_id).await?;
    Ok(Json(records))
}

pub async fn record_payment(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(payload): Json<CreatePaymentRequest>,
) -> Result<Json<PaymentRecord>> {
    let record = PaymentService::record_payment(state.pool(), &user.user_id, payload).await?;
    Ok(Json(record))
}
