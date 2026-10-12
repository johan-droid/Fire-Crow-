use crate::error::{AppError, Result};
use crate::models::{IamPolicy, RolePermission, ServiceAccount};
use crate::services::iam_service::IamService;
use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use std::sync::Arc;

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
    // FC-AUTHZ-01: policy configuration is enumerable only by platform
    // administrators. `iam_policies` are non-enforcing configuration metadata
    // (no evaluator exists), but their rules reveal internal resource and
    // action naming, so ordinary accounts must not enumerate them.
    _admin: crate::middleware::auth::AdminUser,
) -> Result<Json<Vec<IamPolicy>>> {
    let policies = IamService::list_policies(state.pool()).await?;
    Ok(Json(policies))
}

pub async fn create_policy(
    State(state): State<Arc<crate::AppState>>,
    _admin: crate::middleware::auth::AdminUser,
    Json(mut policy): Json<IamPolicy>,
) -> Result<Json<IamPolicy>> {
    if policy.id.is_empty() {
        policy.id = uuid::Uuid::new_v4().to_string();
    }
    IamService::create_policy(state.pool(), policy)
        .await
        .map(Json)
}

pub async fn delete_policy(
    State(state): State<Arc<crate::AppState>>,
    _admin: crate::middleware::auth::AdminUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let ok = IamService::delete_policy(state.pool(), &id).await?;
    if ok {
        Ok(Json(serde_json::json!({"status": "deleted", "id": id})))
    } else {
        Err(AppError::NotFound("IAM policy not found".into()))
    }
}

/// The exact set of permission strings the API will ever write into
/// `role_permissions`. FC-AUTHZ-03: without an allowlist, any platform
/// administrator call could mint arbitrary strings — and before the platform/
/// tenant split, any *tenant* administrator could mint `superadmin` for their
/// own role. Unknown strings are rejected loudly rather than stored, so the
/// permission vocabulary stays auditable.
const GRANTABLE_PERMISSIONS: &[&str] = &[
    // platform administration
    "platform:admin",
    "platform:*",
    "platform:sso",
    "platform:iam",
    "platform:ops",
    // tenant administration (never implies platform authority)
    "tenant_admin",
    "tenant:manage",
    // feature administration (platform-scoped until tenant ownership ships)
    "iam:manage",
    "iam:*",
    "iam:admin",
    "sso:manage",
    "sso:*",
    "sso:admin",
    "pam:approve",
    "pam:manage",
    "pam:*",
    "pam:admin",
    "mfa:admin",
    "mfa:enforce",
    "user:manage",
    "user:admin",
    "billing:manage",
    "audit:admin",
];

pub async fn assign_permission(
    State(state): State<Arc<crate::AppState>>,
    _admin: crate::middleware::auth::AdminUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<RolePermission>> {
    let role_id = payload
        .get("role_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing role_id".into()))?;
    let permission = payload
        .get("permission")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Missing permission".into()))?;
    let resource_pattern = payload
        .get("resource_pattern")
        .and_then(|v| v.as_str())
        .unwrap_or("*");

    if !GRANTABLE_PERMISSIONS.contains(&permission) {
        return Err(AppError::BadRequest(
            "Unknown permission string; only explicit grantable permissions may be assigned".into(),
        ));
    }

    // The role must actually exist (roles are provisioned out-of-band; see
    // documentation/BOOTSTRAP_ADMIN.md). A typo'd or invented role id must not
    // silently create an orphaned grant.
    let role_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1)")
        .bind(role_id)
        .fetch_one(state.pool())
        .await
        .map_err(AppError::Database)?;
    if !role_exists {
        return Err(AppError::NotFound("Role not found".into()));
    }

    IamService::assign_permission(state.pool(), role_id, permission, resource_pattern)
        .await
        .map(Json)
}

pub async fn remove_permission(
    State(state): State<Arc<crate::AppState>>,
    _admin: crate::middleware::auth::AdminUser,
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
    user: crate::middleware::auth::AdminUser,
    Json(mut account): Json<ServiceAccount>,
) -> Result<Json<ServiceAccount>> {
    if account.id.is_empty() {
        account.id = uuid::Uuid::new_v4().to_string();
    }
    account.created_by = user.0.user_id;
    IamService::create_service_account(state.pool(), account)
        .await
        .map(Json)
}

pub async fn revoke_service_account(
    State(state): State<Arc<crate::AppState>>,
    _admin: crate::middleware::auth::AdminUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let ok = IamService::revoke_service_account(state.pool(), &id).await?;
    if ok {
        Ok(Json(serde_json::json!({"status": "revoked", "id": id})))
    } else {
        Err(AppError::NotFound("Service account not found".into()))
    }
}
