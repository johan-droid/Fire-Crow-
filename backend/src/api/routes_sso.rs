use axum::{Json, Router, extract::{Path, State}, routing::get};
use std::sync::Arc;
use crate::error::{AppError, Result};
use crate::models::SsoProvider;
use crate::services::sso_service::{SsoService, SsoProviderUpdate};

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/providers", get(list_providers).post(create_provider))
        .route("/providers/:id", get(get_provider).put(update_provider).delete(delete_provider))
}

pub async fn list_providers(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<SsoProvider>>> {
    SsoService::list_providers(state.pool()).await.map(Json)
}

pub async fn create_provider(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Json(mut provider): Json<SsoProvider>,
) -> Result<Json<SsoProvider>> {
    if provider.id.is_empty() {
        provider.id = uuid::Uuid::new_v4().to_string();
    }
    SsoService::create_provider(state.pool(), provider).await.map(Json)
}

pub async fn get_provider(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<SsoProvider>> {
    SsoService::get_provider(state.pool(), &id)
        .await?
        .map(Json)
        .ok_or_else(|| AppError::NotFound("SSO Provider not found".into()))
}

pub async fn update_provider(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<SsoProvider>> {
    let updates = SsoProviderUpdate {
        name: payload.get("name").and_then(|v| v.as_str()).map(String::from),
        issuer_url: payload.get("issuer_url").and_then(|v| v.as_str()).map(String::from),
        client_id: payload.get("client_id").and_then(|v| v.as_str()).map(String::from),
        client_secret: payload.get("client_secret").and_then(|v| v.as_str()).map(String::from),
        authorization_url: payload.get("authorization_url").and_then(|v| v.as_str()).map(String::from),
        token_url: payload.get("token_url").and_then(|v| v.as_str()).map(String::from),
        userinfo_url: payload.get("userinfo_url").and_then(|v| v.as_str()).map(String::from),
        jwks_url: payload.get("jwks_url").and_then(|v| v.as_str()).map(String::from),
        certificate: payload.get("certificate").and_then(|v| v.as_str()).map(String::from),
        attribute_mapping: payload.get("attribute_mapping").and_then(|v| v.as_str()).map(String::from),
        domains: payload.get("domains").and_then(|v| v.as_str()).map(String::from),
        enforce_mfa: payload.get("enforce_mfa").and_then(|v| v.as_bool()),
        auto_provision: payload.get("auto_provision").and_then(|v| v.as_bool()),
        default_role_id: payload.get("default_role_id").and_then(|v| v.as_str()).map(String::from),
    };

    SsoService::update_provider(state.pool(), &id, &updates)
        .await?
        .map(Json)
        .ok_or_else(|| AppError::NotFound("SSO Provider not found".into()))
}

pub async fn delete_provider(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let deleted = SsoService::delete_provider(state.pool(), &id).await?;
    if deleted {
        Ok(Json(serde_json::json!({"status": "deleted", "id": id})))
    } else {
        Err(AppError::NotFound("SSO Provider not found".into()))
    }
}

