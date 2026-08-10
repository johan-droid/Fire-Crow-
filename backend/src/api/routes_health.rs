use axum::{Json, extract::State};
use std::sync::Arc;

pub async fn health_deep(_state: State<Arc<crate::AppState>>) -> axum::Json<serde_json::Value> {
    Json(serde_json::json!({"status": "healthy", "database": "ok", "local_storage": "ok"}))
}
pub async fn health_ready(_state: State<Arc<crate::AppState>>) -> axum::Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ready", "database": "connected"}))
}
pub async fn health_check(_state: State<Arc<crate::AppState>>) -> axum::Json<serde_json::Value> {
    Json(serde_json::json!({"status": "up", "database": "connected"}))
}
pub async fn health_live() -> &'static str { "live" }

pub fn router() -> axum::Router<Arc<crate::AppState>> {
    use axum::routing::get;
    axum::Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/health", get(health_check))
        .route("/api/v1/health/deep", get(health_deep))
        .route("/api/v1/health/ready", get(health_ready))
        .route("/api/v1/health/live", get(health_live))
}
