use axum::{Json, Router, extract::State, response::Response, routing::{get, post}};
use std::sync::Arc;
use crate::error::Result;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/status", get(system_status))
        .route("/database/stats", get(database_stats))
        .route("/database/housekeeping", post(trigger_housekeeping))
        .route("/metrics", get(metrics))
}

pub async fn system_status(State(_state): State<Arc<crate::AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok", "database": "connected"}))
}
pub async fn database_stats(State(_state): State<Arc<crate::AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"tables": [], "total_records": 0}))
}
pub async fn trigger_housekeeping(State(state): State<Arc<crate::AppState>>) -> Result<Json<serde_json::Value>> {
    let stats = crate::services::housekeeping::HousekeepingService::run(state.pool()).await?;
    Ok(Json(serde_json::json!({"status": "completed", "stats": stats.to_string()})))
}
pub async fn metrics(State(_state): State<Arc<crate::AppState>>) -> Response {
    Response::builder().status(200).header("Content-Type", "text/plain; version=0.0.4").body(axum::body::Body::from("# Fire Crow Metrics\n")).unwrap()
}
