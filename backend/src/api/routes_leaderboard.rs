use axum::{Json, Router, extract::State, routing::get};
use std::sync::Arc;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new().route("/", get(get_leaderboard))
}

pub async fn get_leaderboard(State(_state): State<Arc<crate::AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"entries": []}))
}
