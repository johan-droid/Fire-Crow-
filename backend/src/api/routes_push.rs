use axum::{Json, Router, extract::State, routing::{get, post}};
use std::sync::Arc;
use crate::error::Result;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/vapid-public-key", get(get_vapid_public_key))
        .route("/subscribe", post(subscribe_user))
        .route("/unsubscribe", post(unsubscribe_user))
}

pub async fn get_vapid_public_key(_state: State<Arc<crate::AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"public_key": ""}))
}

pub async fn subscribe_user(State(state): State<Arc<crate::AppState>>, Json(payload): Json<serde_json::Value>) -> Result<Json<serde_json::Value>> {
    let endpoint = payload.get("endpoint").and_then(|v| v.as_str()).unwrap_or("");
    let p256dh = payload.get("p256dh").and_then(|v| v.as_str()).unwrap_or("");
    let auth = payload.get("auth").and_then(|v| v.as_str()).unwrap_or("");
    crate::services::push_notify::PushService::subscribe(state.pool(), "system", endpoint, p256dh, auth).await?;
    Ok(Json(serde_json::json!({"status": "subscribed"})))
}

pub async fn unsubscribe_user(_state: State<Arc<crate::AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "unsubscribed"}))
}
