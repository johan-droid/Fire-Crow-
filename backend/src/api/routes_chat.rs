use axum::{Json, Router, extract::State, routing::post};
use std::sync::Arc;
use crate::error::Result;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new().route("/ask", post(ask_chat))
}

pub async fn ask_chat(State(_state): State<Arc<crate::AppState>>, Json(payload): Json<serde_json::Value>) -> Result<Json<serde_json::Value>> {
    let _job_id = payload.get("job_id").and_then(|v| v.as_str()).unwrap_or("");
    Ok(Json(serde_json::json!({"response": "Chat assistant is not yet implemented in the Rust backend.", "job_id": _job_id})))
}
