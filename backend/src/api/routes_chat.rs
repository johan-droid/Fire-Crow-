use crate::error::Result;
use axum::{extract::State, routing::post, Json, Router};
use std::sync::Arc;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new().route("/ask", post(ask_chat))
}

pub async fn ask_chat(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let job_id = payload.get("job_id").and_then(|v| v.as_str()).unwrap_or("");
    if !job_id.trim().is_empty() {
        let owns: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM audit_jobs WHERE id = $1 AND (user_id = $2 OR (tenant_id IS NOT NULL AND tenant_id != '' AND tenant_id = $3))",
        )
        .bind(job_id)
        .bind(&user.user_id)
        .bind(&user.tenant_id)
        .fetch_optional(state.pool())
        .await
        .map_err(crate::error::AppError::Database)?;

        if owns.is_none() {
            return Err(crate::error::AppError::NotFound(
                "Job not found or access denied".into(),
            ));
        }
    }

    Ok(Json(serde_json::json!({
        "response": "Chat assistant is not yet implemented in the Rust backend.",
        "job_id": job_id,
        "tenant_id": user.tenant_id,
    })))
}
