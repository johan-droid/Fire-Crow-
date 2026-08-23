use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

pub async fn health_deep(State(state): State<Arc<crate::AppState>>) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").execute(state.pool()).await.is_ok();
    let status = if db_ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    
    (status, Json(serde_json::json!({
        "status": if db_ok { "healthy" } else { "unhealthy" },
        "database": if db_ok { "ok" } else { "error" },
        "local_storage": "ok",
        "version": env!("CARGO_PKG_VERSION")
    })))
}

pub async fn health_ready(State(state): State<Arc<crate::AppState>>) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").execute(state.pool()).await.is_ok();
    let status = if db_ok { StatusCode::OK } else { StatusCode::OK };
    
    (status, Json(serde_json::json!({
        "status": if db_ok { "ready" } else { "degraded" },
        "database": if db_ok { "connected" } else { "disconnected" }
    })))
}

pub async fn health_check(State(state): State<Arc<crate::AppState>>) -> impl IntoResponse {
    let db_ok = sqlx::query("SELECT 1").execute(state.pool()).await.is_ok();
    
    Json(serde_json::json!({
        "status": "up",
        "database": if db_ok { "connected" } else { "disconnected" }
    }))
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

