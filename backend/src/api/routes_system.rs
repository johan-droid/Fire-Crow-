use crate::error::Result;
use crate::services::telemetry::get_metrics;
use axum::{
    extract::State,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/status", get(system_status))
        .route("/database/stats", get(database_stats))
        .route("/database/housekeeping", post(trigger_housekeeping))
        .route("/metrics", get(metrics))
}

pub async fn system_status(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let db_connected = match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => "connected",
        Err(_) => "disconnected",
    };
    Ok(Json(
        serde_json::json!({"status": "ok", "database": db_connected}),
    ))
}
/// Database-wide row counts for every public table.
///
/// security_s2 (was S-3): gated on `AuthenticatedUser`, so any registered user
/// could enumerate the size of every table in the database, including
/// `users`, `token_revocations`, `service_accounts` and `login_failures`.
/// Now `AdminUser`, matching every other privileged read in the codebase.
pub async fn database_stats(
    State(state): State<Arc<crate::AppState>>,
    _admin: crate::middleware::auth::AdminUser,
) -> Result<Json<serde_json::Value>> {
    let tables: Vec<String> = sqlx::query_scalar("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name")
        .fetch_all(&state.pool).await.unwrap_or_default();
    let mut table_counts = serde_json::Map::new();
    for table in &tables {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {}", table))
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);
        table_counts.insert(table.clone(), serde_json::Value::Number(count.into()));
    }
    Ok(Json(
        serde_json::json!({"tables": table_counts, "total_tables": tables.len()}),
    ))
}

/// Trigger the housekeeping sweep.
///
/// security_s2 (was S-2): gated on `AuthenticatedUser`, so any registered user
/// could run mass `UPDATE user_sessions` / `DELETE login_failures` /
/// `DELETE auth_exchange_codes`. Deleting `login_failures` rows erases the
/// login-lockout counters, which is a security control in its own right.
///
/// The sweep is time-bounded (`expires_at < now()`, `attempted_at < now - 30d`)
/// and accepts no request input, so scope is fixed. It is also already run
/// automatically by `WorkerPool::housekeeping_loop`, so this endpoint is a manual
/// re-run rather than the only path to these mutations.
pub async fn trigger_housekeeping(
    State(state): State<Arc<crate::AppState>>,
    _admin: crate::middleware::auth::AdminUser,
) -> Result<Json<serde_json::Value>> {
    let stats = crate::services::housekeeping::HousekeepingService::run(state.pool()).await?;
    Ok(Json(
        serde_json::json!({"status": "completed", "stats": stats.to_string()}),
    ))
}
pub async fn metrics(
    State(state): State<Arc<crate::AppState>>,
    _user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Response> {
    let metrics_output = get_metrics();
    Ok(Response::builder()
        .status(200)
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(axum::body::Body::from(metrics_output))
        .unwrap())
}
