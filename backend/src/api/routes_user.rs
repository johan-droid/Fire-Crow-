use axum::{Json, Router, extract::State, routing::{get, delete}};
use std::sync::Arc;
use crate::error::{AppError, Result};

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/export", get(export_user_data))
        .route("/delete", delete(delete_user))
}

pub async fn export_user_data(State(state): State<Arc<crate::AppState>>, user: crate::middleware::auth::AuthenticatedUser) -> Result<Json<serde_json::Value>> {
    let activities = crate::services::user_activity::list_user_activities(state.pool(), &user.user_id, 1000).await?;
    Ok(Json(serde_json::json!({"user_id": user.user_id, "username": user.username, "activities": activities})))
}

pub async fn delete_user(State(state): State<Arc<crate::AppState>>, user: crate::middleware::auth::AuthenticatedUser) -> Result<Json<serde_json::Value>> {
    sqlx::query("UPDATE users SET is_active=false, email=NULL, username='deleted_'||id WHERE id=$1").bind(user.user_id).execute(state.pool()).await.map_err(AppError::Database)?;
    Ok(Json(serde_json::json!({"status": "deleted"})))
}
