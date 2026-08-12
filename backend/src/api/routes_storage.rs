use axum::{Json, Router, extract::{Path, Query, State}, routing::{get, post}};
use std::sync::Arc;
use crate::error::{AppError, Result};

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/artifacts/{artifact_id}/download", get(download_artifact))
        .route("/artifacts/{artifact_id}/legal-hold", post(set_legal_hold))
}

pub async fn download_artifact(State(state): State<Arc<crate::AppState>>, Path(artifact_id): Path<String>, user: crate::middleware::auth::AuthenticatedUser) -> Result<axum::response::Response> {
    let artifact: Option<crate::models::ArtifactObject> = sqlx::query_as::<_, crate::models::ArtifactObject>("SELECT * FROM audit_artifacts WHERE id=$1 AND user_id=$2")
        .bind(artifact_id).bind(&user.user_id).fetch_optional(state.pool()).await.map_err(AppError::Database)?;
    let artifact = artifact.ok_or_else(|| AppError::NotFound("Artifact not found".into()))?;
    let data = state.storage().download_artifact(&artifact.storage_key).await?;
    Ok(axum::response::Response::builder().status(200).header("Content-Type", artifact.mime_type.unwrap_or_else(|| "application/octet-stream".into())).body(axum::body::Body::from(data)).unwrap())
}

pub async fn set_legal_hold(State(state): State<Arc<crate::AppState>>, Path(artifact_id): Path<String>, Query(params): Query<serde_json::Value>, user: crate::middleware::auth::AuthenticatedUser) -> Result<Json<serde_json::Value>> {
    let hold = params.get("hold").and_then(|v| v.as_bool()).unwrap_or(true);
    sqlx::query("UPDATE audit_artifacts SET legal_hold=$1 WHERE id=$2 AND user_id=$3").bind(hold).bind(artifact_id).bind(&user.user_id).execute(state.pool()).await.map_err(AppError::Database)?;
    Ok(Json(serde_json::json!({"status": "updated", "legal_hold": hold})))
}
