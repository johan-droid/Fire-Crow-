use axum::{Json, Router, extract::State, routing::{get, delete}};
use std::sync::Arc;
use crate::error::{AppError, Result};

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/export", get(export_user_data))
        .route("/delete", delete(delete_user))
        .route("/repos", get(list_github_repos))
}

pub async fn export_user_data(State(state): State<Arc<crate::AppState>>, user: crate::middleware::auth::AuthenticatedUser) -> Result<Json<serde_json::Value>> {
    let activities = crate::services::user_activity::list_user_activities(state.pool(), &user.user_id, 1000).await?;
    Ok(Json(serde_json::json!({"user_id": user.user_id, "username": user.username, "activities": activities})))
}

pub async fn delete_user(State(state): State<Arc<crate::AppState>>, user: crate::middleware::auth::AuthenticatedUser) -> Result<Json<serde_json::Value>> {
    sqlx::query("UPDATE users SET is_active=false, email=NULL, username='deleted_'||id WHERE id=$1").bind(user.user_id).execute(state.pool()).await.map_err(AppError::Database)?;
    Ok(Json(serde_json::json!({"status": "deleted"})))
}

pub async fn list_github_repos(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let db_user = sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE id = $1")
        .bind(&user.user_id)
        .fetch_one(state.pool())
        .await
        .map_err(AppError::Database)?;

    let token = if let Some(ref encrypted_token) = db_user.github_access_token {
        if !encrypted_token.is_empty() {
            state.crypto().decrypt_secret(encrypted_token).unwrap_or_else(|_| state.settings().github_token.clone())
        } else {
            state.settings().github_token.clone()
        }
    } else {
        state.settings().github_token.clone()
    };

    if token.is_empty() {
        return Ok(Json(serde_json::json!({
            "status": "not_connected",
            "message": "GitHub account not connected or access token unavailable. Please sign in with GitHub.",
            "repositories": []
        })));
    }

    let client = reqwest::Client::new();
    let res = client.get("https://api.github.com/user/repos?sort=updated&per_page=100&affiliation=owner,collaborator,organization_member")
        .header("User-Agent", "Fire-Crow-Backend")
        .header("Accept", "application/vnd.github.v3+json")
        .header("Authorization", format!("Bearer {}", token))
        .send().await;

    let response = match res {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            return Ok(Json(serde_json::json!({
                "status": "github_error",
                "message": format!("GitHub API returned HTTP {}: {}", status, body),
                "repositories": []
            })));
        }
        Err(e) => {
            return Ok(Json(serde_json::json!({
                "status": "network_error",
                "message": format!("Failed to connect to GitHub API: {}", e),
                "repositories": []
            })));
        }
    };

    let repos_json: Vec<serde_json::Value> = response.json().await.map_err(|e| {
        AppError::Internal(format!("Failed to parse GitHub repositories response: {}", e))
    })?;

    let repositories: Vec<serde_json::Value> = repos_json.into_iter().map(|repo| {
        serde_json::json!({
            "id": repo["id"],
            "name": repo["name"],
            "full_name": repo["full_name"],
            "clone_url": repo["clone_url"],
            "html_url": repo["html_url"],
            "private": repo["private"],
            "description": repo["description"],
            "default_branch": repo["default_branch"].as_str().unwrap_or("main"),
            "updated_at": repo["updated_at"]
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "count": repositories.len(),
        "repositories": repositories
    })))
}

