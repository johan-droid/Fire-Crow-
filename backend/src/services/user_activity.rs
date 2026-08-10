use crate::error::{AppError, Result};
use crate::models::UserActivityEvent;
use chrono::Utc;

pub async fn append_user_activity(pool: &sqlx::PgPool, user_id: &str, action: &str, details: Option<&str>) -> Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO user_activity_events (id, user_id, action, details_json, created_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(id).bind(user_id).bind(action).bind(details.map(|s| s.to_string())).bind(Utc::now().naive_utc())
        .execute(pool).await.map_err(AppError::Database)?;
    Ok(())
}

pub async fn list_user_activities(pool: &sqlx::PgPool, user_id: &str, limit: i64) -> Result<Vec<UserActivityEvent>> {
    sqlx::query_as::<_, UserActivityEvent>(
        "SELECT id, user_id, action, details_json, created_at FROM user_activity_events WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2"
    )
    .bind(user_id).bind(limit)
    .fetch_all(pool).await.map_err(AppError::Database)
}
