use crate::error::{AppError, Result};
use crate::models::PushSubscription;

pub struct PushService;
impl PushService {
    pub async fn subscribe(pool: &sqlx::PgPool, user_id: &str, endpoint: &str, p256dh: &str, auth: &str) -> Result<PushSubscription> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query_as::<_, PushSubscription>(
            "INSERT INTO push_subscriptions (id, user_id, endpoint, p256dh, auth, created_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *"
        )
        .bind(id).bind(user_id).bind(endpoint).bind(p256dh).bind(auth).bind(chrono::Utc::now().naive_utc())
        .fetch_one(pool).await.map_err(AppError::Database)
    }
    pub async fn unsubscribe(pool: &sqlx::PgPool, subscription_id: &str, user_id: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM push_subscriptions WHERE id=$1 AND user_id=$2")
            .bind(subscription_id).bind(user_id)
            .execute(pool).await.map_err(AppError::Database)?;
        Ok(r.rows_affected() > 0)
    }
}
