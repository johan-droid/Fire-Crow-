use crate::error::{AppError, Result};
use chrono::Utc;
use sqlx::PgPool;

pub struct HousekeepingService;
impl HousekeepingService {
    pub async fn run(pool: &PgPool) -> Result<HousekeepingStats> {
        let mut stats = HousekeepingStats::default();
        let now = Utc::now().naive_utc();
        let r = sqlx::query("UPDATE user_sessions SET is_revoked=true WHERE expires_at < $1 AND is_revoked=false")
            .bind(now).execute(pool).await.map_err(AppError::Database)?;
        stats.expired_sessions_revoked = r.rows_affected() as i64;
        let thirty_days = (Utc::now() - chrono::Duration::days(30)).naive_utc();
        let r = sqlx::query("DELETE FROM login_failures WHERE attempted_at < $1")
            .bind(thirty_days).execute(pool).await.map_err(AppError::Database)?;
        stats.old_login_failures_deleted = r.rows_affected() as i64;
        let r = sqlx::query("DELETE FROM auth_exchange_codes WHERE expires_at < $1")
            .bind(now).execute(pool).await.map_err(AppError::Database)?;
        stats.expired_codes_deleted = r.rows_affected() as i64;
        Ok(stats)
    }
}
#[derive(Debug, Clone, Default)]
pub struct HousekeepingStats {
    pub expired_sessions_revoked: i64,
    pub old_login_failures_deleted: i64,
    pub expired_codes_deleted: i64,
}
impl std::fmt::Display for HousekeepingStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sessions_revoked={}, login_failures_deleted={}, codes_deleted={}", self.expired_sessions_revoked, self.old_login_failures_deleted, self.expired_codes_deleted)
    }
}
