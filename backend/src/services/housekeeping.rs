use crate::error::{AppError, Result};
use chrono::Utc;
use sqlx::PgPool;

pub struct HousekeepingService;
impl HousekeepingService {
    pub async fn run(pool: &PgPool) -> Result<HousekeepingStats> {
        let mut stats = HousekeepingStats::default();
        let now = Utc::now().naive_utc();
        let r = sqlx::query(
            "UPDATE user_sessions SET is_revoked=true WHERE expires_at < $1 AND is_revoked=false",
        )
        .bind(now)
        .execute(pool)
        .await
        .map_err(AppError::Database)?;
        stats.expired_sessions_revoked = r.rows_affected() as i64;
        let thirty_days = (Utc::now() - chrono::Duration::days(30)).naive_utc();
        let r = sqlx::query("DELETE FROM login_failures WHERE attempted_at < $1")
            .bind(thirty_days)
            .execute(pool)
            .await
            .map_err(AppError::Database)?;
        stats.old_login_failures_deleted = r.rows_affected() as i64;
        let r = sqlx::query("DELETE FROM auth_exchange_codes WHERE expires_at < $1")
            .bind(now)
            .execute(pool)
            .await
            .map_err(AppError::Database)?;
        stats.expired_codes_deleted = r.rows_affected() as i64;

        // Phase F (M3): Prune expired token revocations (tokens past exp claim)
        let r = sqlx::query("DELETE FROM token_revocations WHERE expires_at < $1")
            .bind(now)
            .execute(pool)
            .await
            .map_err(AppError::Database)?;
        stats.expired_token_revocations_deleted = r.rows_affected() as i64;

        // Prune old revoked sessions past 30 days
        let r =
            sqlx::query("DELETE FROM user_sessions WHERE expires_at < $1 AND is_revoked = true")
                .bind(thirty_days)
                .execute(pool)
                .await
                .map_err(AppError::Database)?;
        stats.old_sessions_deleted = r.rows_affected() as i64;

        // Prune activity logs older than 90 days to prevent unbounded growth
        let ninety_days = (Utc::now() - chrono::Duration::days(90)).naive_utc();
        let r = sqlx::query("DELETE FROM user_activity_events WHERE created_at < $1")
            .bind(ninety_days)
            .execute(pool)
            .await
            .map_err(AppError::Database)?;
        stats.old_activity_events_deleted = r.rows_affected() as i64;

        // Phase 8: Reclaim abandoned running tasks whose heartbeat stopped > 5 minutes ago
        let zombie_reclaimed = Self::sweep_zombie_jobs(pool).await?;
        stats.zombie_jobs_reclaimed = zombie_reclaimed as i64;

        Ok(stats)
    }

    /// Reclaim jobs that are marked 'running' whose executions have stopped
    /// heartbeating for > 5 minutes, or that have been running with no active execution.
    pub async fn sweep_zombie_jobs(pool: &PgPool) -> Result<u64> {
        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(5);
        let mut total_reclaimed = 0u64;

        // 1. Reclaim abandoned running executions whose heartbeat stopped > 5 minutes ago
        let abandoned: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, job_id FROM audit_executions
              WHERE status='running'
                AND COALESCE(heartbeat_at, started_at) < $1",
        )
        .bind(cutoff.naive_utc())
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)?;

        for (execution_id, job_id) in abandoned {
            if let Ok(true) = crate::orchestrator::execution::reap_abandoned_execution(
                pool,
                &execution_id,
                &cutoff.naive_utc(),
                "execution owner stopped heartbeating (recovered by zombie sweeper)",
            )
            .await
            {
                total_reclaimed += 1;
                crate::orchestrator::broadcast_job_progress(pool, &job_id).await;
            }
        }

        // 2. Reclaim orphaned audit_jobs stuck in 'running' with no live running execution
        let stuck_jobs: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT j.id FROM audit_jobs j
            WHERE j.status = 'running'
              AND (j.started_at IS NULL OR j.started_at < $1)
              AND NOT EXISTS (
                  SELECT 1 FROM audit_executions e
                  WHERE e.job_id = j.id AND e.status = 'running'
              )
            "#,
        )
        .bind(cutoff.naive_utc())
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)?;

        for (job_id,) in stuck_jobs {
            let r = sqlx::query(
                "UPDATE audit_jobs SET status = 'failed', finished_at = NOW(), error_message = $1 WHERE id = $2 AND status = 'running'"
            )
            .bind("Job abandoned / worker terminated (no active heartbeat or execution)")
            .bind(&job_id)
            .execute(pool)
            .await
            .map_err(AppError::Database)?;

            if r.rows_affected() > 0 {
                total_reclaimed += r.rows_affected();
                crate::orchestrator::broadcast_job_progress(pool, &job_id).await;
            }
        }

        Ok(total_reclaimed)
    }
}
#[derive(Debug, Clone, Default)]
pub struct HousekeepingStats {
    pub expired_sessions_revoked: i64,
    pub old_login_failures_deleted: i64,
    pub expired_codes_deleted: i64,
    pub expired_token_revocations_deleted: i64,
    pub old_sessions_deleted: i64,
    pub old_activity_events_deleted: i64,
    pub zombie_jobs_reclaimed: i64,
}
impl std::fmt::Display for HousekeepingStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "sessions_revoked={}, login_failures_deleted={}, codes_deleted={}, token_revocations_deleted={}, old_sessions_deleted={}, activity_events_deleted={}, zombie_jobs_reclaimed={}",
            self.expired_sessions_revoked,
            self.old_login_failures_deleted,
            self.expired_codes_deleted,
            self.expired_token_revocations_deleted,
            self.old_sessions_deleted,
            self.old_activity_events_deleted,
            self.zombie_jobs_reclaimed
        )
    }
}
