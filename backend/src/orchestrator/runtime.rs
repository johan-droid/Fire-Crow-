use crate::error::Result;
use crate::schemas::audit_state::AuditState;

#[derive(Debug, Clone)]
pub struct JobCancellationRequested;

pub async fn apply_runtime_updates(pool: &sqlx::PgPool, state: &AuditState) -> Result<()> {
    let _ = sqlx::query("UPDATE audit_jobs SET status=$1 WHERE id=$2")
        .bind(state.status.as_str()).bind(&state.job_id)
        .execute(pool).await;
    Ok(())
}
pub async fn sync_runtime_state(_pool: &sqlx::PgPool, _state: &AuditState) -> Result<()> { Ok(()) }
pub async fn mark_cleanup_completed(_pool: &sqlx::PgPool, _job_id: &str) -> Result<()> { Ok(()) }
