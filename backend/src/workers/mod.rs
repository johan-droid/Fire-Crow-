use crate::config::Settings;
use crate::error::Result;
use crate::models::{AuditJob, JobStatus};
use crate::orchestrator::execute_audit_job;
use crate::services::housekeeping::HousekeepingService;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub enum WorkerTask {
    AuditJob { job_id: String, user_id: String, repo_url: String, repo_branch: String, custom_email: Option<String> },
    Housekeeping,
}

impl WorkerTask {
    pub async fn execute(self, pool: &PgPool, _settings: &Settings) -> Result<()> {
        match self {
            Self::AuditJob { job_id, user_id, repo_url, repo_branch, custom_email } => {
                info!("Worker: executing audit job {job_id}");
                match tokio::time::timeout(tokio::time::Duration::from_secs(1800), execute_audit_job(pool, &job_id, &user_id, &repo_url, &repo_branch, custom_email.as_deref(), None)).await {
                    Ok(Err(e)) => { return Err(crate::error::AppError::Internal(format!("Job {} failed: {}", job_id, e))); }
                    Err(_) => { return Err(crate::error::AppError::Internal(format!("Job {} timed out after 30 minutes", job_id))); }
                    Ok(Ok(_)) => {}
                }
                info!("Worker: audit job {job_id} completed");
            }
            Self::Housekeeping => {
                info!("Worker: running housekeeping");
                let stats = HousekeepingService::run(pool).await?;
                info!("Worker: housekeeping completed — {}", stats);
            }
        }
        Ok(())
    }
}

pub struct WorkerPool {
    pool: PgPool,
    settings: Settings,
    running: Arc<RwLock<bool>>,
    active_jobs: Arc<RwLock<Vec<String>>>,
}

impl WorkerPool {
    pub fn new(pool: PgPool, settings: Settings) -> Self {
        Self { pool, settings, running: Arc::new(RwLock::new(false)), active_jobs: Arc::new(RwLock::new(Vec::new())) }
    }
    pub async fn start(&self, num_workers: usize) {
        {
            let mut r = self.running.write().await;
            *r = true;
        }
        for i in 0..num_workers {
            let pool = self.pool.clone();
            let settings = self.settings.clone();
            let running = self.running.clone();
            let active_jobs = self.active_jobs.clone();
            tokio::spawn(async move { Self::worker_loop(i, pool, settings, running, active_jobs).await; });
        }
        let pool = self.pool.clone();
        let settings = self.settings.clone();
        let running = self.running.clone();
        tokio::spawn(async move { Self::housekeeping_loop(pool, settings, running).await; });

        // Orphan reaper: only kills jobs that have been running for >10 minutes
        // AND are not in the active_jobs list (i.e. not being processed by this server instance)
        let pool = self.pool.clone();
        let active_jobs = self.active_jobs.clone();
        tokio::spawn(async move {
            // Wait 15 seconds on startup before first check to let workers claim jobs
            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

                // Handle explicit cancellation requests
                let _ = sqlx::query("UPDATE audit_jobs SET status=$1, error_message=$2, finished_at=$3 WHERE status=$4 AND cancel_requested=true")
                    .bind(JobStatus::Failed)
                    .bind("Job cancelled by user")
                    .bind(chrono::Utc::now().naive_utc())
                    .bind(JobStatus::Running)
                    .execute(&pool)
                    .await;

                // Find potentially orphaned jobs (running for >10 minutes)
                let stale_cutoff = chrono::Utc::now() - chrono::Duration::minutes(10);
                let orphaned: Vec<AuditJob> = sqlx::query_as::<_, AuditJob>(
                    "SELECT * FROM audit_jobs WHERE status=$1 AND created_at < $2"
                )
                    .bind(JobStatus::Running)
                    .bind(stale_cutoff.naive_utc())
                    .fetch_all(&pool)
                    .await
                    .unwrap_or_default();

                let current_active = active_jobs.read().await;
                for job in orphaned {
                    // Only kill jobs that are NOT actively being processed by this server
                    if !current_active.contains(&job.id) {
                        warn!("Reaping orphaned job {} (not in active worker list, running >10min)", job.id);
                        let _ = sqlx::query("UPDATE audit_jobs SET status=$1, error_message=$2, finished_at=$3 WHERE id=$4")
                            .bind(JobStatus::Failed)
                            .bind("Audit job was interrupted by a server restart")
                            .bind(chrono::Utc::now().naive_utc())
                            .bind(&job.id)
                            .execute(&pool)
                            .await;
                    }
                }
            }
        });
    }
    pub async fn stop(&self) {
        let mut r = self.running.write().await;
        *r = false;
        info!("Worker pool shutting down");
    }

    /// Worker loop: uses atomic `FOR UPDATE SKIP LOCKED` to claim exactly one job.
    /// Multiple workers can run concurrently without racing on the same job.
    async fn worker_loop(id: usize, pool: sqlx::PgPool, _settings: Settings, running: Arc<RwLock<bool>>, active_jobs: Arc<RwLock<Vec<String>>>) {
        loop {
            {
                let r = running.read().await;
                if !*r { break; }
            }

            // Atomic claim: SELECT + UPDATE in one statement with row-level locking.
            // FOR UPDATE SKIP LOCKED ensures each worker grabs a different job.
            let claimed: Option<AuditJob> = match sqlx::query_as::<_, AuditJob>(
                "UPDATE audit_jobs SET status='running' WHERE id = (SELECT id FROM audit_jobs WHERE status='queued' ORDER BY created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *"
            )
                .fetch_optional(&pool)
                .await
            {
                Ok(job) => job,
                Err(e) => {
                    error!("Worker {}: failed to claim job from queue: {}", id, e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            if let Some(job) = claimed {
                info!("Worker {}: claimed job {}", id, job.id);

                {
                    let mut active = active_jobs.write().await;
                    active.push(job.id.clone());
                }

                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(1800),
                    execute_audit_job(&pool, &job.id, &job.user_id, &job.repo_url, &job.repo_branch, None, None)
                ).await {
                    Ok(Err(e)) => {
                        error!("Worker {}: job {} failed: {}", id, job.id, e);
                        let _ = sqlx::query("UPDATE audit_jobs SET status=$1, error_message=$2, finished_at=$3 WHERE id=$4")
                            .bind(JobStatus::Failed)
                            .bind(e.to_string())
                            .bind(chrono::Utc::now().naive_utc())
                            .bind(&job.id)
                            .execute(&pool)
                            .await;
                    }
                    Err(_) => {
                        error!("Worker {}: job {} timed out after 30 minutes", id, job.id);
                        let _ = sqlx::query("UPDATE audit_jobs SET status=$1, error_message=$2, finished_at=$3 WHERE id=$4")
                            .bind(JobStatus::Failed)
                            .bind("Job timed out after 30 minutes".to_string())
                            .bind(chrono::Utc::now().naive_utc())
                            .bind(&job.id)
                            .execute(&pool)
                            .await;
                    }
                    Ok(Ok(_)) => {
                        info!("Worker {}: job {} completed successfully", id, job.id);
                    }
                }

                {
                    let mut active = active_jobs.write().await;
                    active.retain(|jid| jid != &job.id);
                }
            } else {
                // No jobs available — back off to reduce DB polling pressure
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }
    async fn housekeeping_loop(pool: sqlx::PgPool, _settings: Settings, running: Arc<RwLock<bool>>) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            {
                let r = running.read().await;
                if !*r { break; }
            }
            if let Err(e) = HousekeepingService::run(&pool).await { warn!("Housekeeping failed: {}", e); }
        }
    }
}
