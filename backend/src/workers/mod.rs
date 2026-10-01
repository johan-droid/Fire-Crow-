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
    AuditJob {
        job_id: String,
        user_id: String,
        repo_url: String,
        repo_branch: String,
        custom_email: Option<String>,
    },
    Housekeeping,
}

/// Run one audit job, with the hard 30-minute ceiling.
///
/// Both `WorkerTask::execute` and the pool's `worker_loop` funnel through here.
/// They previously carried separate copies of the timeout + failure UPDATE and
/// had drifted: only one guarded its UPDATE on a non-terminal status, so the
/// other could clobber a job that the reaper had already finalised. There is now
/// a single implementation.
pub async fn run_audit_job(
    pool: &PgPool,
    job_id: &str,
    user_id: &str,
    repo_url: &str,
    repo_branch: &str,
    custom_email: Option<&str>,
) {
    info!("Worker: executing audit job {job_id}");
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(1800),
        execute_audit_job(
            pool,
            job_id,
            user_id,
            repo_url,
            repo_branch,
            custom_email,
            None,
        ),
    )
    .await
    {
        Ok(Err(e)) => {
            error!("Worker: job {} failed: {}", job_id, e);
            mark_job_failed(pool, job_id, &e.to_string()).await;
        }
        Err(_) => {
            error!("Worker: job {} timed out after 30 minutes", job_id);
            mark_job_failed(pool, job_id, "Job timed out after 30 minutes").await;
        }
        Ok(Ok(_)) => {
            info!("Worker: audit job {job_id} completed");
        }
    }
}

/// Fail a job, but only while it is still non-terminal.
///
/// The `status IN ('queued','running')` guard is what stops a late failure from
/// overwriting a `completed` job. Every status write in the worker carries it.
async fn mark_job_failed(pool: &PgPool, job_id: &str, message: &str) {
    let _ = sqlx::query(
        "UPDATE audit_jobs SET status=$1, error_message=$2, finished_at=$3 \
         WHERE id=$4 AND status IN ('queued','running')",
    )
    .bind(JobStatus::Failed)
    .bind(message.to_string())
    .bind(chrono::Utc::now().naive_utc())
    .bind(job_id)
    .execute(pool)
    .await;
}

impl WorkerTask {
    pub async fn execute(self, pool: &PgPool, _settings: &Settings) -> Result<()> {
        match self {
            Self::AuditJob {
                job_id,
                user_id,
                repo_url,
                repo_branch,
                custom_email,
            } => {
                run_audit_job(
                    pool,
                    &job_id,
                    &user_id,
                    &repo_url,
                    &repo_branch,
                    custom_email.as_deref(),
                )
                .await;
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
        Self {
            pool,
            settings,
            running: Arc::new(RwLock::new(false)),
            active_jobs: Arc::new(RwLock::new(Vec::new())),
        }
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
            tokio::spawn(async move {
                Self::worker_loop(i, pool, settings, running, active_jobs).await;
            });
        }
        let pool = self.pool.clone();
        let settings = self.settings.clone();
        let running = self.running.clone();
        tokio::spawn(async move {
            Self::housekeeping_loop(pool, settings, running).await;
        });

        // Orphan reaper: only kills jobs that have been running for >10 minutes
        // AND are not in the active_jobs list (i.e. not being processed by this server instance)
        let pool = self.pool.clone();
        let active_jobs = self.active_jobs.clone();
        tokio::spawn(async move {
            // Wait 15 seconds on startup before first check to let workers claim jobs
            tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

                // Handle explicit cancellation requests. A cancellation is its
                // own terminal outcome — `cancelled`, never `failed`. The guard
                // keeps the write on non-terminal rows only.
                let _ = sqlx::query("UPDATE audit_jobs SET status=$1, error_message=$2, finished_at=$3 WHERE status IN ('queued','running') AND cancel_requested=true")
                    .bind(JobStatus::Cancelled)
                    .bind("Job cancelled by user")
                    .bind(chrono::Utc::now().naive_utc())
                    .execute(&pool)
                    .await;

                // Find potentially orphaned jobs. The reaper measures how long a
                // job has been *running* (`started_at`, stamped at claim time),
                // not how long ago it was created, so a job that sat in the queue
                // for a long time is not reaped before it ever starts.
                let stale_cutoff = chrono::Utc::now() - chrono::Duration::minutes(10);
                let orphaned: Vec<AuditJob> = sqlx::query_as::<_, AuditJob>(
                    "SELECT * FROM audit_jobs WHERE status=$1 AND COALESCE(started_at, created_at) < $2",
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
                        warn!(
                            "Reaping orphaned job {} (not in active worker list, running >10min)",
                            job.id
                        );
                        let _ = sqlx::query("UPDATE audit_jobs SET status=$1, error_message=$2, finished_at=$3 WHERE id=$4 AND status IN ('queued','running')")
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
    async fn worker_loop(
        id: usize,
        pool: sqlx::PgPool,
        _settings: Settings,
        running: Arc<RwLock<bool>>,
        active_jobs: Arc<RwLock<Vec<String>>>,
    ) {
        loop {
            {
                let r = running.read().await;
                if !*r {
                    break;
                }
            }

            // Atomic claim: SELECT + UPDATE in one statement with row-level locking.
            // FOR UPDATE SKIP LOCKED ensures each worker grabs a different job.
            let claimed: Option<AuditJob> = match sqlx::query_as::<_, AuditJob>(
                "UPDATE audit_jobs SET status='running', started_at=NOW() WHERE id = (SELECT id FROM audit_jobs WHERE status='queued' ORDER BY created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *"
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

                // One shared job-run path (timeout, execution, and the guarded
                // failure write all live in `run_audit_job`).
                run_audit_job(
                    &pool,
                    &job.id,
                    &job.user_id,
                    &job.repo_url,
                    &job.repo_branch,
                    None,
                )
                .await;

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
    async fn housekeeping_loop(pool: sqlx::PgPool, settings: Settings, running: Arc<RwLock<bool>>) {
        // housekeeping_interval_seconds is authoritative. It previously arrived
        // here as `_settings` and was ignored in favour of a hardcoded 3600,
        // while `default_housekeeping_interval()` independently returned the same
        // value, so the setting looked configurable but silently was not.
        //
        // `Settings::validate` rejects non-positive values, because
        // `tokio::time::interval` panics on a zero duration and this task is
        // spawned without supervision, so that panic would go unseen.
        let period = settings.housekeeping_interval_seconds.max(1) as u64;
        tracing::info!(
            "Housekeeping loop interval: {}s (from housekeeping_interval_seconds)",
            period
        );
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(period));
        loop {
            interval.tick().await;
            {
                let r = running.read().await;
                if !*r {
                    break;
                }
            }
            if let Err(e) = HousekeepingService::run(&pool).await {
                warn!("Housekeeping failed: {}", e);
            }
        }
    }
}
