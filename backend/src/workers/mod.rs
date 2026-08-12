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
                execute_audit_job(pool, &job_id, &user_id, &repo_url, &repo_branch, custom_email.as_deref(), None).await?;
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
        let pool = self.pool.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                let _ = sqlx::query("UPDATE audit_jobs SET status=$1, error_message=$2, finished_at=$3 WHERE status=$4 AND cancel_requested=true")
                    .bind(JobStatus::Failed)
                    .bind("Job cancelled by user")
                    .bind(chrono::Utc::now().naive_utc())
                    .bind(JobStatus::Running)
                    .execute(&pool)
                    .await;
                let orphaned: Vec<AuditJob> = sqlx::query_as::<_, AuditJob>("SELECT * FROM audit_jobs WHERE status=$1")
                    .bind(JobStatus::Running)
                    .fetch_all(&pool)
                    .await
                    .unwrap_or_default();
                for job in orphaned {
                    warn!("Found orphaned job: {}", job.id);
                    let _ = sqlx::query("UPDATE audit_jobs SET status=$1, error_message=$2, finished_at=$3 WHERE id=$4")
                        .bind(JobStatus::Failed)
                        .bind("Audit job was interrupted by a server restart")
                        .bind(chrono::Utc::now().naive_utc())
                        .bind(&job.id)
                        .execute(&pool)
                        .await;
                }
            }
        });
    }
    pub async fn stop(&self) {
        let mut r = self.running.write().await;
        *r = false;
        info!("Worker pool shutting down");
    }
    async fn worker_loop(_id: usize, pool: sqlx::PgPool, _settings: Settings, running: Arc<RwLock<bool>>, active_jobs: Arc<RwLock<Vec<String>>>) {
        loop {
            {
                let r = running.read().await;
                if !*r { break; }
            }
            let queued_jobs: Vec<AuditJob> = sqlx::query_as::<_, AuditJob>("SELECT * FROM audit_jobs WHERE status=$1 ORDER BY created_at ASC LIMIT 1")
                .bind(JobStatus::Queued)
                .fetch_all(&pool)
                .await
                .unwrap_or_default();
            for job in queued_jobs {
                info!("Worker: picked up job {}", job.id);
                let _ = sqlx::query("UPDATE audit_jobs SET status=$1 WHERE id=$2")
                    .bind(JobStatus::Running)
                    .bind(&job.id)
                    .execute(&pool)
                    .await;

                {
                    let mut active = active_jobs.write().await;
                    active.push(job.id.clone());
                }

                if let Err(e) = execute_audit_job(&pool, &job.id, &job.user_id, &job.repo_url, &job.repo_branch, None, None).await {
                    error!("Worker: job {} failed: {}", job.id, e);
                    let _ = sqlx::query("UPDATE audit_jobs SET status=$1, error_message=$2, finished_at=$3 WHERE id=$4")
                        .bind(JobStatus::Failed)
                        .bind(e.to_string())
                        .bind(chrono::Utc::now().naive_utc())
                        .bind(&job.id)
                        .execute(&pool)
                        .await;
                }

                {
                    let mut active = active_jobs.write().await;
                    active.retain(|id| id != &job.id);
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
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
