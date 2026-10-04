use crate::config::Settings;
use crate::error::Result;
use crate::models::AuditJob;
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
        /// Pinned snapshot from the submission contract, if the caller gave one.
        requested_sha: Option<String>,
    },
    Housekeeping,
}

/// Resolve the GitHub token for one job: the owner's own connected token when
/// present, the platform token otherwise.
///
/// The stored token is encrypted; a decryption failure falls back to the
/// platform token rather than failing the audit (the fetch phase then reports
/// an honest 404 for a repository the fallback cannot read). The resolved
/// value is passed in-memory to the pipeline and never persisted: installation
/// and OAuth tokens must not become audit data.
pub async fn resolve_github_token(pool: &PgPool, settings: &Settings, user_id: &str) -> String {
    let platform = settings.github_token.clone();
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT github_access_token FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    let Some((Some(encrypted),)) = row else {
        return platform;
    };
    if encrypted.trim().is_empty() {
        return platform;
    }
    match crate::services::crypto::crypto_manager(&settings.secret_key, &settings.encryption_key)
        .and_then(|crypto| {
            crypto
                .decrypt_secret(&encrypted)
                .map_err(|e| anyhow::anyhow!("{e:?}"))
        }) {
        Ok(token) if !token.trim().is_empty() => token,
        Ok(_) => platform,
        Err(e) => {
            warn!("Worker: GitHub token decrypt failed, using platform token: {e:?}");
            platform
        }
    }
}

/// Report a finished job back to GitHub as a Check Run (Phase 19B.7).
///
/// Only for webhook-created jobs (`github_installation_id` set) when the App
/// is configured. Best-effort and silent on failure: reporting must never
/// fail, mutate, or delay the audit itself — the deterministic report is
/// already committed before this runs. The conclusion reflects the *audit
/// outcome* (did the scan complete?), never a verdict on the findings.
pub async fn maybe_post_github_check(pool: &PgPool, settings: &Settings, job_id: &str) {
    use crate::services::github_app::{exchange_installation_token, post_check_run, AppIdentity};

    let job: Option<crate::models::AuditJob> =
        sqlx::query_as::<_, crate::models::AuditJob>("SELECT * FROM audit_jobs WHERE id=$1")
            .bind(job_id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    let installation_id = match job.as_ref() {
        Some(job) if job.github_installation_id.unwrap_or(0) > 0 => {
            job.github_installation_id.unwrap_or(0)
        }
        _ => return,
    };
    let job = job.unwrap();
    let identity = match AppIdentity::from_settings(settings) {
        Ok(Some(identity)) => identity,
        _ => return,
    };

    let conclusion = match job.status {
        crate::models::JobStatus::Completed => "success",
        crate::models::JobStatus::Partial => "neutral",
        crate::models::JobStatus::Cancelled => "cancelled",
        crate::models::JobStatus::EngineUnavailable => "neutral",
        crate::models::JobStatus::Failed => "failure",
        // Not terminal: nothing to report yet.
        crate::models::JobStatus::Queued | crate::models::JobStatus::Running => return,
    };

    let execution: Option<crate::orchestrator::execution::AuditExecution> =
        sqlx::query_as::<_, crate::orchestrator::execution::AuditExecution>(
            "SELECT * FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number DESC LIMIT 1",
        )
        .bind(job_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
    let (attempt, commit, findings) = match execution {
        Some(exec) => {
            let count: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM findings WHERE job_id=$1 AND execution_id=$2")
                    .bind(job_id)
                    .bind(&exec.id)
                    .fetch_one(pool)
                    .await
                    .unwrap_or((0,));
            (exec.attempt_number, exec.commit_sha, count.0)
        }
        None => (0, None, 0),
    };
    let head = match commit
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(job.commit_sha.as_deref())
    {
        Some(head) => head.to_string(),
        // No pinned snapshot (fetch never succeeded): nothing to attach a
        // check to. Reporting here would pin a verdict to the wrong commit.
        None => return,
    };
    let (owner, repo) = match crate::agents::fetch::parse_github_owner_repo(&job.repo_url) {
        Some(pair) => pair,
        None => return,
    };

    let title = format!("Security audit {}", job.status.as_str());
    let summary = format!(
        "Fire Crow audit {status}: {findings} finding(s), score {score}, attempt {attempt}, commit {head}.",
        status = job.status.as_str(),
        score = job
            .security_score
            .map(|s| s.to_string())
            .unwrap_or_else(|| "n/a".into()),
    );

    let result = async {
        let token = exchange_installation_token(
            &crate::agents::fetch::github_api_base(),
            &identity,
            installation_id,
        )
        .await?;
        post_check_run(
            &crate::agents::fetch::github_api_base(),
            token.token(),
            &owner,
            &repo,
            &head,
            conclusion,
            &title,
            &summary,
        )
        .await
        .map(|_| ())
    }
    .await;
    if let Err(e) = result {
        // Best-effort by design: the audit stands regardless.
        warn!("Worker: GitHub check run for job {job_id} failed: {e}");
    }
}
/// Run one audit job, with the hard 30-minute ceiling.
///
/// Both `WorkerTask::execute` and the pool's `worker_loop` funnel through here.
/// They previously carried separate copies of the timeout + failure UPDATE and
/// had drifted: only one guarded its UPDATE on a non-terminal status, so the
/// other could clobber a job that the reaper had already finalised. There is now
/// a single implementation.
///
/// Eight parameters is the settled worker signature (pool + job/user identity +
/// repo triple + delivery/token inputs); same frozen-gate rationale as above.
#[allow(clippy::too_many_arguments)]
pub async fn run_audit_job(
    pool: &PgPool,
    job_id: &str,
    user_id: &str,
    repo_url: &str,
    repo_branch: &str,
    custom_email: Option<&str>,
    github_token: Option<&str>,
    requested_sha: Option<&str>,
) {
    info!("Worker: executing audit job {job_id}");
    let started = std::time::Instant::now();
    let input = crate::orchestrator::ExecutionInput {
        github_token: github_token
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string),
        requested_sha: requested_sha
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    };
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(1800),
        execute_audit_job(
            pool,
            job_id,
            user_id,
            repo_url,
            repo_branch,
            custom_email,
            Some(input),
        ),
    )
    .await
    {
        Ok(Err(e)) => {
            error!("Worker: job {} failed: {}", job_id, e);
            // Phase 12.1: the failure path closes the running execution first
            // (same commit as the job's terminal status) instead of writing
            // `audit_jobs.status` around the execution. Without this a failed
            // pipeline would leave a `running` execution with no ending while
            // the job already reads `failed`.
            let _ = crate::orchestrator::execution::fail_running_execution(
                pool,
                job_id,
                &e.to_string(),
            )
            .await;
        }
        Err(_) => {
            error!("Worker: job {} timed out after 30 minutes", job_id);
            let _ = crate::orchestrator::execution::fail_running_execution(
                pool,
                job_id,
                "Job timed out after 30 minutes",
            )
            .await;
        }
        Ok(Ok(state)) => {
            // 19.11: one structured completion event per audit. Identifiers,
            // outcome, coverage, and counts only — never repository contents,
            // evidence, tokens, or provider bodies.
            info!(
                job_id = %job_id,
                status = state.status.as_str(),
                findings = state.findings.len(),
                score = ?state.security_score,
                coverage_complete = state.coverage_complete,
                analysis_performed = state.analysis_performed,
                duration_ms = started.elapsed().as_millis() as u64,
                "Worker: audit job completed"
            );
        }
    }
}

impl WorkerTask {
    pub async fn execute(self, pool: &PgPool, settings: &Settings) -> Result<()> {
        match self {
            Self::AuditJob {
                job_id,
                user_id,
                repo_url,
                repo_branch,
                custom_email,
                requested_sha,
            } => {
                // Same resolution as the pool loop below: the owner's token
                // when present, the platform token otherwise. Neither funnel
                // may drift from the other.
                let token = resolve_github_token(pool, settings, &user_id).await;
                run_audit_job(
                    pool,
                    &job_id,
                    &user_id,
                    &repo_url,
                    &repo_branch,
                    custom_email.as_deref(),
                    Some(&token),
                    requested_sha.as_deref(),
                )
                .await;
                // Reporting back never reopens the audit: the job is terminal
                // and the check reflects its recorded outcome.
                maybe_post_github_check(pool, settings, &job_id).await;
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

                // Phase 12: the reaper no longer writes a terminal status for a
                // cancellation. A cancellation is decided by the owning execution
                // inside its finalization transaction, so that a request racing a
                // successful run is resolved by the database rather than by which
                // writer happened to run last. The reaper's job is only to notice
                // executions whose owner has stopped heartbeating (below).

                // Find potentially orphaned jobs. The reaper measures how long a
                // job has been *running* (`started_at`, stamped at claim time),
                // not how long ago it was created, so a job that sat in the queue
                // for a long time is not reaped before it ever starts.
                // Phase 12.1: this scan is retired. Elapsed `started_at` time is
                // not evidence of death once executions carry heartbeats: a slow
                // but alive scan heartbeats every phase while a dead worker
                // stops. Only the heartbeat-cutoff reap below may close an
                // execution; nothing here writes a terminal status.
                let stale_cutoff = chrono::Utc::now() - chrono::Duration::minutes(10);
                let _ = stale_cutoff;

                // Phase 12.1: the reaper closes executions through the lease-aware
                // `reap_abandoned_execution`, which proves abandonment with the
                // heartbeat cutoff and releases the job back to `queued` only
                // when no live execution remains. The old unconditional UPDATE
                // closed executions a live worker had just heartbeated, and the
                // orphaned-job scan below it is retired: elapsed `started_at`
                // time is not evidence of death once heartbeats exist.
                let stale_execution_cutoff = chrono::Utc::now() - chrono::Duration::minutes(10);
                let abandoned: Vec<(String, String)> = sqlx::query_as(
                    "SELECT id, job_id FROM audit_executions
                      WHERE status='running'
                        AND COALESCE(heartbeat_at, started_at) < $1",
                )
                .bind(stale_execution_cutoff.naive_utc())
                .fetch_all(&pool)
                .await
                .unwrap_or_default();

                for (execution_id, job_id) in abandoned {
                    warn!(
                        "Reaping abandoned execution {execution_id} of job {job_id} (owner stopped heartbeating)"
                    );
                    let _ = crate::orchestrator::execution::reap_abandoned_execution(
                        &pool,
                        &execution_id,
                        &stale_execution_cutoff.naive_utc(),
                        "execution owner stopped heartbeating (recovered by reaper)",
                    )
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

    /// Worker loop: uses atomic `FOR UPDATE SKIP LOCKED` to claim exactly one job.
    /// Multiple workers can run concurrently without racing on the same job.
    async fn worker_loop(
        id: usize,
        pool: sqlx::PgPool,
        settings: Settings,
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
                // failure write all live in `run_audit_job`), with the same
                // token resolution as `WorkerTask::execute`.
                let token = resolve_github_token(&pool, &settings, &job.user_id).await;
                run_audit_job(
                    &pool,
                    &job.id,
                    &job.user_id,
                    &job.repo_url,
                    &job.repo_branch,
                    None,
                    Some(&token),
                    job.requested_commit_sha.as_deref(),
                )
                .await;
                maybe_post_github_check(&pool, &settings, &job.id).await;

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
