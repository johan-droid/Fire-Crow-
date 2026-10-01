//! Audit job orchestrator — replaces LangGraph + Celery.

use crate::error::{AppError, Result};
use crate::schemas::audit_state::AuditState;
use crate::utils::generate_uuid;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub async fn execute_audit_job(
    pool: &PgPool,
    job_id: &str,
    user_id: &str,
    repo_url: &str,
    repo_branch: &str,
    custom_email: Option<&str>,
    _unused_graph: Option<()>,
) -> Result<AuditState> {
    let mut state = AuditState {
        job_id: job_id.into(),
        user_id: user_id.into(),
        repo_url: repo_url.into(),
        repo_branch: repo_branch.into(),
        custom_email: custom_email.unwrap_or("").into(),
        created_at: Utc::now(),
        status: crate::models::JobStatus::Running,
        current_phase: "intake".into(),
        ..Default::default()
    };

    // Ensure job is marked as running in database (idempotent safety).
    // Never resurrect a job that already reached a terminal state.
    let _ = sqlx::query(
        "UPDATE audit_jobs SET status=$1 WHERE id=$2 AND status IN ('queued', 'running')",
    )
    .bind(crate::models::JobStatus::Running)
    .bind(job_id)
    .execute(pool)
    .await;

    tracing::info!(
        "[orchestrator] Starting job {} for repo {} at {}",
        job_id,
        repo_url,
        Utc::now().to_rfc3339()
    );

    // State machine outcome tracking. Failure and cancellation are distinct
    // terminal outcomes — never conflate them.
    let cancelled = false;
    let failure: Option<(String, String)> = None; // (phase, error)

    // Phase 1: Intake
    let started = Utc::now();
    log_phase_started(pool, job_id, "intake").await?;
    state.repo_owner = extract_repo_owner(repo_url);
    state.repo_name = extract_repo_name(repo_url);
    log_phase_completed(pool, job_id, "intake", "completed", started, None).await?;

    // ---------------------------------------------------------------------
    // Analysis phases
    //
    // security_p0_c: every phase here used to run a fabricating stand-in. The
    // SAST agent returned three hardcoded findings naming src/config.rs:42,
    // src/db/queries.rs:118 and src/middleware/cors.rs:15 with CVSS 9.8/8.5/5.3
    // for every repository, without opening a file; recon returned a fixed
    // five-entry tech stack; the "AI" analyzer copied its input to its own
    // output after a 400 ms sleep. Those functions have been deleted.
    //
    // No engine is installed, so there is no analysis phase to run. The job
    // terminates as EngineUnavailable with zero findings and a NULL score, so it
    // can never be mistaken for a clean result. Notably, a score derived from
    // zero findings would be 10.0 "low risk" - the most misleading output this
    // product could produce - which is why the score is left null instead.
    //
    // A real engine adds its phases in the `else` position below and is gated by
    // the same constant.
    // ---------------------------------------------------------------------
    let engine_available = crate::agents::ENGINE_AVAILABLE;
    if !engine_available {
        tracing::warn!(
            "[orchestrator] Job {}: {} (engine={})",
            job_id,
            crate::agents::ENGINE_UNAVAILABLE_REASON,
            crate::agents::ENGINE_NAME
        );
        state.current_phase = "engine_unavailable".into();
        // No finding rows, no scoring, no attack graph, no report.
        state.static_findings.clear();
        state.dynamic_findings.clear();
        state.scored_findings.clear();
        state.validated_findings.clear();
        state.security_score = None;
        state.risk_summary = serde_json::json!({
            "score": null,
            "risk_level": "unknown",
            "total_findings": 0,
            "analysis_performed": false,
        });
        log_phase_skipped(
            pool,
            job_id,
            "engine_unavailable",
            crate::agents::ENGINE_UNAVAILABLE_REASON,
        )
        .await?;
    } else {
        unreachable!(
            "no vulnerability analysis engine is compiled into this build; \
             {} reports ENGINE_AVAILABLE=true without providing one",
            crate::agents::ENGINE_NAME
        );
    }

    // Finalize. Writes are guarded on non-terminal statuses so we never
    // overwrite a result recorded by the timeout handler or orphan reaper.
    // Failure wins over cancellation; cancellation wins over completion.
    let final_status = if failure.is_some() {
        crate::models::JobStatus::Failed
    } else if cancelled || is_cancelled(pool, job_id).await? {
        crate::models::JobStatus::Cancelled
    } else if !engine_available {
        // security_p0_c: an unavailable engine must never resolve to Completed.
        // Completed means "an engine ran"; here nothing ran.
        crate::models::JobStatus::EngineUnavailable
    } else {
        crate::models::JobStatus::Completed
    };

    let _ = sqlx::query(
        "UPDATE phase_ledger SET status='skipped', ended_at=$1 WHERE job_id=$2 AND status='started'"
    )
    .bind(Utc::now().naive_utc())
    .bind(job_id)
    .execute(pool)
    .await;

    match final_status {
        crate::models::JobStatus::Failed => {
            let (phase, msg) = failure.as_ref().expect("failure set for Failed status");
            tracing::error!(
                "[orchestrator] Job {} failed during {}: {}",
                job_id,
                phase,
                msg
            );
            state.status = crate::models::JobStatus::Failed;
            state.current_phase = format!("failed:{}", phase);
            sqlx::query("UPDATE audit_jobs SET status=$1, finished_at=$2, error_message=$3 WHERE id=$4 AND status IN ('queued','running')")
                .bind(crate::models::JobStatus::Failed)
                .bind(Utc::now().naive_utc())
                .bind(format!("{} phase failed: {}", phase, msg))
                .bind(job_id)
                .execute(pool)
                .await
                .map_err(AppError::Database)?;
        }
        crate::models::JobStatus::EngineUnavailable => {
            // Persist the truthful state: no findings were produced, no score was
            // computed, and the reason is recorded for the operator.
            state.status = crate::models::JobStatus::EngineUnavailable;
            state.report_delivered = false;
            state.current_phase = "engine_unavailable".into();
            state.security_score = None;
            sqlx::query("UPDATE audit_jobs SET status=$1, finished_at=$2, security_score=NULL, error_message=$3 WHERE id=$4 AND status IN ('queued','running')")
                .bind(crate::models::JobStatus::EngineUnavailable)
                .bind(Utc::now().naive_utc())
                .bind(crate::agents::ENGINE_UNAVAILABLE_REASON)
                .bind(job_id)
                .execute(pool)
                .await
                .map_err(AppError::Database)?;
        }
        crate::models::JobStatus::Cancelled => {
            state.status = crate::models::JobStatus::Cancelled;
            state.current_phase = "cancelled".into();
            sqlx::query("UPDATE audit_jobs SET status=$1, finished_at=$2, error_message=$3 WHERE id=$4 AND status IN ('queued','running')")
                .bind(crate::models::JobStatus::Cancelled)
                .bind(Utc::now().naive_utc())
                .bind("Job cancelled by user")
                .bind(job_id)
                .execute(pool)
                .await
                .map_err(AppError::Database)?;
        }
        _ => {
            state.status = crate::models::JobStatus::Completed;
            state.report_delivered = true;
            state.current_phase = "complete".into();
            sqlx::query("UPDATE audit_jobs SET status=$1, finished_at=$2, security_score=$3, error_message=NULL WHERE id=$4 AND status IN ('queued','running')")
                .bind(crate::models::JobStatus::Completed)
                .bind(Utc::now().naive_utc())
                .bind(state.security_score.unwrap_or(0.0))
                .bind(job_id)
                .execute(pool)
                .await
                .map_err(AppError::Database)?;
        }
    }

    tracing::info!(
        "[orchestrator] Job {} finalized with status {:?} and score {:?}",
        job_id,
        state.status,
        state.security_score
    );
    Ok(state)
}

async fn is_cancelled(pool: &PgPool, job_id: &str) -> Result<bool> {
    let row = sqlx::query_as::<_, (bool,)>("SELECT cancel_requested FROM audit_jobs WHERE id=$1")
        .bind(job_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::Database)?;
    Ok(row.map(|(cancelled,)| cancelled).unwrap_or(false))
}

fn extract_repo_owner(url: &str) -> String {
    let cleaned = url.trim_end_matches('/').trim_end_matches(".git");
    if cleaned.contains("git@") {
        cleaned
            .split(':')
            .next_back()
            .unwrap_or("")
            .split('/')
            .next()
            .unwrap_or("")
            .into()
    } else {
        cleaned.split('/').nth_back(1).unwrap_or("").into()
    }
}

fn extract_repo_name(url: &str) -> String {
    let cleaned = url.trim_end_matches('/').trim_end_matches(".git");
    cleaned.split('/').next_back().unwrap_or("repo").into()
}
/// Record a phase that never ran.
///
/// `log_phase_completed` only updates a row that `log_phase_started` inserted,
/// so it silently does nothing for a phase that was skipped before starting.
/// That hid the unavailability from the ledger. This inserts the terminal row
/// directly, with `mode='skipped'` so it is distinguishable from real work.
async fn log_phase_skipped(pool: &PgPool, job_id: &str, phase: &str, reason: &str) -> Result<()> {
    let now = Utc::now().naive_utc();
    let _ = sqlx::query("INSERT INTO phase_ledger (id, job_id, phase_name, status, mode, started_at, ended_at, duration_sec, error_message) VALUES ($1,$2,$3,'skipped','skipped',$4,$4,0,$5)")
        .bind(generate_uuid())
        .bind(job_id)
        .bind(phase)
        .bind(now)
        .bind(reason)
        .execute(pool)
        .await;
    Ok(())
}

async fn log_phase_started(pool: &PgPool, job_id: &str, phase: &str) -> Result<()> {
    let id = generate_uuid();
    let _ = sqlx::query("INSERT INTO phase_ledger (id, job_id, phase_name, status, mode, started_at) VALUES ($1,$2,$3,'started','real',$4)")
        .bind(id).bind(job_id).bind(phase).bind(Utc::now().naive_utc()).execute(pool).await;
    Ok(())
}
async fn log_phase_completed(
    pool: &PgPool,
    job_id: &str,
    phase: &str,
    status: &str,
    started_at: DateTime<Utc>,
    error_message: Option<String>,
) -> Result<()> {
    let ended_at = Utc::now();
    let duration = (ended_at - started_at).num_milliseconds() as f64 / 1000.0;
    let _ = sqlx::query("UPDATE phase_ledger SET status=$1, ended_at=$2, duration_sec=$3, error_message=$4 WHERE id IN (SELECT id FROM phase_ledger WHERE job_id=$5 AND phase_name=$6 AND status='started' ORDER BY started_at DESC LIMIT 1)")
        .bind(status).bind(ended_at.naive_utc()).bind(duration).bind(error_message).bind(job_id).bind(phase).execute(pool).await;
    Ok(())
}
