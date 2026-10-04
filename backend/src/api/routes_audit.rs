use crate::error::{AppError, Result};
use crate::schemas::audit_api::*;
use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/submit", post(submit_audit))
        .route("/jobs", get(list_jobs))
        .route("/privacy-logs", get(list_privacy_logs))
        .route("/job/:job_id", get(get_job_detail).delete(cancel_job))
        .route("/job/:job_id/retry", post(retry_job))
        .route("/job/:job_id/phases", get(get_job_phases))
        // Phase 19.6: the attempt history. Retries are never flattened into
        // one mutable audit — each execution is listed with its own status,
        // snapshot, coverage, and delivery outcome.
        .route("/job/:job_id/executions", get(list_job_executions))
        .route("/job/:job_id/report", get(download_report))
        // Historical reports are addressed by execution id explicitly, so a
        // retry can never be mistaken for the attempt the caller wants.
        .route(
            "/job/:job_id/execution/:execution_id/report",
            get(download_execution_report),
        )
        // The AI narrative is addressed the same way, and only alongside the
        // execution it explains. There is deliberately no job-level "narrative"
        // route: one would have to pick an attempt, and a retried job has one
        // narrative per attempt.
        .route(
            "/job/:job_id/execution/:execution_id/narrative",
            get(download_execution_narrative).post(generate_execution_narrative),
        )
        // Delivery is execution-scoped. A job-level email route is ambiguous by
        // construction: a retried job has one report per attempt, so the route
        // would have to guess which attempt the caller meant.
        .route(
            "/job/:job_id/execution/:execution_id/email",
            post(email_execution_report),
        )
        // Telegram, same execution-scoped shape and the same guarantees. The chat
        // is operator configuration, never a request parameter, so this route has
        // no way to redirect a report.
        .route(
            "/job/:job_id/execution/:execution_id/telegram",
            post(telegram_execution_report),
        )
        .route("/job/:job_id/insight", get(get_job_insight))
        .route("/job/:job_id/graph", get(get_attack_graph))
}

pub async fn submit_audit(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(req): Json<SubmitJobRequest>,
) -> Result<Json<JobResponse>> {
    // One door: URL validation, SHA shape, and the backpressure gate all live
    // in `create_audit_job`, shared with webhook-created jobs.
    let job_id = create_audit_job(
        state.pool(),
        state.settings().max_active_jobs_per_user.max(1) as i64,
        &user.user_id,
        (!user.tenant_id.is_empty()).then_some(user.tenant_id.as_str()),
        &req.repo_url,
        req.repo_branch.as_deref().unwrap_or("main"),
        req.commit_sha.as_deref(),
    )
    .await?;
    let job: crate::models::AuditJob =
        sqlx::query_as::<_, crate::models::AuditJob>("SELECT * FROM audit_jobs WHERE id=$1")
            .bind(&job_id)
            .fetch_one(state.pool())
            .await
            .map_err(AppError::Database)?;
    Ok(Json(JobResponse::from(job)))
}

/// Attribution for a webhook-created job: which delivery produced it and
/// which installation authorized it. The delivery ID makes creation
/// idempotent (one delivery → at most one job); the installation ID is
/// attribution for reporting back, never a substitute for live authorization.
#[derive(Debug, Clone)]
pub struct WebhookJob {
    pub delivery_id: String,
    pub installation_id: i64,
}

/// The single audit-job creation path.
///
/// `submit_audit` (user request) and the GitHub webhook (verified push/PR
/// events, 19B.6) both funnel through here, so there is exactly one door
/// with one set of validation, one backpressure gate, and one insert. There
/// is no second audit pipeline: a webhook-created job is indistinguishable
/// from a user-submitted one from this point on.
pub async fn create_audit_job(
    pool: &sqlx::PgPool,
    max_active_jobs: i64,
    user_id: &str,
    tenant_id: Option<&str>,
    repo_url: &str,
    repo_branch: &str,
    requested_sha: Option<&str>,
) -> Result<String> {
    create_audit_job_attributed(
        pool,
        max_active_jobs,
        user_id,
        tenant_id,
        repo_url,
        repo_branch,
        requested_sha,
        None,
    )
    .await
}

/// [`create_audit_job`], plus webhook attribution for deliveries.
///
/// A redelivered event finds the existing job instead of queueing a second
/// audit: the insert is `ON CONFLICT DO NOTHING` on the delivery ID, and a
/// zero-row insert falls back to selecting the row the first attempt wrote.
/// Crash between "job created" and "delivery marked processed" is therefore
/// a duplicate acknowledgement, never a duplicate job.
///
/// Eight parameters is the settled gate signature (pool + cap + identity +
/// repo triple + webhook attribution); splitting it into a params struct is
/// a refactor, not a defect fix, and is deferred out of the frozen gate.
#[allow(clippy::too_many_arguments)]
pub async fn create_audit_job_attributed(
    pool: &sqlx::PgPool,
    max_active_jobs: i64,
    user_id: &str,
    tenant_id: Option<&str>,
    repo_url: &str,
    repo_branch: &str,
    requested_sha: Option<&str>,
    webhook: Option<WebhookJob>,
) -> Result<String> {
    validate_github_repo_url(repo_url)?;

    let sha = match requested_sha.map(str::trim) {
        None | Some("") => None,
        Some(sha) if crate::agents::fetch::is_valid_commit_sha(sha) => Some(sha.to_string()),
        Some(_) => {
            return Err(AppError::BadRequest(
                "commit_sha must be a 40-character lowercase hex commit digest".into(),
            ));
        }
    };

    let max_active = max_active_jobs.max(1);
    if let Some(attribution) = webhook.as_ref() {
        // A redelivery finds its job before any gate: backpressure must never
        // turn a retry into a lost audit.
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT id FROM audit_jobs WHERE webhook_delivery_id = $1")
                .bind(&attribution.delivery_id)
                .fetch_optional(pool)
                .await
                .map_err(AppError::Database)?;
        if let Some((existing,)) = existing {
            return Ok(existing);
        }
    }
    // Phase 20: the gate and the insert must be one atomic step.
    //
    // `SELECT COUNT(*)` followed by a bare `INSERT` is a read-then-write race:
    // concurrent submissions all observe the same live count and all insert,
    // so a user could queue far past `max_active_jobs_per_user`. Under a
    // webhook flood that is exactly the unbounded job producer backpressure
    // is meant to prevent.
    //
    // An advisory lock keyed on the user id serializes this path per user
    // (different users never block each other), and a transaction makes the
    // count-then-insert atomic. Lock is transaction-scoped, so it is released
    // on commit, rollback, or connection loss — including a crash mid-insert.
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    let live: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_jobs WHERE user_id=$1 AND status IN ('queued','running')",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    if live.0 >= max_active {
        return Err(AppError::Conflict(format!(
            "too many active audits ({live_0}/{max_active}); wait for one to finish or cancel it",
            live_0 = live.0,
        )));
    }

    let job_id = uuid::Uuid::new_v4().to_string();
    let inserted = if let Some(attribution) = webhook.as_ref() {
        sqlx::query("INSERT INTO audit_jobs (id, user_id, tenant_id, repo_url, repo_branch, requested_commit_sha, webhook_delivery_id, github_installation_id, status, cancel_requested, legal_hold, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (webhook_delivery_id) DO NOTHING")
            .bind(&job_id)
            .bind(user_id)
            .bind(tenant_id)
            .bind(repo_url)
            .bind(repo_branch)
            .bind(sha.as_deref())
            .bind(&attribution.delivery_id)
            .bind(attribution.installation_id)
            .bind(crate::models::JobStatus::Queued)
            .bind(false)
            .bind(false)
            .bind(chrono::Utc::now().naive_utc())
            .execute(&mut *tx).await.map_err(AppError::Database)?
    } else {
        sqlx::query("INSERT INTO audit_jobs (id, user_id, tenant_id, repo_url, repo_branch, requested_commit_sha, status, cancel_requested, legal_hold, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(&job_id)
            .bind(user_id)
            .bind(tenant_id)
            .bind(repo_url)
            .bind(repo_branch)
            .bind(sha.as_deref())
            .bind(crate::models::JobStatus::Queued)
            .bind(false)
            .bind(false)
            .bind(chrono::Utc::now().naive_utc())
            .execute(&mut *tx).await.map_err(AppError::Database)?
    };
    tx.commit().await.map_err(AppError::Database)?;

    if inserted.rows_affected() == 0 {
        // A redelivery raced the first attempt: return the job it wrote.
        let existing: Option<(String,)> =
            sqlx::query_as("SELECT id FROM audit_jobs WHERE webhook_delivery_id = $1")
                .bind(webhook.map(|w| w.delivery_id).unwrap_or_default())
                .fetch_optional(pool)
                .await
                .map_err(AppError::Database)?;
        if let Some((existing,)) = existing {
            return Ok(existing);
        }
    }
    Ok(job_id)
}

pub async fn list_jobs(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<JobResponse>>> {
    let jobs: Vec<crate::models::AuditJob> = sqlx::query_as::<_, crate::models::AuditJob>(
        "SELECT * FROM audit_jobs WHERE user_id=$1 ORDER BY created_at DESC",
    )
    .bind(&user.user_id)
    .fetch_all(state.pool())
    .await
    .map_err(AppError::Database)?;
    Ok(Json(jobs.into_iter().map(JobResponse::from).collect()))
}

pub async fn get_job_detail(
    State(state): State<Arc<crate::AppState>>,
    Path(job_id): Path<String>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<JobDetailResponse>> {
    let job: crate::models::AuditJob = sqlx::query_as::<_, crate::models::AuditJob>(
        "SELECT * FROM audit_jobs WHERE id=$1 AND user_id=$2",
    )
    .bind(&job_id)
    .bind(&user.user_id)
    .fetch_optional(state.pool())
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound("Job not found".into()))?;
    // Phase 12.1: the API reconstructs the audit from the latest execution,
    // never by mixing attempts. Findings come from the attempt the pipeline
    // finalized; the execution summary below is read from the same persisted
    // rows (`audit_executions`, `audit_scanner_runs`, canonical JSON).
    let findings: Vec<crate::models::FindingModel> =
        sqlx::query_as::<_, crate::models::FindingModel>(
            "SELECT f.* FROM findings f
              WHERE f.job_id=$1
                AND (f.execution_id = (SELECT id FROM audit_executions
                                       WHERE job_id=$1 ORDER BY attempt_number DESC LIMIT 1)
                     OR (f.execution_id IS NULL
                         AND NOT EXISTS (SELECT 1 FROM audit_executions WHERE job_id=$1)))",
        )
        .bind(&job_id)
        .fetch_all(state.pool())
        .await
        .map_err(AppError::Database)?;
    let execution: Option<crate::orchestrator::execution::AuditExecution> =
        sqlx::query_as::<_, crate::orchestrator::execution::AuditExecution>(
            "SELECT * FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number DESC LIMIT 1",
        )
        .bind(&job_id)
        .fetch_optional(state.pool())
        .await
        .map_err(AppError::Database)?;
    let mut detail = JobDetailResponse {
        job: JobResponse::from(job),
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        execution_id: None,
        attempt_number: None,
        canonical_json: None,
    };
    if let Some(exec) = execution {
        detail.execution_id = Some(exec.id);
        detail.attempt_number = Some(exec.attempt_number);
        detail.canonical_json = exec.canonical_json;
    }
    Ok(Json(detail))
}

pub async fn cancel_job(
    State(state): State<Arc<crate::AppState>>,
    Path(job_id): Path<String>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    // Phase 12: cancellation is a *request*, not a terminal write.
    //
    // This endpoint used to set `status='cancelled'` directly, which let the API
    // move an audit to a terminal state while its worker was still mid-pipeline.
    // The worker would then keep scanning and persisting, and whichever writer
    // ran last decided the outcome — a timing race. Now the request is recorded
    // and the owning execution decides, inside its finalization transaction:
    // a cancellation that arrives before finalization always wins, and one that
    // arrives after the audit is already terminal finds nothing to cancel.
    //
    // Only queued/running audits can be cancelled; a finished audit is immutable.
    let result = sqlx::query(
        "UPDATE audit_jobs SET cancel_requested=true, cancel_requested_at=$1
         WHERE id=$2 AND user_id=$3 AND status IN ('queued','running')",
    )
    .bind(chrono::Utc::now().naive_utc())
    .bind(&job_id)
    .bind(&user.user_id)
    .execute(state.pool())
    .await
    .map_err(AppError::Database)?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "Job not found, already finished, or access denied".into(),
        ));
    }
    Ok(Json(
        serde_json::json!({"status": "cancellation_requested"}),
    ))
}

pub async fn retry_job(
    State(state): State<Arc<crate::AppState>>,
    Path(job_id): Path<String>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    // Phase 12.1 retry: cancelled/failed/partial/engine_unavailable becomes
    // runnable again; the previous execution stays immutable and the retry is
    // a *new* execution (attempt N+1). Terminal completed/partial successes
    // are historical records and are never reopened by a retry — partial
    // retries through the same path when fresh evidence is wanted.
    let job: crate::models::AuditJob = sqlx::query_as::<_, crate::models::AuditJob>(
        "SELECT * FROM audit_jobs WHERE id=$1 AND user_id=$2",
    )
    .bind(&job_id)
    .bind(&user.user_id)
    .fetch_optional(state.pool())
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound("Job not found".into()))?;
    if matches!(
        job.status,
        crate::models::JobStatus::Completed
            | crate::models::JobStatus::Running
            | crate::models::JobStatus::Queued
    ) {
        return Err(AppError::Conflict(format!(
            "job {} is {} and cannot be retried",
            job_id,
            job.status.as_str()
        )));
    }
    // Refuse while an execution is still running: a retry must be a new
    // attempt, never a second concurrent owner of the same audit.
    let live: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_executions WHERE job_id=$1 AND status='running'",
    )
    .bind(&job_id)
    .fetch_one(state.pool())
    .await
    .map_err(AppError::Database)?;
    if live.0 > 0 {
        return Err(AppError::Conflict(format!(
            "job {job_id} already has a running execution"
        )));
    }
    let result = sqlx::query(
        "UPDATE audit_jobs SET status='queued', cancel_requested=false,
                cancel_requested_at=NULL, error_message=NULL
          WHERE id=$1 AND user_id=$2
            AND status IN ('failed','cancelled','partial','engine_unavailable')",
    )
    .bind(&job_id)
    .bind(&user.user_id)
    .execute(state.pool())
    .await
    .map_err(AppError::Database)?;
    if result.rows_affected() == 0 {
        return Err(AppError::Conflict(format!(
            "job {job_id} cannot be retried from its current state"
        )));
    }
    Ok(Json(serde_json::json!({"status": "queued"})))
}

/// The requested presentation of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReportFormat {
    Markdown,
    Json,
    Html,
}

impl ReportFormat {
    fn from_query(query: &crate::schemas::audit_api::ReportQuery) -> Result<Self> {
        match query.format.as_deref().map(str::trim) {
            None | Some("") | Some("markdown") | Some("md") => Ok(Self::Markdown),
            Some("json") => Ok(Self::Json),
            Some("html") => Ok(Self::Html),
            Some(other) => Err(AppError::BadRequest(format!(
                "unsupported report format '{other}'; expected markdown, json, or html"
            ))),
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            Self::Markdown => "text/markdown; charset=utf-8",
            Self::Json => "application/json; charset=utf-8",
            Self::Html => "text/html; charset=utf-8",
        }
    }
}

fn report_response(format: ReportFormat, body: String) -> axum::response::Response {
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", format.content_type())
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// Latest finalized report for a job.
pub async fn download_report(
    State(state): State<Arc<crate::AppState>>,
    Path(job_id): Path<String>,
    user: crate::middleware::auth::AuthenticatedUser,
    Query(query): Query<crate::schemas::audit_api::ReportQuery>,
) -> Result<axum::response::Response> {
    serve_report(
        state,
        job_id,
        user.user_id,
        None,
        ReportFormat::from_query(&query)?,
    )
    .await
}

/// Report for a specific (historical) execution of a job.
pub async fn download_execution_report(
    State(state): State<Arc<crate::AppState>>,
    Path((job_id, execution_id)): Path<(String, String)>,
    user: crate::middleware::auth::AuthenticatedUser,
    Query(query): Query<crate::schemas::audit_api::ReportQuery>,
) -> Result<axum::response::Response> {
    serve_report(
        state,
        job_id,
        user.user_id,
        Some(execution_id),
        ReportFormat::from_query(&query)?,
    )
    .await
}

/// Serve a report for a job the caller owns.
///
/// The persisted report is preferred because it was committed atomically with
/// the execution and is therefore byte-stable. If it is absent, the report is
/// rebuilt deterministically from the execution's canonical audit — the same
/// source of truth, never a fresh read of the database's findings. A running or
/// report-less execution surfaces as a conflict, never as an invented report.
async fn serve_report(
    state: Arc<crate::AppState>,
    job_id: String,
    user_id: String,
    execution_id: Option<String>,
    format: ReportFormat,
) -> Result<axum::response::Response> {
    let owns: Option<(String,)> =
        sqlx::query_as("SELECT id FROM audit_jobs WHERE id=$1 AND user_id=$2")
            .bind(&job_id)
            .bind(&user_id)
            .fetch_optional(state.pool())
            .await
            .map_err(AppError::Database)?;
    if owns.is_none() {
        return Err(AppError::NotFound("Job not found".into()));
    }

    if let Some(stored) = crate::orchestrator::execution::load_stored_report(
        state.pool(),
        &job_id,
        execution_id.as_deref(),
    )
    .await?
    {
        let body = match format {
            ReportFormat::Markdown => stored.markdown,
            ReportFormat::Json => stored.json.map(|value| {
                let mut rendered =
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string());
                rendered.push('\n');
                rendered
            }),
            ReportFormat::Html => stored.html,
        };
        if let Some(body) = body {
            return Ok(report_response(format, body));
        }
    }

    let Some(source) = crate::orchestrator::execution::reconstruct_report_source(
        state.pool(),
        &job_id,
        execution_id.as_deref(),
    )
    .await?
    else {
        return Err(AppError::NotFound("Report not found".into()));
    };
    let identity = crate::schemas::report::ExecutionIdentity {
        execution_id: source.execution_id.clone(),
        attempt_number: source.attempt_number,
    };
    let report = crate::schemas::report::build_report(&source.audit, &identity)
        .map_err(|error| AppError::Internal(error.to_string()))?;
    let body = match format {
        ReportFormat::Markdown => {
            crate::services::reporter::ReportGenerator::render_markdown(&report)?
        }
        ReportFormat::Json => crate::services::reporter::ReportGenerator::render_json(&report)?,
        ReportFormat::Html => crate::services::reporter::ReportGenerator::render_html(&report)?,
    };
    Ok(report_response(format, body))
}

/// The validated AI narrative persisted for one execution of a job.
///
/// Only an already-validated narrative is ever stored, so serving it back
/// requires no re-validation and cannot introduce a claim the Phase 14
/// validator refused. Raw model output has no route to the client.
pub async fn download_execution_narrative(
    State(state): State<Arc<crate::AppState>>,
    Path((job_id, execution_id)): Path<(String, String)>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    // Ownership first: a caller must not learn that an execution exists for
    // somebody else's job.
    let owns: Option<(String,)> =
        sqlx::query_as("SELECT id FROM audit_jobs WHERE id=$1 AND user_id=$2")
            .bind(&job_id)
            .bind(&user.user_id)
            .fetch_optional(state.pool())
            .await
            .map_err(AppError::Database)?;
    if owns.is_none() {
        return Err(AppError::NotFound("Job not found".into()));
    }
    // Execution-scoped: the lookup is keyed by the execution the caller named,
    // so a retried job can never return the wrong attempt's narrative. An
    // execution that belongs to another job simply does not resolve.
    let Some(stored) = crate::orchestrator::execution::load_ai_narrative(
        state.pool(),
        &job_id,
        Some(&execution_id),
    )
    .await?
    else {
        return Err(AppError::NotFound("AI narrative not found".into()));
    };
    Ok(Json(serde_json::json!({
        "execution_id": stored.execution_id,
        "attempt_number": stored.attempt_number,
        "narrative_schema_version": stored.narrative_schema_version,
        "narrative": stored.narrative,
    })))
}

/// Explain one execution, on explicit request.
///
/// A `POST` rather than an automatic step in the scan pipeline, because the
/// deterministic audit is already complete and valid without it. Fire Crow stays
/// fully functional when the AI provider is unavailable; this route is the only
/// place that can fail because of it, and its failure leaves the audit
/// untouched.
///
/// Idempotent: an execution that already has a narrative returns it unchanged
/// rather than paying for a second generation.
pub async fn generate_execution_narrative(
    State(state): State<Arc<crate::AppState>>,
    Path((job_id, execution_id)): Path<(String, String)>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    // Ownership first: never spend a model call, or reveal that an execution
    // exists, on somebody else's job.
    let owns: Option<(String,)> =
        sqlx::query_as("SELECT id FROM audit_jobs WHERE id=$1 AND user_id=$2")
            .bind(&job_id)
            .bind(&user.user_id)
            .fetch_optional(state.pool())
            .await
            .map_err(AppError::Database)?;
    if owns.is_none() {
        return Err(AppError::NotFound("Job not found".into()));
    }

    let model_config = crate::services::narrative::ModelConfig::from_settings(state.settings());
    // The transport is constructed *inside* the generation step, not here. An
    // unconfigured AI layer must not mask the answer to "does this execution
    // exist and is it yours": a missing credential is reported only once there
    // is a finalized report to explain.
    let settings = state.settings().clone();
    let generation_config = model_config.clone();
    let stored = crate::orchestrator::ai_narrative::ensure_ai_narrative(
        state.pool(),
        &job_id,
        &execution_id,
        &model_config,
        move |prompt| {
            let settings = settings.clone();
            let generation_config = generation_config.clone();
            async move {
                // The Phase 15B boundary speaks AppError; the provider's own
                // failure classes are preserved rather than flattened to a string.
                let provider = crate::services::llm_provider::ProviderClient::from_model_config(
                    &generation_config,
                    crate::services::llm_provider::DEFAULT_BASE_URL,
                )
                .map_err(AppError::from)?;
                provider.complete(&prompt).await.map_err(AppError::from)
            }
        },
    )
    .await?;

    Ok(Json(serde_json::json!({
        "execution_id": stored.execution_id,
        "attempt_number": stored.attempt_number,
        "narrative_schema_version": stored.narrative_schema_version,
        "narrative": stored.narrative,
    })))
}

/// Deliver one execution's report by email.
///
/// Execution-scoped on purpose. Ownership is checked before anything else, so a
/// foreign execution is indistinguishable from a nonexistent one.
pub async fn email_execution_report(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Path((job_id, execution_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    use crate::services::email::EmailService;

    // Ownership first: never reveal that somebody else's execution exists, and
    // never send them a report.
    let owns: Option<(String,)> =
        sqlx::query_as("SELECT id FROM audit_jobs WHERE id=$1 AND user_id=$2")
            .bind(&job_id)
            .bind(&user.user_id)
            .fetch_optional(state.pool())
            .await
            .map_err(AppError::Database)?;
    if owns.is_none() {
        return Err(AppError::NotFound("Job not found".into()));
    }

    // The recipient is the authenticated account's own address. It comes from
    // the application database, never from the request, scanner output, or model
    // output, so no untrusted input can redirect a report.
    let recipient: String =
        sqlx::query_as::<_, (Option<String>,)>("SELECT email FROM users WHERE id=$1")
            .bind(&user.user_id)
            .fetch_optional(state.pool())
            .await
            .map_err(AppError::Database)?
            .and_then(|(email,)| email)
            .filter(|email| !email.trim().is_empty())
            .ok_or_else(|| {
                AppError::BadRequest("No email address on file for this account".into())
            })?;

    // Resolve the execution and its finalized report *before* touching the mail
    // configuration. A running execution is a 409 about the audit, and must not
    // be masked by an unrelated 501 about the server's SMTP setup.
    let artifact = crate::orchestrator::delivery::finalized_email_artifact(
        state.pool(),
        &job_id,
        &execution_id,
    )
    .await?;

    // An unconfigured mail server is reported honestly rather than as a queued
    // message that will never be sent.
    let Some(mailer) = EmailService::from_settings(state.settings()) else {
        return Err(AppError::Delivery(
            crate::error::DeliveryError::NotConfigured,
        ));
    };

    let outcome = crate::orchestrator::delivery::deliver_execution_email(
        state.pool(),
        &job_id,
        &execution_id,
        &recipient,
        &mailer,
        &artifact,
    )
    .await?;

    let status = crate::orchestrator::delivery::delivery_state(
        state.pool(),
        &crate::orchestrator::delivery::DeliveryKey {
            execution_id: execution_id.clone(),
            channel: crate::orchestrator::delivery::CHANNEL_EMAIL,
            destination_ref: recipient.clone(),
            delivery_version: 1,
        },
    )
    .await?;

    Ok(Json(serde_json::json!({
        "status": match outcome {
            crate::orchestrator::delivery::DeliveryOutcome::Sent => "sent",
            crate::orchestrator::delivery::DeliveryOutcome::AlreadySent => "already_sent",
        },
        "execution_id": execution_id,
        "delivery_status": status,
        // The address is the caller's own; no audit content is echoed back.
        "recipient": recipient,
    })))
}
/// Deliver one execution's report to the configured Telegram chat.
///
/// Identical guarantees to the email route, because it is the same delivery core:
/// execution-scoped, no report regeneration, no scanner or model call, no
/// transaction held across the provider, and a provider failure recorded only on
/// the delivery row.
///
/// The chat is read from configuration. There is deliberately no request field for
/// it: a caller-supplied destination would turn this route into an open relay for
/// security reports.
pub async fn telegram_execution_report(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Path((job_id, execution_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    // Ownership first: never spend a provider call, or reveal that an execution
    // exists, on somebody else's job.
    let owns: Option<(String,)> =
        sqlx::query_as("SELECT id FROM audit_jobs WHERE id=$1 AND user_id=$2")
            .bind(&job_id)
            .bind(&user.user_id)
            .fetch_optional(state.pool())
            .await
            .map_err(AppError::Database)?;
    if owns.is_none() {
        return Err(AppError::NotFound("Job not found".into()));
    }

    let settings = state.settings();

    // Resolve the execution and its finalized content *before* consulting the
    // Telegram configuration, so a running execution is still a 409 about the
    // audit rather than an unrelated 501 about the bot token.
    let content =
        crate::orchestrator::delivery::load_delivery_content(state.pool(), &job_id, &execution_id)
            .await?;

    let chat_id = settings.telegram_chat_id.trim();
    if settings.telegram_bot_token.trim().is_empty() || chat_id.is_empty() {
        return Err(AppError::Delivery(
            crate::error::DeliveryError::NotConfigured,
        ));
    }

    let transport = crate::services::telegram::TelegramTransport::new(
        crate::services::telegram::DEFAULT_BASE_URL,
        &settings.telegram_bot_token,
        settings.telegram_max_response_bytes,
        settings.telegram_max_attempts.max(1) as u32,
        std::time::Duration::from_secs(settings.telegram_timeout_seconds.max(1) as u64),
    )
    .map_err(AppError::Delivery)?;

    // The size policy (17.4) is applied here, to already-finalized content: a full
    // report when it fits, an explicitly labelled summary when it does not. Never a
    // truncation.
    // The configured limit may lower the provider ceiling but never raise it: a
    // setting above 4096 would otherwise turn every delivery into a rejection
    // for a reason that has nothing to do with the audit.
    let limit = settings
        .telegram_message_limit_chars
        .min(crate::services::telegram_artifact::TELEGRAM_MAX_MESSAGE_CHARS);
    let message = crate::services::telegram_artifact::render_message(
        &content.report,
        content.narrative.as_ref(),
        limit,
    );

    let key = crate::orchestrator::delivery::DeliveryKey {
        execution_id: execution_id.clone(),
        channel: crate::orchestrator::delivery::CHANNEL_TELEGRAM,
        destination_ref: chat_id.to_string(),
        delivery_version: 1,
    };

    let outcome = crate::orchestrator::delivery::deliver(state.pool(), &key, || async {
        // Telegram names the message it accepted; the delivery row records it so a
        // duplicate-suppression claim can be reconciled against the provider.
        transport
            .send_message(chat_id, &message.text)
            .await
            .map(Some)
    })
    .await?;

    let status = crate::orchestrator::delivery::delivery_state(state.pool(), &key).await?;

    Ok(Json(serde_json::json!({
        "status": match outcome {
            crate::orchestrator::delivery::DeliveryOutcome::Sent => "sent",
            crate::orchestrator::delivery::DeliveryOutcome::AlreadySent => "already_sent",
        },
        "execution_id": execution_id,
        "delivery_status": status,
        // Whether the full report fit. A summary is a legitimate delivery; saying
        // so is not optional.
        "message_is_summary": message.is_summary,
        "omitted_findings": message.omitted_findings,
    })))
}

/// Accept only `https://github.com/{owner}/{repo}`.
///
/// Owner and repository segments may contain `[A-Za-z0-9._-]`; a single optional
/// trailing `.git` and trailing `/` are tolerated. Anything else — other
/// schemes (`file://`, `ssh://`), the `git@host:` SCP form, other hosts, extra
/// path segments, or `.`/`..` segments — is a 400.
///
/// Delegates to the scan contract's `normalize_repository_url`, the single
/// authority on acceptable URLs, so intake validation can never disagree with
/// the fetch phase about what counts as a repository.
pub fn validate_github_repo_url(url: &str) -> Result<String> {
    crate::schemas::scan_contract::normalize_repository_url(url).map_err(|_| {
        AppError::BadRequest("repo_url must be an https://github.com/{owner}/{repo} URL".into())
    })
}
pub async fn get_job_insight(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let _job: crate::models::AuditJob = sqlx::query_as::<_, crate::models::AuditJob>(
        "SELECT * FROM audit_jobs WHERE id=$1 AND user_id=$2",
    )
    .bind(&job_id)
    .bind(&user.user_id)
    .fetch_optional(state.pool())
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound("Job not found".into()))?;
    Ok(Json(serde_json::json!({"insights": []})))
}
pub async fn get_attack_graph(
    State(state): State<Arc<crate::AppState>>,
    Path(job_id): Path<String>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let _job: crate::models::AuditJob = sqlx::query_as::<_, crate::models::AuditJob>(
        "SELECT * FROM audit_jobs WHERE id=$1 AND user_id=$2",
    )
    .bind(&job_id)
    .bind(&user.user_id)
    .fetch_optional(state.pool())
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound("Job not found".into()))?;

    let findings: Vec<crate::models::FindingModel> =
        sqlx::query_as::<_, crate::models::FindingModel>(
            "SELECT f.* FROM findings f
              WHERE f.job_id=$1
                AND (f.execution_id = (SELECT id FROM audit_executions
                                       WHERE job_id=$1 ORDER BY attempt_number DESC LIMIT 1)
                     OR (f.execution_id IS NULL
                         AND NOT EXISTS (SELECT 1 FROM audit_executions WHERE job_id=$1)))",
        )
        .bind(&job_id)
        .fetch_all(state.pool())
        .await
        .map_err(AppError::Database)?;
    let model_findings: Vec<crate::schemas::audit_state::Finding> = findings
        .into_iter()
        .map(|f| crate::schemas::audit_state::Finding {
            id: f.id,
            agent_source: f.agent_source,
            title: f.title,
            description: f.description,
            severity: f.severity,
            cvss_vector: f.cvss_vector,
            cvss_score: f.cvss_score,
            evidence: f.evidence,
            remediation: f.remediation,
            cwe_id: f.cwe_id,
            owasp_category: f.owasp_category,
            confidence: f.confidence,
            scanner_name: f.scanner_name,
            scanner_mode: f.scanner_mode,
            file_path: f.file_path,
            line_number: f.line_number,
            route: f.route,
            metadata_json: f.metadata_json.map(|v| v.to_string()),
        })
        .collect();
    Ok(Json(crate::services::attack_graph::attack_graph_body(
        &model_findings,
    )))
}

pub async fn list_privacy_logs(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<crate::models::PrivacyAuditLog>>> {
    let logs = crate::services::privacy_audit_service::PrivacyAuditService::list_user_logs(
        state.pool(),
        &user.user_id,
    )
    .await?;
    Ok(Json(logs))
}

pub async fn get_job_phases(
    State(state): State<Arc<crate::AppState>>,
    Path(job_id): Path<String>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<crate::models::PhaseLedgerModel>>> {
    let _job: crate::models::AuditJob = sqlx::query_as::<_, crate::models::AuditJob>(
        "SELECT * FROM audit_jobs WHERE id=$1 AND user_id=$2",
    )
    .bind(&job_id)
    .bind(&user.user_id)
    .fetch_optional(state.pool())
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound("Job not found".into()))?;

    let phases = sqlx::query_as::<_, crate::models::PhaseLedgerModel>(
        "SELECT * FROM phase_ledger WHERE job_id = $1 ORDER BY started_at ASC",
    )
    .bind(&job_id)
    .fetch_all(state.pool())
    .await
    .map_err(AppError::Database)?;

    Ok(Json(phases))
}

/// One attempt in a job's history, for the user-facing audit timeline.
///
/// Read-only and assembled from persisted rows only: execution state, finding
/// count, stored report/narrative presence, and delivery outcomes. Nothing is
/// recomputed, re-resolved, or re-fetched — history is what was recorded.
pub async fn list_job_executions(
    State(state): State<Arc<crate::AppState>>,
    Path(job_id): Path<String>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<Vec<serde_json::Value>>> {
    let owns: Option<(String,)> =
        sqlx::query_as("SELECT id FROM audit_jobs WHERE id=$1 AND user_id=$2")
            .bind(&job_id)
            .bind(&user.user_id)
            .fetch_optional(state.pool())
            .await
            .map_err(AppError::Database)?;
    if owns.is_none() {
        return Err(AppError::NotFound("Job not found".into()));
    }

    let executions: Vec<crate::orchestrator::execution::AuditExecution> =
        sqlx::query_as::<_, crate::orchestrator::execution::AuditExecution>(
            "SELECT * FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number ASC",
        )
        .bind(&job_id)
        .fetch_all(state.pool())
        .await
        .map_err(AppError::Database)?;

    let mut out = Vec::with_capacity(executions.len());
    for exec in executions {
        let finding_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM findings WHERE job_id=$1 AND execution_id=$2")
                .bind(&job_id)
                .bind(&exec.id)
                .fetch_one(state.pool())
                .await
                .map_err(AppError::Database)?;
        let report: Option<(String,)> =
            sqlx::query_as("SELECT id FROM audit_reports WHERE job_id=$1 AND execution_id=$2")
                .bind(&job_id)
                .bind(&exec.id)
                .fetch_optional(state.pool())
                .await
                .map_err(AppError::Database)?;
        let narrative: Option<(String,)> =
            sqlx::query_as("SELECT execution_id FROM ai_narratives WHERE execution_id=$1")
                .bind(&exec.id)
                .fetch_optional(state.pool())
                .await
                .map_err(AppError::Database)?;
        let deliveries: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT channel, status, failure_class FROM audit_deliveries WHERE execution_id=$1",
        )
        .bind(&exec.id)
        .fetch_all(state.pool())
        .await
        .map_err(AppError::Database)?;
        out.push(serde_json::json!({
            "execution_id": exec.id,
            "attempt_number": exec.attempt_number,
            "status": exec.status,
            "commit_sha": exec.commit_sha,
            "started_at": exec.started_at.and_utc(),
            "finished_at": exec.finished_at.map(|t| t.and_utc()),
            "finding_count": finding_count.0,
            "has_report": report.is_some(),
            "has_narrative": narrative.is_some(),
            "deliveries": deliveries.iter().map(|(channel, status, failure_class)| {
                serde_json::json!({
                    "channel": channel,
                    "status": status,
                    "failure_class": failure_class,
                })
            }).collect::<Vec<_>>(),
        }));
    }
    Ok(Json(out))
}
