use crate::error::{AppError, Result};
use crate::schemas::audit_api::*;
use axum::{
    extract::{Path, State},
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
        .route("/job/:job_id/phases", get(get_job_phases))
        .route("/job/:job_id/report", get(download_report))
        .route("/job/:job_id/email", post(email_report))
        .route("/job/:job_id/insight", get(get_job_insight))
        .route("/job/:job_id/graph", get(get_attack_graph))
}

pub async fn submit_audit(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(req): Json<SubmitJobRequest>,
) -> Result<Json<JobResponse>> {
    // Only real GitHub HTTPS repository URLs are accepted. This is the single
    // acquisition surface for the scan pipeline, so `file://`, `ssh://`,
    // `git@…`, any non-github.com host, and `..` path segments are rejected here
    // rather than being handed to the fetch phase.
    validate_github_repo_url(&req.repo_url)?;

    let job_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO audit_jobs (id, user_id, tenant_id, repo_url, repo_branch, status, cancel_requested, legal_hold, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(&job_id)
        .bind(&user.user_id)
        .bind(&user.tenant_id)
        .bind(&req.repo_url)
        .bind(req.repo_branch.as_deref().unwrap_or("main"))
        .bind(crate::models::JobStatus::Queued)
        .bind(false)
        .bind(false)
        .bind(chrono::Utc::now().naive_utc())
        .execute(state.pool()).await.map_err(AppError::Database)?;
    let job: crate::models::AuditJob =
        sqlx::query_as::<_, crate::models::AuditJob>("SELECT * FROM audit_jobs WHERE id=$1")
            .bind(&job_id)
            .fetch_one(state.pool())
            .await
            .map_err(AppError::Database)?;
    Ok(Json(JobResponse::from(job)))
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
    let findings: Vec<crate::models::FindingModel> =
        sqlx::query_as::<_, crate::models::FindingModel>("SELECT * FROM findings WHERE job_id=$1")
            .bind(&job_id)
            .fetch_all(state.pool())
            .await
            .map_err(AppError::Database)?;
    Ok(Json(JobDetailResponse {
        job: JobResponse::from(job),
        findings: findings.into_iter().map(FindingResponse::from).collect(),
    }))
}

pub async fn cancel_job(
    State(state): State<Arc<crate::AppState>>,
    Path(job_id): Path<String>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    // Only queued/running jobs can be cancelled — finished jobs are immutable.
    let result = sqlx::query("UPDATE audit_jobs SET cancel_requested=true, cancel_requested_at=$1, status=$2 WHERE id=$3 AND user_id=$4 AND status IN ('queued','running')")
        .bind(chrono::Utc::now().naive_utc())
        .bind(crate::models::JobStatus::Cancelled)
        .bind(&job_id)
        .bind(&user.user_id)
        .execute(state.pool()).await.map_err(AppError::Database)?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "Job not found, already finished, or access denied".into(),
        ));
    }
    Ok(Json(
        serde_json::json!({"status": "cancellation_requested"}),
    ))
}

pub async fn download_report(
    State(state): State<Arc<crate::AppState>>,
    Path(job_id): Path<String>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<axum::response::Response> {
    let report: Option<crate::models::AuditReport> = sqlx::query_as::<_, crate::models::AuditReport>("SELECT r.* FROM audit_reports r JOIN audit_jobs j ON r.job_id = j.id WHERE r.job_id=$1 AND j.user_id=$2")
        .bind(&job_id)
        .bind(&user.user_id)
        .fetch_optional(state.pool()).await.map_err(AppError::Database)?;
    let report = report.ok_or_else(|| AppError::NotFound("Report not found".into()))?;
    let markdown = report.markdown_content.unwrap_or_default();
    Ok(axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "text/markdown")
        .body(axum::body::Body::from(markdown))
        .unwrap())
}

pub async fn email_report(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    use crate::services::email::EmailService;

    let job: crate::models::AuditJob = sqlx::query_as::<_, crate::models::AuditJob>(
        "SELECT * FROM audit_jobs WHERE id=$1 AND user_id=$2",
    )
    .bind(&job_id)
    .bind(&user.user_id)
    .fetch_optional(state.pool())
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| AppError::NotFound("Job not found".into()))?;

    // No SMTP transport means the report cannot be delivered. Returning
    // `email_queued` in that case was a lie: nothing was queued and nothing
    // would ever be sent. Answer 501 instead.
    let Some(mailer) = EmailService::from_settings(state.settings()) else {
        return Err(AppError::NotImplemented(
            "Email delivery is not configured on this server (SMTP_HOST is unset).".into(),
        ));
    };

    // The recipient is the report owner; there is no per-request override here.
    let recipient: String =
        sqlx::query_as::<_, (Option<String>,)>("SELECT email FROM users WHERE id=$1")
            .bind(&user.user_id)
            .fetch_optional(state.pool())
            .await
            .map_err(AppError::Database)?
            .and_then(|(e,)| e)
            .filter(|e| !e.trim().is_empty())
            .ok_or_else(|| {
                AppError::BadRequest("No email address on file for this account".into())
            })?;

    let report: Option<crate::models::AuditReport> =
        sqlx::query_as::<_, crate::models::AuditReport>(
            "SELECT * FROM audit_reports WHERE job_id=$1",
        )
        .bind(&job_id)
        .fetch_optional(state.pool())
        .await
        .map_err(AppError::Database)?;
    let markdown = report
        .and_then(|r| r.markdown_content)
        .ok_or_else(|| AppError::NotFound("Report not found".into()))?;

    let subject = format!("FireCrow security report for {}", job.repo_url);
    let body = "Your requested FireCrow security report is attached as Markdown.\n";

    // Delivery outcome is recorded on its own column and never rewrites the
    // job's terminal status. A `completed` job stays `completed` even when the
    // mail server rejects the message.
    match mailer
        .send_report_email(&recipient, &subject, body, &markdown)
        .await
    {
        Ok(()) => {
            let _ = sqlx::query(
                "UPDATE audit_jobs SET email_delivery_status='sent' WHERE id=$1 AND status IN ('queued','running','completed','engine_unavailable','failed','cancelled')",
            )
            .bind(&job_id)
            .execute(state.pool())
            .await;
            Ok(Json(serde_json::json!({
                "status": "sent",
                "recipient": recipient,
            })))
        }
        Err(e) => {
            tracing::warn!("Report email delivery failed for job {}: {}", job_id, e);
            let _ = sqlx::query(
                "UPDATE audit_jobs SET email_delivery_status='failed' WHERE id=$1 AND status IN ('queued','running','completed','engine_unavailable','failed','cancelled')",
            )
            .bind(&job_id)
            .execute(state.pool())
            .await;
            Ok(Json(serde_json::json!({
                "status": "delivery_failed",
                "recipient": recipient,
            })))
        }
    }
}

/// Accept only `https://github.com/{owner}/{repo}`.
///
/// Owner and repository segments may contain `[A-Za-z0-9._-]`; a single optional
/// trailing `.git` and trailing `/` are tolerated. Anything else — other
/// schemes (`file://`, `ssh://`), the `git@host:` SCP form, other hosts, extra
/// path segments, or `.`/`..` segments — is a 400.
pub fn validate_github_repo_url(url: &str) -> Result<String> {
    fn valid_segment(seg: &str) -> bool {
        !seg.is_empty()
            && seg != "."
            && seg != ".."
            && seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    }

    let trimmed = url.trim();
    let rest = trimmed
        .strip_prefix("https://github.com/")
        .ok_or_else(|| {
            AppError::BadRequest("repo_url must be an https://github.com/{owner}/{repo} URL".into())
        })?
        .trim_end_matches('/');

    // Tolerate a single trailing `.git`.
    let rest = rest.strip_suffix(".git").unwrap_or(rest);

    let segments: Vec<&str> = rest.split('/').collect();
    if segments.len() != 2 || !valid_segment(segments[0]) || !valid_segment(segments[1]) {
        return Err(AppError::BadRequest(
            "repo_url must be an https://github.com/{owner}/{repo} URL".into(),
        ));
    }

    Ok(format!(
        "https://github.com/{}/{}",
        segments[0], segments[1]
    ))
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
        sqlx::query_as::<_, crate::models::FindingModel>("SELECT * FROM findings WHERE job_id=$1")
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
            metadata_json: f.metadata_json,
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
