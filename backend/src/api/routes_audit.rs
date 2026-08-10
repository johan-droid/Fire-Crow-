use axum::{Json, Router, extract::{Path, State}, routing::{get, post}};
use std::sync::Arc;
use crate::error::{AppError, Result};
use crate::schemas::audit_api::*;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/submit", post(submit_audit))
        .route("/jobs", get(list_jobs))
        .route("/job/{job_id}", get(get_job_detail).delete(cancel_job))
        .route("/job/{job_id}/report", get(download_report))
        .route("/job/{job_id}/email", post(email_report))
        .route("/job/{job_id}/insight", get(get_job_insight))
        .route("/job/{job_id}/graph", get(get_attack_graph))
}

pub async fn submit_audit(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(req): Json<SubmitJobRequest>,
) -> Result<Json<JobResponse>> {
    let job_id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO audit_jobs (id, user_id, repo_url, repo_branch, status, created_at) VALUES ($1,$2,$3,$4,'queued',$5)")
        .bind(&job_id).bind(&user.user_id).bind(&req.repo_url).bind(req.repo_branch.as_deref().unwrap_or("main")).bind(chrono::Utc::now().naive_utc())
        .execute(state.pool()).await.map_err(AppError::Database)?;
    let pool = state.pool().clone();
    let repo_url = req.repo_url.clone();
    let repo_branch = req.repo_branch.clone().unwrap_or_else(|| "main".into());
    let custom_email = req.custom_email.clone();
    let j_id = job_id.clone();
    let uid = user.user_id.clone();
    tokio::spawn(async move {
        let _ = crate::orchestrator::execute_audit_job(&pool, &j_id, &uid, &repo_url, &repo_branch, custom_email.as_deref(), None).await;
    });
    let job: crate::models::AuditJob = sqlx::query_as::<_, crate::models::AuditJob>("SELECT * FROM audit_jobs WHERE id=$1")
        .bind(&job_id).fetch_one(state.pool()).await.map_err(AppError::Database)?;
    Ok(Json(JobResponse::from(job)))
}

pub async fn list_jobs(State(state): State<Arc<crate::AppState>>) -> Result<Json<Vec<JobResponse>>> {
    let jobs: Vec<crate::models::AuditJob> = sqlx::query_as::<_, crate::models::AuditJob>("SELECT * FROM audit_jobs ORDER BY created_at DESC").fetch_all(state.pool()).await.map_err(AppError::Database)?;
    Ok(Json(jobs.into_iter().map(JobResponse::from).collect()))
}

pub async fn get_job_detail(State(state): State<Arc<crate::AppState>>, Path(job_id): Path<String>) -> Result<Json<JobDetailResponse>> {
    let job: crate::models::AuditJob = sqlx::query_as::<_, crate::models::AuditJob>("SELECT * FROM audit_jobs WHERE id=$1").bind(&job_id).fetch_optional(state.pool()).await.map_err(AppError::Database)?.ok_or_else(|| AppError::NotFound("Job not found".into()))?;
    let findings: Vec<crate::models::FindingModel> = sqlx::query_as::<_, crate::models::FindingModel>("SELECT * FROM findings WHERE job_id=$1").bind(&job_id).fetch_all(state.pool()).await.map_err(AppError::Database)?;
    Ok(Json(JobDetailResponse { job: JobResponse::from(job), findings: findings.into_iter().map(FindingResponse::from).collect() }))
}

pub async fn cancel_job(State(state): State<Arc<crate::AppState>>, Path(job_id): Path<String>) -> Result<Json<serde_json::Value>> {
    sqlx::query("UPDATE audit_jobs SET cancel_requested=true, cancel_requested_at=$1, status='cancelled' WHERE id=$2").bind(chrono::Utc::now().naive_utc()).bind(job_id).execute(state.pool()).await.map_err(AppError::Database)?;
    Ok(Json(serde_json::json!({"status": "cancellation_requested"})))
}

pub async fn download_report(State(state): State<Arc<crate::AppState>>, Path(job_id): Path<String>) -> Result<axum::response::Response> {
    let report: Option<crate::models::AuditReport> = sqlx::query_as::<_, crate::models::AuditReport>("SELECT * FROM audit_reports WHERE job_id=$1").bind(job_id).fetch_optional(state.pool()).await.map_err(AppError::Database)?;
    let report = report.ok_or_else(|| AppError::NotFound("Report not found".into()))?;
    let markdown = report.markdown_content.unwrap_or_default();
    Ok(axum::response::Response::builder().status(200).header("Content-Type", "text/markdown").body(axum::body::Body::from(markdown)).unwrap())
}

pub async fn email_report(_state: State<Arc<crate::AppState>>, _job_id: Path<String>) -> Result<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({"status": "email_queued"})))
}
pub async fn get_job_insight(_state: State<Arc<crate::AppState>>, _job_id: Path<String>) -> Result<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({"insights": []})))
}
pub async fn get_attack_graph(State(state): State<Arc<crate::AppState>>, Path(job_id): Path<String>) -> Result<Json<serde_json::Value>> {
    if let Ok(graph) = crate::graph::GraphStore::fetch_attack_graph(state.pool(), &job_id).await {
        if let Some(nodes) = graph.get("nodes").and_then(|v| v.as_array()) {
            if !nodes.is_empty() {
                return Ok(Json(graph));
            }
        }
    }
    let findings: Vec<crate::models::FindingModel> = sqlx::query_as::<_, crate::models::FindingModel>("SELECT * FROM findings WHERE job_id=$1").bind(&job_id).fetch_all(state.pool()).await.map_err(AppError::Database)?;
    let model_findings: Vec<crate::schemas::audit_state::Finding> = findings.into_iter().map(|f| crate::schemas::audit_state::Finding {
        id: f.id, agent_source: f.agent_source, title: f.title, description: f.description, severity: f.severity,
        cvss_vector: f.cvss_vector, cvss_score: f.cvss_score, evidence: f.evidence, remediation: f.remediation,
        cwe_id: f.cwe_id, owasp_category: f.owasp_category, confidence: f.confidence, scanner_name: f.scanner_name,
        scanner_mode: f.scanner_mode, file_path: f.file_path, line_number: f.line_number, route: f.route, metadata_json: f.metadata_json,
    }).collect();
    Ok(Json(crate::services::attack_graph::attack_graph_body(&model_findings)))
}
