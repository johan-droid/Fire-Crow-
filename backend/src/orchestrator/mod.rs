//! Audit job orchestrator — replaces LangGraph + Celery.

use crate::agents::*;
use crate::error::{AppError, Result};
use crate::models::AuditJob;
use crate::schemas::audit_state::AuditState;
use crate::services::reporter::ReportGenerator;
use crate::utils::generate_uuid;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub mod runtime;
pub mod scan_plan;
pub use runtime::*;
pub use scan_plan::*;

pub async fn execute_audit_job(
    pool: &PgPool, job_id: &str, user_id: &str, repo_url: &str, repo_branch: &str,
    custom_email: Option<&str>, _unused_graph: Option<()>,
) -> Result<AuditState> {
    let mut state = AuditState {
        job_id: job_id.into(), user_id: user_id.into(), repo_url: repo_url.into(), repo_branch: repo_branch.into(),
        custom_email: custom_email.unwrap_or("").into(), created_at: Utc::now(),
        status: crate::models::JobStatus::Running, current_phase: "intake".into(), ..Default::default()
    };

    tracing::info!("[orchestrator] Starting job {} for repo {}", job_id, repo_url);

    // Phase 1: Intake
    let started = Utc::now();
    log_phase_started(pool, job_id, "intake").await?;
    state.repo_owner = extract_repo_owner(repo_url);
    state.repo_name = extract_repo_name(repo_url);
    log_phase_completed(pool, job_id, "intake", "completed", started, None).await?;

    // Phase 2: Recon
    let started = Utc::now();
    log_phase_started(pool, job_id, "recon").await?;
    state.current_phase = "recon".into();
    if let Err(e) = run_recon(&mut state).await { log_phase_completed(pool, job_id, "recon", "failed", started, Some(e.to_string())).await?; record_error(&mut state, "recon", &e.to_string()); }
    else { log_phase_completed(pool, job_id, "recon", "completed", started, None).await?; }

    // Phase 3: SBOM
    let started = Utc::now();
    log_phase_started(pool, job_id, "sbom").await?;
    let _ = run_dependency_scan(&mut state).await;
    log_phase_completed(pool, job_id, "sbom", "completed", started, None).await?;

    // Phase 4: API Surface
    let started = Utc::now();
    log_phase_started(pool, job_id, "api_surface").await?;
    let _ = api_surface_body(&mut state).await;
    log_phase_completed(pool, job_id, "api_surface", "completed", started, None).await?;

    // Phase 5: Scanning
    let started = Utc::now();
    log_phase_started(pool, job_id, "scanning").await?;
    let _ = run_sast(&mut state).await;
    let _ = run_semgrep_scan(&mut state).await;
    let _ = run_secret_history(&mut state).await;
    let _ = run_iac_scan(&mut state).await;
    let _ = run_container_scan(&mut state).await;
    let _ = run_cicd_scan(&mut state).await;
    let _ = run_config_scan(&mut state).await;
    let _ = run_network_scan(&mut state).await;
    let _ = run_authz_idor_scan(&mut state).await;
    let _ = run_exploit_validation(&mut state).await;
    let _ = generate_threat_model(&mut state).await;
    log_phase_completed(pool, job_id, "scanning", "completed", started, None).await?;

    // Phase 6: AI Analysis
    let started = Utc::now();
    log_phase_started(pool, job_id, "ai_analysis").await?;
    state.scored_findings = state.dynamic_findings.clone();
    let _ = run_ai_analyzer(&mut state).await;
    let _ = cross_validate_findings(&mut state).await;
    log_phase_completed(pool, job_id, "ai_analysis", "completed", started, None).await?;

    // Phase 7: Remediation
    let started = Utc::now();
    log_phase_started(pool, job_id, "remediation").await?;
    state.remediation_tasks = crate::services::remediation_planner::remediation_planner_body(&state.validated_findings);
    log_phase_completed(pool, job_id, "remediation", "completed", started, None).await?;

    // Phase 8: Attack Graph
    let started = Utc::now();
    log_phase_started(pool, job_id, "attack_graph").await?;
    let attack_graph_val = crate::services::attack_graph::attack_graph_body(&state.validated_findings);
    if let (Some(nodes), Some(edges)) = (attack_graph_val.get("nodes").and_then(|v| v.as_array()), attack_graph_val.get("edges").and_then(|v| v.as_array())) {
        let _ = crate::graph::GraphStore::store_attack_graph(pool, job_id, nodes, edges).await;
    }
    state.attack_graph = attack_graph_val;
    log_phase_completed(pool, job_id, "attack_graph", "completed", started, None).await?;

    // Phase 9: Scoring
    let started = Utc::now();
    log_phase_started(pool, job_id, "scoring").await?;
    compute_security_score(&mut state);
    log_phase_completed(pool, job_id, "scoring", "completed", started, None).await?;

    // Phase 10: Reporting
    let started = Utc::now();
    log_phase_started(pool, job_id, "reporting").await?;
    state.current_phase = "reporting".into();
    let markdown = ReportGenerator::generate_markdown(&get_job(pool, job_id).await?, &state.validated_findings, &state)?;
    let report_id = generate_uuid();
    sqlx::query("INSERT INTO audit_reports (id, job_id, markdown_content, created_at) VALUES ($1,$2,$3,$4)")
        .bind(&report_id).bind(job_id).bind(&markdown).bind(Utc::now().naive_utc()).execute(pool).await.map_err(AppError::Database)?;
    sqlx::query("UPDATE audit_jobs SET report_id=$1 WHERE id=$2").bind(&report_id).bind(job_id).execute(pool).await.map_err(AppError::Database)?;
    log_phase_completed(pool, job_id, "reporting", "completed", started, None).await?;

    // Phase 11: Integrations
    let _ = run_github_mcp(&mut state).await;
    let _ = run_google_agent(&mut state).await;

    // Finalize
    state.status = crate::models::JobStatus::Completed;
    state.report_delivered = true;
    state.current_phase = "complete".into();
    sqlx::query("UPDATE audit_jobs SET status=$1, finished_at=$2, security_score=$3 WHERE id=$4")
        .bind(crate::models::JobStatus::Completed)
        .bind(Utc::now().naive_utc())
        .bind(state.security_score.unwrap_or(0.0))
        .bind(job_id)
        .execute(pool)
        .await
        .map_err(AppError::Database)?;

    tracing::info!("[orchestrator] Job {} completed with score {:?}", job_id, state.security_score);
    Ok(state)
}

fn compute_security_score(state: &mut AuditState) {
    let all = &state.validated_findings;
    if all.is_empty() { state.security_score = Some(10.0); state.risk_summary = serde_json::json!({"score": 10.0, "risk_level": "low"}); return; }
    let mut score: f64 = 10.0;
    for f in all {
        score -= match f.severity {
            crate::models::Severity::Critical => 3.0,
            crate::models::Severity::High => 2.0,
            crate::models::Severity::Medium => 1.0,
            crate::models::Severity::Low => 0.3,
            crate::models::Severity::Info => 0.1,
        };
    }
    score = score.max(0.0).min(10.0);
    state.security_score = Some((score * 10.0).round() / 10.0);
    let risk_level = if score >= 8.0 { "low" } else if score >= 5.0 { "medium" } else if score >= 3.0 { "high" } else { "critical" };
    state.risk_summary = serde_json::json!({"score": state.security_score, "risk_level": risk_level, "total_findings": all.len()});
}

fn extract_repo_owner(url: &str) -> String { url.trim_end_matches('/').split('/').nth_back(2).unwrap_or("").into() }
fn extract_repo_name(url: &str) -> String { url.trim_end_matches('/').split('/').next_back().unwrap_or("repo").trim_end_matches(".git").into() }
fn record_error(state: &mut AuditState, phase: &str, error: &str) {
    state.errors.push(serde_json::json!({"phase": phase, "error": error, "timestamp": Utc::now().to_rfc3339()}));
}
async fn get_job(pool: &PgPool, job_id: &str) -> Result<AuditJob> {
    sqlx::query_as::<_, AuditJob>("SELECT * FROM audit_jobs WHERE id=$1").bind(job_id).fetch_optional(pool).await.map_err(AppError::Database)?.ok_or_else(|| AppError::NotFound("Job not found".into()))
}
async fn log_phase_started(pool: &PgPool, job_id: &str, phase: &str) -> Result<()> {
    let id = generate_uuid();
    let _ = sqlx::query("INSERT INTO phase_ledger (id, job_id, phase_name, status, mode, started_at) VALUES ($1,$2,$3,'started','real',$4)")
        .bind(id).bind(job_id).bind(phase).bind(Utc::now().naive_utc()).execute(pool).await;
    Ok(())
}
async fn log_phase_completed(pool: &PgPool, job_id: &str, phase: &str, status: &str, started_at: DateTime<Utc>, error_message: Option<String>) -> Result<()> {
    let ended_at = Utc::now();
    let duration = (ended_at - started_at).num_milliseconds() as f64 / 1000.0;
    let _ = sqlx::query("UPDATE phase_ledger SET status=$1, ended_at=$2, duration_sec=$3, error_message=$4 WHERE id IN (SELECT id FROM phase_ledger WHERE job_id=$5 AND phase_name=$6 AND status='started' ORDER BY started_at DESC LIMIT 1)")
        .bind(status).bind(ended_at.naive_utc()).bind(duration).bind(error_message).bind(job_id).bind(phase).execute(pool).await;
    Ok(())
}
