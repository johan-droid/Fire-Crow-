//! Audit job orchestrator — replaces LangGraph + Celery.

use crate::agents::*;
use crate::error::{AppError, Result};
use crate::models::AuditJob;
use crate::schemas::audit_state::AuditState;
use crate::services::reporter::ReportGenerator;
use crate::utils::generate_uuid;
use chrono::{DateTime, Utc};
use sqlx::PgPool;


pub async fn execute_audit_job(
    pool: &PgPool, job_id: &str, user_id: &str, repo_url: &str, repo_branch: &str,
    custom_email: Option<&str>, _unused_graph: Option<()>,
) -> Result<AuditState> {
    let mut state = AuditState {
        job_id: job_id.into(), user_id: user_id.into(), repo_url: repo_url.into(), repo_branch: repo_branch.into(),
        custom_email: custom_email.unwrap_or("").into(), created_at: Utc::now(),
        status: crate::models::JobStatus::Running, current_phase: "intake".into(), ..Default::default()
    };

    // Ensure job is marked as running in database (idempotent safety)
    let _ = sqlx::query("UPDATE audit_jobs SET status=$1 WHERE id=$2 AND status != 'completed' AND status != 'failed'")
        .bind(crate::models::JobStatus::Running)
        .bind(job_id)
        .execute(pool)
        .await;

    tracing::info!("[orchestrator] Starting job {} for repo {} at {}", job_id, repo_url, Utc::now().to_rfc3339());

    let mut job_cancelled = false;

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
    if is_cancelled(pool, job_id).await? { job_cancelled = true; }
    if !job_cancelled {
        if let Err(e) = run_recon(&mut state).await {
            log_phase_completed(pool, job_id, "recon", "failed", started, Some(e.to_string())).await?;
            record_error(&mut state, "recon", &e.to_string());
            job_cancelled = true;
        } else {
            log_phase_completed(pool, job_id, "recon", "completed", started, None).await?;
        }
    }

    if !job_cancelled {
        // Phase 2b: Static Analysis
        let started = Utc::now();
        log_phase_started(pool, job_id, "scanning").await?;
        if is_cancelled(pool, job_id).await? { job_cancelled = true; }
        if !job_cancelled {
            if let Err(e) = run_sast(&mut state).await {
                log_phase_completed(pool, job_id, "scanning", "failed", started, Some(e.to_string())).await?;
                record_error(&mut state, "scanning", &e.to_string());
                job_cancelled = true;
            } else {
                log_phase_completed(pool, job_id, "scanning", "completed", started, None).await?;
            }
        }
    }

    if !job_cancelled {
        // Phase 3: AI Analysis
        let started = Utc::now();
        log_phase_started(pool, job_id, "ai_analysis").await?;
        if is_cancelled(pool, job_id).await? { job_cancelled = true; }
        if !job_cancelled {
            state.scored_findings = [state.static_findings.clone(), state.dynamic_findings.clone()].concat();
            if let Err(e) = run_ai_analyzer(&mut state).await {
                log_phase_completed(pool, job_id, "ai_analysis", "failed", started, Some(e.to_string())).await?;
                record_error(&mut state, "ai_analysis", &e.to_string());
                job_cancelled = true;
            } else if let Err(e) = cross_validate_findings(&mut state).await {
                log_phase_completed(pool, job_id, "ai_analysis", "failed", started, Some(e.to_string())).await?;
                record_error(&mut state, "cross_validation", &e.to_string());
                job_cancelled = true;
            } else {
                for f in &state.validated_findings {
                    let _ = sqlx::query(
                        "INSERT INTO findings (id, job_id, agent_source, title, description, severity, cvss_vector, cvss_score, evidence, remediation, cwe_id, owasp_category, confidence, scanner_name, scanner_mode, file_path, line_number, route, metadata_json, created_at)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)"
                    )
                    .bind(&f.id)
                    .bind(job_id)
                    .bind(&f.agent_source)
                    .bind(&f.title)
                    .bind(&f.description)
                    .bind(f.severity)
                    .bind(&f.cvss_vector)
                    .bind(f.cvss_score)
                    .bind(&f.evidence)
                    .bind(&f.remediation)
                    .bind(&f.cwe_id)
                    .bind(&f.owasp_category)
                    .bind(&f.confidence)
                    .bind(&f.scanner_name)
                    .bind(&f.scanner_mode)
                    .bind(&f.file_path)
                    .bind(f.line_number)
                    .bind(&f.route)
                    .bind(&f.metadata_json)
                    .bind(Utc::now().naive_utc())
                    .execute(pool)
                    .await;
                }
                log_phase_completed(pool, job_id, "ai_analysis", "completed", started, None).await?;
            }
        }
    }

    if !job_cancelled {
        // Phase 4: Remediation
        let started = Utc::now();
        log_phase_started(pool, job_id, "remediation").await?;
        if is_cancelled(pool, job_id).await? { job_cancelled = true; }
        if !job_cancelled {
            state.remediation_tasks = crate::services::remediation_planner::remediation_planner_body(&state.validated_findings);
            log_phase_completed(pool, job_id, "remediation", "completed", started, None).await?;
        }
    }

    if !job_cancelled {
        // Phase 5: Attack Graph
        let started = Utc::now();
        log_phase_started(pool, job_id, "attack_graph").await?;
        if is_cancelled(pool, job_id).await? { job_cancelled = true; }
        if !job_cancelled {
            let attack_graph_val = crate::services::attack_graph::attack_graph_body(&state.validated_findings);
            if let (Some(nodes), Some(edges)) = (attack_graph_val.get("nodes").and_then(|v| v.as_array()), attack_graph_val.get("edges").and_then(|v| v.as_array())) {
                if let Err(e) = crate::graph::GraphStore::store_attack_graph(pool, job_id, nodes, edges).await {
                    log_phase_completed(pool, job_id, "attack_graph", "failed", started, Some(e.to_string())).await?;
                    record_error(&mut state, "attack_graph", &e.to_string());
                    job_cancelled = true;
                }
            }
            if !job_cancelled {
                state.attack_graph = attack_graph_val;
                log_phase_completed(pool, job_id, "attack_graph", "completed", started, None).await?;
            }
        }
    }

    if !job_cancelled {
        // Phase 6: Scoring
        let started = Utc::now();
        log_phase_started(pool, job_id, "scoring").await?;
        if is_cancelled(pool, job_id).await? { job_cancelled = true; }
        if !job_cancelled {
            compute_security_score(&mut state);
            log_phase_completed(pool, job_id, "scoring", "completed", started, None).await?;
        }
    }

    if !job_cancelled {
        // Phase 7: Reporting
        let started = Utc::now();
        log_phase_started(pool, job_id, "reporting").await?;
        state.current_phase = "reporting".into();
        if is_cancelled(pool, job_id).await? { job_cancelled = true; }
        if !job_cancelled {
            match ReportGenerator::generate_markdown(&get_job(pool, job_id).await?, &state.validated_findings, &state) {
                Ok(markdown) => {
                    let report_id = generate_uuid();
                    if let Err(e) = sqlx::query("INSERT INTO audit_reports (id, job_id, markdown_content, created_at) VALUES ($1,$2,$3,$4)")
                        .bind(&report_id).bind(job_id).bind(&markdown).bind(Utc::now().naive_utc()).execute(pool).await
                    {
                        log_phase_completed(pool, job_id, "reporting", "failed", started, Some(e.to_string())).await?;
                        record_error(&mut state, "reporting", &e.to_string());
                        job_cancelled = true;
                    } else if let Err(e) = sqlx::query("UPDATE audit_jobs SET report_id=$1 WHERE id=$2").bind(&report_id).bind(job_id).execute(pool).await {
                        log_phase_completed(pool, job_id, "reporting", "failed", started, Some(e.to_string())).await?;
                        record_error(&mut state, "reporting", &e.to_string());
                        job_cancelled = true;
                    } else {
                        log_phase_completed(pool, job_id, "reporting", "completed", started, None).await?;
                    }
                }
                Err(e) => {
                    log_phase_completed(pool, job_id, "reporting", "failed", started, Some(e.to_string())).await?;
                    record_error(&mut state, "reporting", &e.to_string());
                    job_cancelled = true;
                }
            }
        }
    }

    // Finalize
    if job_cancelled {
        state.status = crate::models::JobStatus::Cancelled;
        state.current_phase = "cancelled".into();
        sqlx::query("UPDATE audit_jobs SET status=$1, finished_at=$2, error_message=$3 WHERE id=$4")
            .bind(crate::models::JobStatus::Cancelled)
            .bind(Utc::now().naive_utc())
            .bind("Job cancelled by user or system")
            .bind(job_id)
            .execute(pool)
            .await
            .map_err(AppError::Database)?;
    } else {
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
    }

    tracing::info!("[orchestrator] Job {} completed with score {:?}", job_id, state.security_score);
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

fn extract_repo_owner(url: &str) -> String {
    let cleaned = url.trim_end_matches('/').trim_end_matches(".git");
    if cleaned.contains("git@") {
        cleaned.split(':').last().unwrap_or("").split('/').next().unwrap_or("").into()
    } else {
        cleaned.split('/').nth_back(1).unwrap_or("").into()
    }
}

fn extract_repo_name(url: &str) -> String {
    let cleaned = url.trim_end_matches('/').trim_end_matches(".git");
    cleaned.split('/').next_back().unwrap_or("repo").into()
}
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
