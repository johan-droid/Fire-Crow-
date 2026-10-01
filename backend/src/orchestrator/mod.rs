//! Audit job orchestrator.
//!
//! Phases run strictly in order — intake, fetch, scan, normalize, score, report,
//! deliver — and each writes a `phase_ledger` row. Cancellation is checked
//! between phases. A failure in any phase records that phase's name and ends the
//! job as `Failed` with a NULL score; a phase that did not run is never reported.
//!
//! Nothing here invents a result. Findings come from the scanner, and the score
//! is derived only from a scan that actually completed.

use crate::error::{AppError, Result};
use crate::models::JobStatus;
use crate::schemas::audit_state::{AuditState, Finding};
use crate::utils::generate_uuid;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashSet;

/// Terminal outcome of the pipeline.
enum Outcome {
    Ok,
    Failed(String, String),
    Cancelled,
}

pub async fn execute_audit_job(
    pool: &PgPool,
    job_id: &str,
    user_id: &str,
    repo_url: &str,
    repo_branch: &str,
    custom_email: Option<&str>,
    _unused_graph: Option<()>,
) -> Result<AuditState> {
    let _ = custom_email;
    let mut state = AuditState {
        job_id: job_id.into(),
        user_id: user_id.into(),
        repo_url: repo_url.into(),
        repo_branch: repo_branch.into(),
        created_at: Utc::now(),
        status: JobStatus::Running,
        current_phase: "intake".into(),
        ..Default::default()
    };

    // Idempotent safety. Never resurrect a job that already reached a terminal
    // state.
    let _ = sqlx::query(
        "UPDATE audit_jobs SET status=$1 WHERE id=$2 AND status IN ('queued', 'running')",
    )
    .bind(JobStatus::Running)
    .bind(job_id)
    .execute(pool)
    .await;

    tracing::info!(
        "[orchestrator] Starting job {} for repo {} at {}",
        job_id,
        repo_url,
        Utc::now().to_rfc3339()
    );

    let engine_available = crate::agents::ENGINE_AVAILABLE;

    // Phase: intake — resolve owner/name from the (already validated) URL.
    let intake = phase(pool, job_id, "intake", async {
        state.repo_owner = extract_repo_owner(repo_url);
        state.repo_name = extract_repo_name(repo_url);
        Ok(())
    })
    .await;

    let outcome = match intake {
        Ok(()) => {
            if engine_available {
                run_pipeline(pool, job_id, &mut state).await
            } else {
                state.current_phase = "engine_unavailable".into();
                state.analysis_performed = false;
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
                Outcome::Ok
            }
        }
        Err(e) => Outcome::Failed("intake".into(), e.to_string()),
    };

    // Failure wins over cancellation; cancellation wins over completion. An
    // unavailable engine must never resolve to `Completed`.
    let final_status = match &outcome {
        Outcome::Failed(..) => JobStatus::Failed,
        Outcome::Cancelled => JobStatus::Cancelled,
        Outcome::Ok => {
            if engine_available {
                JobStatus::Completed
            } else {
                JobStatus::EngineUnavailable
            }
        }
    };

    // Close out any phase rows left `started` (e.g. by a cancellation) so the
    // ledger never shows a phase as perpetually in flight.
    let _ = sqlx::query(
        "UPDATE phase_ledger SET status='skipped', ended_at=$1 WHERE job_id=$2 AND status='started'",
    )
    .bind(Utc::now().naive_utc())
    .bind(job_id)
    .execute(pool)
    .await;

    match final_status {
        JobStatus::Failed => {
            let (phase_name, msg) = match &outcome {
                Outcome::Failed(p, m) => (p.clone(), m.clone()),
                _ => ("unknown".to_string(), "pipeline failed".to_string()),
            };
            state.status = JobStatus::Failed;
            state.current_phase = format!("failed:{}", phase_name);
            state.security_score = None;
            sqlx::query("UPDATE audit_jobs SET status=$1, finished_at=$2, security_score=NULL, error_message=$3 WHERE id=$4 AND status IN ('queued','running')")
                .bind(JobStatus::Failed)
                .bind(Utc::now().naive_utc())
                .bind(format!("{} phase failed: {}", phase_name, msg))
                .bind(job_id)
                .execute(pool)
                .await
                .map_err(AppError::Database)?;
        }
        JobStatus::Cancelled => {
            state.status = JobStatus::Cancelled;
            state.current_phase = "cancelled".into();
            sqlx::query("UPDATE audit_jobs SET status=$1, finished_at=$2, error_message=$3 WHERE id=$4 AND status IN ('queued','running')")
                .bind(JobStatus::Cancelled)
                .bind(Utc::now().naive_utc())
                .bind("Job cancelled by user")
                .bind(job_id)
                .execute(pool)
                .await
                .map_err(AppError::Database)?;
        }
        JobStatus::EngineUnavailable => {
            state.status = JobStatus::EngineUnavailable;
            state.current_phase = "engine_unavailable".into();
            state.security_score = None;
            sqlx::query("UPDATE audit_jobs SET status=$1, finished_at=$2, security_score=NULL, error_message=$3 WHERE id=$4 AND status IN ('queued','running')")
                .bind(JobStatus::EngineUnavailable)
                .bind(Utc::now().naive_utc())
                .bind(crate::agents::ENGINE_UNAVAILABLE_REASON)
                .bind(job_id)
                .execute(pool)
                .await
                .map_err(AppError::Database)?;
        }
        _ => {
            state.status = JobStatus::Completed;
            state.current_phase = "complete".into();
            sqlx::query("UPDATE audit_jobs SET status=$1, finished_at=$2, security_score=$3, error_message=NULL WHERE id=$4 AND status IN ('queued','running')")
                .bind(JobStatus::Completed)
                .bind(Utc::now().naive_utc())
                .bind(state.security_score)
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

/// Run every analysis phase in order, short-circuiting on cancellation or error.
///
/// Each phase goes through [`phase`], which brackets it with a `phase_ledger`
/// start/completion row. Cancellation is re-checked immediately before each
/// phase.
async fn run_pipeline(pool: &PgPool, job_id: &str, state: &mut AuditState) -> Outcome {
    macro_rules! step {
        ($name:literal, $expr:expr) => {{
            if is_cancelled(pool, job_id).await.unwrap_or(false) {
                return Outcome::Cancelled;
            }
            match phase(pool, job_id, $name, $expr).await {
                Ok(v) => v,
                Err(e) => return Outcome::Failed($name.to_string(), e.to_string()),
            }
        }};
    }

    // fetch — acquire the repository into a temp dir. `fetched` owns that dir and
    // removes it on drop, which happens when this function returns.
    let fetched = step!("fetch", async {
        let token = github_token();
        crate::agents::fetch::fetch_repo(&state.repo_url, &state.repo_branch, &token).await
    });
    state.clone_path = fetched.path().to_string_lossy().to_string();

    // scan — gitleaks, read-only mount. A scanner failure is a phase failure: the
    // job must not then report a score.
    step!("scan", async {
        let sandbox = crate::services::sandbox::SandboxManager::new("", "");
        let result = crate::agents::scanner::run_secret_scan(fetched.path(), &sandbox).await;
        state.scanner_execution.insert(
            crate::agents::scanner::SCANNER_NAME.to_string(),
            result.scanner_execution.clone(),
        );
        state.analysis_performed = !result.failed;
        state.findings = result.findings.clone();
        if result.failed {
            Err(AppError::Internal(
                "gitleaks scan failed; no result can be reported".into(),
            ))
        } else {
            Ok(())
        }
    });

    // normalize — dedupe by fingerprint of rule + file + line, then reject
    // anything that escaped without a file, a line, or evidence. The pipeline
    // may not carry invalid findings forward, so the count kept in
    // `state.findings` is the count that can actually be persisted.
    let prepared = step!("normalize", async {
        let deduped = dedupe_findings(std::mem::take(&mut state.findings));
        let validated = prepare_findings_for_persist(deduped);
        state.findings = validated.valid.clone();
        Ok(validated)
    });
    state
        .scanner_execution
        .insert("normalize".to_string(), serde_json::json!(prepared));

    // score — a real score only when analysis actually ran, and counted over
    // the persisted findings so the score can never rest on dropped rows.
    step!("score", async {
        let count = state.findings.len();
        state.security_score = score_scan(state.analysis_performed, count);
        state.risk_summary = risk_summary(state.analysis_performed, count);
        Ok(())
    });

    // report — persist findings to `findings`, then persist the markdown report.
    step!("report", async {
        let job =
            sqlx::query_as::<_, crate::models::AuditJob>("SELECT * FROM audit_jobs WHERE id=$1")
                .bind(job_id)
                .fetch_one(pool)
                .await
                .map_err(AppError::Database)?;
        let stored = persist_findings(pool, job_id, &state.findings).await?;
        if stored != state.findings.len() {
            return Err(AppError::Internal(format!(
                "expected to persist {} findings but stored {stored}",
                state.findings.len()
            )));
        }
        let stored_rows = load_findings(pool, job_id).await?;
        if stored_rows.len() != state.findings.len() {
            return Err(AppError::Internal(format!(
                "expected {} finding rows for job {job_id} but read {}",
                state.findings.len(),
                stored_rows.len()
            )));
        }
        state.findings = stored_rows;
        let markdown = crate::services::reporter::ReportGenerator::generate_markdown(
            &job,
            &state.findings,
            state.security_score,
        )?;
        sqlx::query(
            "INSERT INTO audit_reports (id, job_id, markdown_content, created_at) VALUES ($1,$2,$3,$4) \
             ON CONFLICT (job_id) DO UPDATE SET markdown_content=EXCLUDED.markdown_content",
        )
        .bind(generate_uuid())
        .bind(job_id)
        .bind(&markdown)
        .bind(Utc::now().naive_utc())
        .execute(pool)
        .await
        .map_err(AppError::Database)?;
        Ok(())
    });

    // deliver — the report is produced synchronously above; delivery itself is
    // on demand through `POST /audit/job/:id/email`. This phase asserts the
    // report it must hand off actually exists.
    step!("deliver", async {
        let exists: Option<(String,)> =
            sqlx::query_as("SELECT id FROM audit_reports WHERE job_id=$1")
                .bind(job_id)
                .fetch_optional(pool)
                .await
                .map_err(AppError::Database)?;
        if exists.is_none() {
            return Err(AppError::Internal(
                "report was not persisted before delivery".into(),
            ));
        }
        Ok(())
    });

    Outcome::Ok
}

/// Bracket one phase with a `phase_ledger` start row and a terminal row.
async fn phase<F, T>(pool: &PgPool, job_id: &str, name: &str, fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    log_phase_started(pool, job_id, name).await?;
    let started = Utc::now();
    match fut.await {
        Ok(value) => {
            log_phase_completed(pool, job_id, name, "completed", started, None).await?;
            Ok(value)
        }
        Err(e) => {
            log_phase_completed(pool, job_id, name, "failed", started, Some(e.to_string())).await?;
            Err(e)
        }
    }
}

/// Score for a completed scan, in `[0, 9]`.
///
/// `None` when no analysis ran (which includes a failed scanner). A scan never
/// asserts perfection: zero findings yields `9.0`, not `10.0`, because "no
/// findings" is not the same as "proven secure". A perfect `10/10` derived from
/// an empty result would be the most misleading output this product could give.
/// Read back persisted findings for a job, newest writes last.
pub async fn load_findings(pool: &PgPool, job_id: &str) -> Result<Vec<Finding>> {
    let rows: Vec<crate::models::FindingModel> = sqlx::query_as::<_, crate::models::FindingModel>(
        "SELECT * FROM findings WHERE job_id=$1 ORDER BY created_at ASC, id ASC",
    )
    .bind(job_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(rows
        .into_iter()
        .map(
            |f: crate::models::FindingModel| crate::schemas::audit_state::Finding {
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
            },
        )
        .collect())
}

/// A finding is persistable only when it carries the scanner's file, line, and
/// evidence. Anything else is rejected and counted, so the report can never be
/// built from a row the schema refuses to hold.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ValidatedFindings {
    pub valid: Vec<Finding>,
    pub raw_count: usize,
    pub dropped_count: usize,
}

pub fn prepare_findings_for_persist(findings: Vec<Finding>) -> ValidatedFindings {
    let raw_count = findings.len();
    let valid: Vec<Finding> = findings
        .into_iter()
        .filter(|f| {
            f.file_path
                .as_deref()
                .map(|path| !path.trim().is_empty())
                .unwrap_or(false)
                && f.line_number.is_some()
                && f.evidence
                    .as_deref()
                    .map(|evidence| !evidence.trim().is_empty())
                    .unwrap_or(false)
        })
        .collect();
    ValidatedFindings {
        dropped_count: raw_count.saturating_sub(valid.len()),
        valid,
        raw_count,
    }
}

/// Score for a completed scan, in `[0, 9]`.
///
/// `None` when no analysis ran (which includes a failed scanner). A scan never
/// asserts perfection: zero findings yields `9.0`, not `10.0`, because "no
/// findings" is not the same as "proven secure".
pub fn score_scan(analysis_performed: bool, finding_count: usize) -> Option<f64> {
    if !analysis_performed {
        return None;
    }
    let penalty = finding_count as f64 * 1.5;
    Some((10.0 - penalty).clamp(0.0, 9.0))
}

/// Idempotently replace a job's findings with the exact count given.
///
/// Using one stable row per input (fingerprint-matching when the job already has
/// rows, otherwise freshly inserted) means rerunning this phase neither leaves
/// stale rows behind nor appends duplicates. The returned count must equal
/// `findings.len()` or the caller treats the phase as failed.
pub async fn persist_findings(pool: &PgPool, job_id: &str, findings: &[Finding]) -> Result<usize> {
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    let mut stored = 0usize;
    for finding in findings {
        let now = Utc::now().naive_utc();
        let updated = sqlx::query(
            "UPDATE findings SET agent_source=$1, title=$2, description=$3, severity=$4, \
             cvss_vector=$5, cvss_score=$6, evidence=$7, remediation=$8, cwe_id=$9, \
             owasp_category=$10, confidence=$11, scanner_name=$12, scanner_mode=$13, \
             file_path=$14, line_number=$15, route=$16, metadata_json=CAST($17 AS JSONB), \
             created_at=$18 \
             WHERE job_id=$19 AND id=$20",
        )
        .bind(&finding.agent_source)
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(finding.severity.as_str())
        .bind(finding.cvss_vector.as_deref())
        .bind(finding.cvss_score)
        .bind(finding.evidence.as_deref())
        .bind(finding.remediation.as_deref())
        .bind(finding.cwe_id.as_deref())
        .bind(finding.owasp_category.as_deref())
        .bind(finding.confidence.as_deref())
        .bind(finding.scanner_name.as_deref())
        .bind(finding.scanner_mode.as_deref())
        .bind(finding.file_path.as_deref())
        .bind(finding.line_number)
        .bind(finding.route.as_deref())
        .bind(finding.metadata_json.as_deref())
        .bind(now)
        .bind(job_id)
        .bind(&finding.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .rows_affected();
        if updated == 0 {
            sqlx::query(
                "INSERT INTO findings (id, job_id, agent_source, title, description, \
                 severity, cvss_vector, cvss_score, evidence, remediation, cwe_id, \
                 owasp_category, confidence, scanner_name, scanner_mode, file_path, \
                 line_number, route, metadata_json, created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,CAST($19 AS JSONB),$20)",
            )
            .bind(&finding.id)
            .bind(job_id)
            .bind(&finding.agent_source)
            .bind(&finding.title)
            .bind(&finding.description)
            .bind(finding.severity.as_str())
            .bind(finding.cvss_vector.as_deref())
            .bind(finding.cvss_score)
            .bind(finding.evidence.as_deref())
            .bind(finding.remediation.as_deref())
            .bind(finding.cwe_id.as_deref())
            .bind(finding.owasp_category.as_deref())
            .bind(finding.confidence.as_deref())
            .bind(finding.scanner_name.as_deref())
            .bind(finding.scanner_mode.as_deref())
            .bind(finding.file_path.as_deref())
            .bind(finding.line_number)
            .bind(finding.route.as_deref())
            .bind(finding.metadata_json.as_deref())
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;
        }
        stored += 1;
    }
    sqlx::query(
        "DELETE FROM findings WHERE job_id=$1 AND id NOT IN \
         (SELECT UNNEST(CAST($2 AS TEXT[])))",
    )
    .bind(job_id)
    .bind(
        &findings
            .iter()
            .map(|finding| finding.id.clone())
            .collect::<Vec<String>>(),
    )
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    tx.commit().await.map_err(AppError::Database)?;
    Ok(stored)
}

/// The `risk_summary` persisted on the scan.
///
/// `analysis_performed` is `true` only when the scanner actually ran and
/// succeeded, so a client can tell a clean result apart from no result.
pub fn risk_summary(analysis_performed: bool, finding_count: usize) -> serde_json::Value {
    let score = score_scan(analysis_performed, finding_count);
    serde_json::json!({
        "score": score,
        "risk_level": risk_level(score),
        "total_findings": finding_count,
        "analysis_performed": analysis_performed,
    })
}

/// Coarse risk label for a score. `unknown` whenever there is no score.
pub fn risk_level(score: Option<f64>) -> &'static str {
    match score {
        None => "unknown",
        Some(s) if s >= 8.0 => "low",
        Some(s) if s >= 5.0 => "medium",
        Some(s) if s >= 2.0 => "high",
        Some(_) => "critical",
    }
}

/// Stable identity for a finding: scanner rule + file + line (+ scanner name).
///
/// The rule id is carried in `metadata_json` by the scanner; when absent the
/// title stands in. This is deliberately *not* a similarity heuristic — it only
/// collapses entries the scanner emitted twice for the same location.
pub fn finding_fingerprint(f: &Finding) -> String {
    let rule = f
        .metadata_json
        .as_deref()
        .and_then(|m| serde_json::from_str::<serde_json::Value>(m).ok())
        .and_then(|v| {
            v.get("rule_id")
                .and_then(|r| r.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| f.title.clone());
    format!(
        "{}|{}|{}|{}",
        rule,
        f.file_path.clone().unwrap_or_default(),
        f.line_number.unwrap_or(0),
        f.scanner_name.clone().unwrap_or_default(),
    )
}

/// Collapse findings that share a fingerprint, keeping the first occurrence.
pub fn dedupe_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: HashSet<String> = HashSet::new();
    findings
        .into_iter()
        .filter(|f| seen.insert(finding_fingerprint(f)))
        .collect()
}

/// The platform GitHub token used for repository access.
///
/// Per-user tokens are stored encrypted and are not decrypted in the worker yet;
/// until they are, scans use the platform token, which is sufficient for public
/// repositories. An empty value means an unauthenticated (public-only) fetch.
fn github_token() -> String {
    std::env::var("GITHUB_TOKEN")
        .unwrap_or_default()
        .trim()
        .to_string()
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
    cleaned.split('/').nth_back(1).unwrap_or("").into()
}

fn extract_repo_name(url: &str) -> String {
    let cleaned = url.trim_end_matches('/').trim_end_matches(".git");
    cleaned.split('/').next_back().unwrap_or("repo").into()
}

/// Record a phase that never ran.
///
/// `log_phase_completed` only updates a row that `log_phase_started` inserted,
/// so it silently does nothing for a phase that was skipped before starting.
/// This inserts the terminal row directly, with `mode='skipped'` so it is
/// distinguishable from real work.
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
