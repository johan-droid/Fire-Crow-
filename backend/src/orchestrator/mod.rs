//! Audit job orchestrator.
//!
//! Phase 12.1: there is exactly one production persistence path, and it
//! terminates through `execution::finalize_execution` (or
//! `finalize_without_findings` for attempts that never produced a result).
//! The pipeline opens an execution at claim, binds the snapshot to it, runs
//! scanners, canonicalizes, and finalizes — one COMMIT. `persist_findings`
//! is a test helper; no production code calls it.

use crate::error::{AppError, Result};
use crate::models::JobStatus;
use crate::schemas::audit_state::{AuditState, Finding};
use crate::utils::generate_uuid;

pub mod ai_narrative;
pub mod canonical_audit;
pub mod delivery;
pub mod execution;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashSet;

/// Terminal outcome of the pipeline.
enum Outcome {
    Ok,
    Partial(String),
    Failed(String, String),
    Cancelled,
}

/// Atomically move a queued job to `running`, returning whether this worker won.
///
/// This is the queue's claim point, and it is single-statement so two workers
/// racing for the same row cannot both observe it as `queued`.
///
/// Only `queued` may be claimed. A job that is already `running` is owned by
/// another worker, and a terminal job is a historical record that no execution
/// may reopen.
pub async fn claim_job_for_execution(pool: &PgPool, job_id: &str) -> Result<bool> {
    let claimed =
        sqlx::query("UPDATE audit_jobs SET status=$1, started_at=NOW() WHERE id=$2 AND status=$3")
            .bind(JobStatus::Running)
            .bind(job_id)
            .bind(JobStatus::Queued)
            .execute(pool)
            .await
            .map_err(AppError::Database)?
            .rows_affected();
    Ok(claimed == 1)
}

/// Whether an execution may proceed against this job.
///
/// The pipeline used to issue an unguarded
/// `UPDATE ... WHERE status IN ('queued','running')` and discard the result, so
/// a worker arriving after an audit had already finished still ran the entire
/// pipeline: it re-fetched, re-scanned, and [`persist_findings`] then deleted
/// and rewrote the finished audit's findings. The status guard quietly stopped
/// the *status* from changing but not the *findings* from being replaced.
///
/// A terminal job is refused; a missing job has nothing to execute. `queued`
/// and `running` are both accepted, because the queue claims `queued -> running`
/// before handing the job to the pipeline — a legitimately in-flight job is
/// therefore already `running` by the time it starts executing.
pub async fn may_execute_job(pool: &PgPool, job_id: &str) -> Result<bool> {
    let row: Option<(JobStatus,)> = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(job_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::Database)?;
    Ok(matches!(row, Some((status,)) if !status.is_terminal()))
}

/// Project the in-memory scanner execution map into persistable per-scanner rows.
///
/// Phase 12 closed the gap where scanner statuses and coverage existed only in
/// process memory: without this, a finished audit could not say which scanners
/// ran or whether any of them failed.
fn scanner_run_records(
    execution_map: &std::collections::HashMap<String, serde_json::Value>,
) -> Vec<execution::ScannerRunRecord> {
    execution_map
        .iter()
        .filter(|(name, _)| matches!(name.as_str(), "gitleaks" | "osv" | "semgrep"))
        .map(|(name, record)| {
            let text = |key: &str| {
                record
                    .get(key)
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let status = if record.get("error").is_some() {
                "failed".to_string()
            } else {
                match record.get("coverage").and_then(|v| v.as_str()) {
                    Some("unknown") => "failed".to_string(),
                    _ => match record.get("finding_count").and_then(|v| v.as_u64()) {
                        Some(0) => "success_clean".to_string(),
                        Some(_) => "success_findings".to_string(),
                        None => "success_clean".to_string(),
                    },
                }
            };
            let coverage_known = status.starts_with("success");
            execution::ScannerRunRecord {
                scanner: name.clone(),
                version: text("version"),
                parser: text("parser"),
                mode: text("mode"),
                image: text("image"),
                status,
                finding_count: record
                    .get("finding_count")
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32),
                coverage_known,
                detail: record
                    .get("error")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                limitations: Vec::new(),
            }
        })
        .collect()
}

/// Per-execution inputs resolved by the worker before the pipeline runs.
///
/// Both are optional and both fall back safely: no token means the platform
/// token (or an unauthenticated public-only fetch), and no SHA means the
/// branch head resolved at fetch time. Neither is ever persisted — a resolved
/// credential must not become audit data, and the pinned snapshot is recorded
/// separately by the fetch phase itself.
#[derive(Debug, Clone, Default)]
pub struct ExecutionInput {
    /// Caller-resolved GitHub token (e.g. the user's own OAuth token,
    /// decrypted by the worker). Never stored.
    pub github_token: Option<String>,
    /// Caller-pinned commit SHA from the submission contract. Used verbatim;
    /// a branch is only an input used to resolve a SHA.
    pub requested_sha: Option<String>,
}

pub async fn execute_audit_job(
    pool: &PgPool,
    job_id: &str,
    user_id: &str,
    repo_url: &str,
    repo_branch: &str,
    custom_email: Option<&str>,
    input: Option<ExecutionInput>,
) -> Result<AuditState> {
    let _ = custom_email;
    let input = input.unwrap_or_default();
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

    // Decide whether this execution may proceed at all. A finished audit is a
    // historical record: re-running it would re-fetch, re-scan, and then
    // overwrite the very findings the finished audit reported. The previous
    // code performed this check's UPDATE but discarded its result, so the
    // pipeline ran regardless.
    //
    // A `queued` job is claimed here (the direct-invocation path, where nothing
    // claimed it first). A `running` job is already owned by the queue's claim
    // and is executing legitimately.
    if may_execute_job(pool, job_id).await.unwrap_or(false) {
        let _ = claim_job_for_execution(pool, job_id).await;
    } else {
        tracing::info!(
            "[orchestrator] Job {} is already finalized; execution skipped",
            job_id
        );
        // Re-read the row so the caller sees the real persisted state rather
        // than a fabricated `running`.
        let existing: Option<crate::models::AuditJob> =
            sqlx::query_as("SELECT * FROM audit_jobs WHERE id=$1")
                .bind(job_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();
        if let Some(existing) = existing {
            state.status = existing.status;
            state.commit_sha = existing.commit_sha;
            state.repo_url = existing.repo_url;
            state.repo_branch = existing.repo_branch;
            state.created_at = existing.created_at.and_utc();
        }
        return Ok(state);
    }

    tracing::info!(
        "[orchestrator] Starting job {} for repo {} at {}",
        job_id,
        repo_url,
        Utc::now().to_rfc3339()
    );

    // Open a durable execution for this attempt. Everything this run produces
    // belongs to it, and only its holder may finalize it. The execution opens
    // BEFORE any phase row or snapshot write, so every persistence below is
    // scoped to this attempt (Phase 12.1: exactly one production path).
    let lease = match execution::begin_execution(pool, job_id).await {
        Ok(lease) => lease,
        Err(error) => {
            tracing::warn!("[orchestrator] Job {job_id} could not open an execution: {error}");
            return Err(error);
        }
    };
    let exec_id = Some(lease.execution_id.as_str());

    let engine_available = crate::agents::ENGINE_AVAILABLE;

    // Phase: intake — resolve owner/name from the (already validated) URL.
    let intake = phase(pool, job_id, exec_id, "intake", async {
        state.repo_owner = extract_repo_owner(repo_url);
        state.repo_name = extract_repo_name(repo_url);
        Ok(())
    })
    .await;

    let outcome = match intake {
        Ok(()) => {
            if engine_available {
                run_pipeline(pool, job_id, &lease, &mut state, &input).await
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
                    exec_id,
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
        Outcome::Partial(_) => JobStatus::Partial,
        Outcome::Ok => {
            if engine_available {
                JobStatus::Completed
            } else {
                JobStatus::EngineUnavailable
            }
        }
    };

    // Close out any phase rows left `started` by this execution (e.g. by a
    // cancellation) so the ledger never shows a phase as perpetually in
    // flight. Scoped to this execution: another attempt's rows are untouched.
    let _ = sqlx::query(
        "UPDATE phase_ledger SET status='skipped', ended_at=$1 WHERE execution_id=$2 AND status='started'",
    )
    .bind(Utc::now().naive_utc())
    .bind(&lease.execution_id)
    .execute(pool)
    .await;

    // Phase 12: one atomic commit point.
    //
    // The five status-writing arms this replaces each committed separately from
    // the findings and the report, so a crash between them could leave persisted
    // findings under an audit that never finalized. `finalize_execution` commits
    // findings, scanner runs, the canonical document, the report row, the
    // execution's terminal status, and the job's status together — or not at all.
    let finalization = match &outcome {
        Outcome::Failed(phase_name, msg) => {
            let reason = format!("{phase_name} phase failed: {msg}");
            execution::Finalization {
                job_status: "failed".into(),
                failure_reason: Some(reason.clone()),
                security_score: None,
                ..Default::default()
            }
        }
        Outcome::Cancelled => execution::Finalization {
            job_status: "cancelled".into(),
            failure_reason: Some("Job cancelled by user".into()),
            security_score: None,
            ..Default::default()
        },
        Outcome::Partial(reason) => execution::Finalization {
            job_status: "partial".into(),
            failure_reason: Some(format!("partial coverage: {reason}")),
            security_score: None,
            // Successful scanners' findings are kept; the coverage state is what
            // makes the audit explicitly not-complete rather than clean.
            findings: state.findings.clone(),
            scanner_runs: scanner_run_records(&state.scanner_execution),
            coverage_status: "partial".into(),
            coverage_complete: false,
            coverage_limitations: state.coverage_limitations.clone(),
            summary: Some(state.risk_summary.clone()),
            report_markdown: state.report_markdown.clone(),
            report_json: state.report_json.clone(),
            report_html: state.report_html.clone(),
            canonical_json: state.canonical_json.clone(),
        },
        Outcome::Ok => execution::Finalization {
            findings: state.findings.clone(),
            scanner_runs: scanner_run_records(&state.scanner_execution),
            coverage_status: if state.coverage_complete {
                "complete".into()
            } else {
                "partial".into()
            },
            coverage_complete: state.coverage_complete,
            coverage_limitations: state.coverage_limitations.clone(),
            summary: Some(state.risk_summary.clone()),
            report_markdown: state.report_markdown.clone(),
            report_json: state.report_json.clone(),
            report_html: state.report_html.clone(),
            security_score: state.security_score,
            job_status: if engine_available {
                "completed".into()
            } else {
                "engine_unavailable".into()
            },
            failure_reason: if engine_available {
                None
            } else {
                Some(crate::agents::ENGINE_UNAVAILABLE_REASON.to_string())
            },
            canonical_json: state.canonical_json.clone(),
        },
    };

    match execution::finalize_execution(pool, &lease, &finalization).await {
        Ok(()) => state.status = final_status,
        Err(error) => {
            // A refused finalization means this worker no longer owns the
            // execution (a stale worker, or one whose attempt was already
            // finalized). It must not overwrite the newer state, so the error
            // is logged and the persisted status is re-read instead.
            tracing::warn!("[orchestrator] Job {job_id} finalization refused: {error}");
            if let Ok(Some(job)) =
                sqlx::query_as::<_, crate::models::AuditJob>("SELECT * FROM audit_jobs WHERE id=$1")
                    .bind(job_id)
                    .fetch_optional(pool)
                    .await
            {
                state.status = job.status;
                state.security_score = job.security_score;
            }
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
async fn run_pipeline(
    pool: &PgPool,
    job_id: &str,
    lease: &execution::ExecutionLease,
    state: &mut AuditState,
    input: &ExecutionInput,
) -> Outcome {
    let exec_id = Some(lease.execution_id.as_str());
    macro_rules! step {
        ($name:literal, $expr:expr) => {{
            if is_cancelled(pool, job_id).await.unwrap_or(false) {
                return Outcome::Cancelled;
            }
            // Heartbeat so the reaper can tell "alive" from "dead" instead of
            // guessing from elapsed time. Best-effort: a missed beat only
            // risks a later reap, never a wrong result.
            let _ = execution::heartbeat(pool, &lease.execution_id, &lease.owner_token).await;
            match phase(pool, job_id, exec_id, $name, $expr).await {
                Ok(v) => v,
                // A phase that fails while cancellation was requested ends as
                // cancelled, not failed: the user asked for it to stop.
                Err(e) => {
                    if is_cancelled(pool, job_id).await.unwrap_or(false) {
                        return Outcome::Cancelled;
                    }
                    return Outcome::Failed($name.to_string(), e.to_string());
                }
            }
        }};
    }

    // fetch — validate access, capture repository metadata, pin the branch head,
    // and acquire the repository into a temp dir. `fetched` owns that dir and
    // removes it on drop, which happens when this function returns.
    //
    // The download/extraction is where the minutes go, so cancellation is
    // polled *during* the fetch (not just before it): the poller flips the
    // flag, the fetch aborts at its next checkpoint, and the temp dir is
    // still cleaned up by the guard.
    let fetched = step!("fetch", async {
        // The worker-resolved token first (the user's own, for private
        // repositories they granted), the platform token otherwise. The
        // resolved value lives only in this call — it is never persisted.
        let token = input
            .github_token
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .unwrap_or_else(github_token);
        let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let poll_flag = cancel_flag.clone();
        let poll_pool = pool.clone();
        let poll_job = job_id.to_string();
        let poller = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tick.tick().await;
                if is_cancelled(&poll_pool, &poll_job).await.unwrap_or(false) {
                    poll_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
        });
        let out = crate::agents::fetch::fetch_repo_with_cancel(
            &state.repo_url,
            &state.repo_branch,
            &token,
            input.requested_sha.as_deref(),
            &|| cancel_flag.load(std::sync::atomic::Ordering::Relaxed),
        )
        .await;
        poller.abort();
        out
    });
    state.clone_path = fetched.path().to_string_lossy().to_string();
    state.commit_sha = fetched.metadata().commit_sha.clone();
    // Pin the snapshot on the job the moment the fetch resolves it. An audit is
    // a judgement about exactly one immutable tree, so the snapshot becomes part
    // of the audit's identity here, and every finding is checked against it
    // before it may be persisted.
    // Pin the snapshot on the job and the execution together, before any
    // scanner runs. `bind_snapshot` is authoritative: a bind failure (stale
    // lease, already-bound execution) fails the pipeline rather than scanning
    // a tree no attempt can be proven to have judged.
    if let Some(commit) = state.commit_sha.clone() {
        let _ = sqlx::query("UPDATE audit_jobs SET commit_sha=$1 WHERE id=$2")
            .bind(&commit)
            .bind(job_id)
            .execute(pool)
            .await;
        if let Err(e) =
            execution::bind_snapshot(pool, &lease.execution_id, &lease.owner_token, &commit).await
        {
            return Outcome::Failed("fetch".to_string(), e.to_string());
        }
    }
    state.repo_visibility = Some(fetched.metadata().visibility.as_str().to_string());
    state.scanner_execution.insert(
        "fetch_snapshot".to_string(),
        serde_json::to_value(fetched.snapshot()).unwrap_or(serde_json::Value::Null),
    );

    // Phase 13: the report is derived from a canonical audit, which needs both
    // the scanner results and the raw findings of this attempt. They are kept in
    // locals (never in `scanner_execution`, which is the persisted summary form)
    // and consumed by the report phase below.
    let mut scanner_results: Vec<crate::agents::scanner::ScannerResult> = Vec::new();
    let mut aggregated_findings: Vec<Finding> = Vec::new();

    // scan — the real scanner runtime, one scanner at a time over the same
    // snapshot. The orchestrator knows only `run secret scan` /
    // `run dependency scan`; how each tool understands the tree lives in its
    // adapter. Every scanner's outcome is explicit, and only successful runs
    // may feed the rest of the pipeline: a failed, timed-out, or cancelled
    // scan is unknown coverage, never zero findings. Usable findings are kept
    // even when another scanner fails; incomplete coverage becomes Partial,
    // never a complete result.
    step!("scan", async {
        let sandbox = crate::services::sandbox::SandboxManager::new();
        let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let poll_flag = cancel_flag.clone();
        let poll_pool = pool.clone();
        let poll_job = job_id.to_string();
        let poller = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tick.tick().await;
                if is_cancelled(&poll_pool, &poll_job).await.unwrap_or(false) {
                    poll_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
        });
        let snapshot = fetched.snapshot();
        let input = crate::agents::scanner::ScanInput {
            source_dir: fetched.path().to_path_buf(),
            commit_sha: snapshot.commit_sha.clone().into(),
            file_count: snapshot.file_count,
            total_size: snapshot.total_size,
        };
        let cancelled = || cancel_flag.load(std::sync::atomic::Ordering::Relaxed);
        let secret = crate::agents::scanner::run_secret_scan(&input, &sandbox, &cancelled).await;
        let dependency =
            crate::agents::scanner::run_dependency_scan(&input, &sandbox, &cancelled).await;
        let sast = crate::agents::scanner::run_sast_scan(&input, &sandbox, &cancelled).await;
        poller.abort();

        // Scanning can legitimately take many minutes. Report liveness so the
        // reaper can tell a slow-but-healthy execution from a dead one, instead
        // of inferring death from elapsed time.
        let _ = execution::heartbeat(pool, &lease.execution_id, &lease.owner_token).await;

        let scanners = [&secret, &dependency, &sast];
        for result in scanners {
            state
                .scanner_execution
                .insert(result.scanner.clone(), result.execution_record.clone());
        }
        let (findings, coverage, detail) = canonical_audit::aggregate_scan_results(&scanners);
        // Analysis ran if any scanner reported. Coverage completeness is
        // tracked separately so a partial result can never receive a score.
        state.analysis_performed = scanners.iter().any(|r| r.analyzed());
        state.coverage_complete = coverage.complete;
        state.coverage_detail = detail.clone();
        state.coverage_limitations = coverage.limitations.clone();
        state.scanner_execution.insert(
            "coverage".to_string(),
            serde_json::json!({
                "status": coverage.status.as_str(),
                "complete": coverage.complete,
                "successful_scanners": coverage.successful_scanners,
                "unsuccessful_scanners": coverage.unsuccessful_scanners,
                "limitations": coverage.limitations,
            }),
        );
        state.findings = findings;

        // Phase 13: keep this attempt's scanner results and raw findings for the
        // canonical-audit build in the report phase. These live only in memory
        // until the single finalization commit.
        scanner_results = scanners.iter().map(|result| (*result).clone()).collect();
        aggregated_findings = state.findings.clone();

        // A cancelled scan ends the job as cancelled, not as a failure.
        if scanners
            .iter()
            .any(|r| r.outcome == crate::agents::scanner::ScannerOutcome::Cancelled)
        {
            return Err(AppError::Cancelled("scan cancelled".into()));
        }
        if !state.analysis_performed {
            let first = scanners
                .iter()
                .find(|r| !r.usable())
                .map(|r| {
                    format!(
                        "scanner {} did not produce a trustworthy result ({}); no result can be reported",
                        r.scanner,
                        r.outcome.as_str()
                    )
                })
                .unwrap_or_else(|| "no scanner produced a trustworthy result".to_string());
            return Err(AppError::Internal(first));
        }
        Ok(())
    });

    // normalize — canonical identity first, then type-specific evidence
    // validation. Exact duplicates are correlated rather than silently
    // dropped; invalid findings are quarantined and counted. The pipeline may
    // not carry invalid findings forward, so the count kept in
    // `state.findings` is the count that can actually be persisted.
    let prepared = step!("normalize", async {
        let normalized =
            canonical_audit::normalize_findings_for_persist(std::mem::take(&mut state.findings));
        if !normalized.invalid.is_empty() {
            state.coverage_complete = false;
            state.coverage_detail = Some(format!(
                "{} finding(s) failed canonical evidence validation",
                normalized.invalid.len()
            ));
            state.coverage_limitations.push(format!(
                "{} finding(s) failed canonical evidence validation",
                normalized.invalid.len()
            ));
            state.coverage_limitations.sort();
            state.coverage_limitations.dedup();
        }
        state.findings = normalized.valid.clone();
        Ok(normalized)
    });
    state
        .scanner_execution
        .insert("normalize".to_string(), serde_json::json!(prepared));

    // score — a real score only when coverage is complete, and counted over
    // the persisted findings so the score can never rest on dropped rows.
    // Partial coverage keeps successful findings but leaves the score null.
    step!("score", async {
        let count = state.findings.len();
        state.security_score = score_scan(state.coverage_complete, count);
        state.risk_summary = coverage_risk_summary(state, count);
        Ok(())
    });

    // report — build the canonical audit for this attempt and derive the
    // deterministic report from it, but write nothing yet.
    //
    // Phase 12: this step used to commit the findings and the report row here,
    // in their own transactions, before the terminal status was written
    // somewhere else entirely. A crash in between left persisted findings under
    // an audit that never finalized — the exact D1 failure. The report text is
    // now produced here and committed by `finalize_execution`, so there is one
    // commit boundary for the whole audit result.
    //
    // Phase 13: the report is a *presentation* of a Canonical Audit v1. This step
    // builds the canonical audit from this attempt's scanner results and raw
    // findings, then derives Markdown, JSON, and HTML from that single model. No
    // scanner is re-run, no repository is re-read, and no AI service is called.
    step!("report", async {
        let snapshot = fetched.snapshot();
        let request = canonical_audit::CanonicalAuditRequest {
            scan_id: job_id,
            repository_url: &state.repo_url,
            repo_branch: &state.repo_branch,
            repo_owner: &state.repo_owner,
            repo_name: &state.repo_name,
            snapshot_commit: state.commit_sha.as_deref(),
            snapshot_file_count: snapshot.file_count,
            snapshot_total_size: snapshot.total_size,
            results: &scanner_results,
            findings: &aggregated_findings,
            security_score: state.security_score,
        };
        let audit = canonical_audit::canonical_audit(&request)
            .map_err(|error| AppError::Internal(format!("canonical audit failed: {error}")))?;
        let execution = crate::schemas::report::ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        };
        let report = crate::schemas::report::build_report(&audit, &execution)
            .map_err(|error| AppError::Internal(format!("report build failed: {error}")))?;
        let markdown = crate::services::reporter::ReportGenerator::render_markdown(&report)?;
        let html = crate::services::reporter::ReportGenerator::render_html(&report)?;
        state.canonical_json = Some(serde_json::to_value(&audit).map_err(|error| {
            AppError::Internal(format!("canonical audit serialization failed: {error}"))
        })?);
        state.report_json = Some(serde_json::to_value(&report).map_err(|error| {
            AppError::Internal(format!("report serialization failed: {error}"))
        })?);
        state.report_html = Some(html);
        state.report_markdown = Some(markdown);
        Ok(())
    });

    // deliver — the report is produced synchronously above; delivery itself is
    // on demand through `POST /audit/job/:id/email`. This phase asserts the
    // report it must hand off actually exists.
    //
    // It checks the *generated* document, not a persisted row: the report row,
    // the findings, and the terminal status are committed together by
    // `finalize_execution`, which runs after this pipeline returns. Requiring a
    // row here would ask for a commit boundary the atomicity invariant forbids.
    step!("deliver", async {
        if state.report_markdown.is_none() {
            return Err(AppError::Internal(
                "report was not generated before delivery".into(),
            ));
        }
        Ok(())
    });

    // Partial coverage is a terminal outcome of its own: successful scanners'
    // findings were persisted and reported, but the audit is explicitly not
    // complete and carries no score.
    if !state.coverage_complete {
        let reason = state
            .coverage_detail
            .clone()
            .unwrap_or_else(|| "one or more scanners did not analyze the repository".to_string());
        return Outcome::Partial(reason);
    }

    Outcome::Ok
}

/// Bracket one phase with a `phase_ledger` start row and a terminal row.
///
/// `execution_id` scopes the row to the attempt that produced it, so attempt
/// history is reconstructable per attempt (Phase 12.1), not only per job.
async fn phase<F, T>(
    pool: &PgPool,
    job_id: &str,
    execution_id: Option<&str>,
    name: &str,
    fut: F,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    log_phase_started(pool, job_id, execution_id, name).await?;
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
///
/// Phase 12.1: execution-scoped. Returns the findings of the job's latest
/// execution (the attempt the API reconstructs), so a retry never mixes two
/// attempts' evidence in one response. Legacy rows with no execution are
/// returned only when the job has no execution at all.
pub async fn load_findings(pool: &PgPool, job_id: &str) -> Result<Vec<Finding>> {
    let latest_exec: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number DESC LIMIT 1",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;
    let rows: Vec<crate::models::FindingModel> = match latest_exec {
        Some((exec_id,)) => sqlx::query_as::<_, crate::models::FindingModel>(
            "SELECT * FROM findings WHERE job_id=$1 AND execution_id=$2 ORDER BY created_at ASC, id ASC",
        )
        .bind(job_id)
        .bind(&exec_id)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)?,
        None => sqlx::query_as::<_, crate::models::FindingModel>(
            "SELECT * FROM findings WHERE job_id=$1 ORDER BY created_at ASC, id ASC",
        )
        .bind(job_id)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)?,
    };
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
                metadata_json: f.metadata_json.map(|v| v.to_string()),
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
/// Refuse to write findings to an audit that must not change.
///
/// Two invariants are checked before a single row is written, inside the same
/// transaction that performs the write:
///
/// 1. **Terminal audits are immutable.** A finished audit is a historical
///    record. `persist_findings` replaces a job's whole finding set, so without
///    this check a duplicate or retried execution silently replaced the
///    findings of a completed audit while its status guard quietly did nothing.
/// 2. **Findings belong to the audit's snapshot.** Each finding carries the
///    snapshot it was produced from; if that differs from the snapshot the job
///    is pinned to, the finding is evidence about a different tree and must not
///    be attached to this audit.
async fn assert_audit_is_writable(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    job_id: &str,
    findings: &[Finding],
) -> Result<()> {
    let row: Option<(JobStatus, Option<String>)> =
        sqlx::query_as("SELECT status, commit_sha FROM audit_jobs WHERE id=$1 FOR UPDATE")
            .bind(job_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::Database)?;
    let Some((status, commit)) = row else {
        return Err(AppError::NotFound(format!("audit job {job_id}")));
    };
    if status.is_terminal() {
        return Err(AppError::Conflict(format!(
            "audit {job_id} is already {} and its findings are immutable",
            status.as_str()
        )));
    }
    if let Some(job_commit) = commit.as_deref() {
        for finding in findings {
            let finding_commit = finding
                .metadata_json
                .as_deref()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
                .and_then(|meta| {
                    meta.get("snapshot_commit")
                        .and_then(|value| value.as_str())
                        .map(str::to_string)
                });
            if let Some(finding_commit) = finding_commit {
                if finding_commit != job_commit {
                    return Err(AppError::Conflict(format!(
                        "finding {} belongs to snapshot {finding_commit}, but audit {job_id} is pinned to {job_commit}",
                        finding.id
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Using one stable row per input (fingerprint-matching when the job already has
/// rows, otherwise freshly inserted) means rerunning this phase neither leaves
/// stale rows behind nor appends duplicates. The returned count must equal
/// `findings.len()` or the caller treats the phase as failed.
///
/// Phase 12.1 test helper, not part of the production path. Production commits
/// findings only inside `finalize_execution`, scoped to the owning execution.
/// Kept (and still guarded by the same writability checks) so the Phase 11
/// lifecycle tests keep exercising the trigger layer.
pub async fn persist_findings(pool: &PgPool, job_id: &str, findings: &[Finding]) -> Result<usize> {
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    assert_audit_is_writable(&mut tx, job_id, findings).await?;
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
        findings
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

/// Coverage-aware risk summary: same score fields plus explicit coverage.
///
/// The score still comes from [`score_scan`], but only complete coverage may
/// carry one — the caller passes the count and the coverage flag separately
/// so a partial result can never be scored by accident.
pub fn coverage_risk_summary(state: &AuditState, finding_count: usize) -> serde_json::Value {
    let score = score_scan(state.coverage_complete, finding_count);
    serde_json::json!({
        "score": score,
        "risk_level": risk_level(score),
        "total_findings": finding_count,
        "analysis_performed": state.analysis_performed,
        "coverage_complete": state.coverage_complete,
        "coverage_status": if state.coverage_complete {
            "complete"
        } else {
            "partial"
        },
        "coverage_detail": state.coverage_detail,
        "coverage_limitations": state.coverage_limitations,
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

/// Stable identity for a finding: canonical scanner identity.
///
/// Canonical normalization decides identity from scanner, versions, rule,
/// native fingerprint, normalized location/target, and evidence digest. The
/// legacy rule|file|line|scanner fallback is used only when a finding cannot
/// be validated; invalid rows must stay distinct rather than collapse.
pub fn finding_fingerprint(f: &Finding) -> String {
    canonical_audit::canonical_identity(f).unwrap_or_else(|_| {
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
            "legacy|{}|{}|{}|{}|{}",
            rule,
            f.file_path.clone().unwrap_or_default(),
            f.line_number.unwrap_or(0),
            f.scanner_name.clone().unwrap_or_default(),
            f.id,
        )
    })
}

/// Collapse findings that share a canonical identity, keeping the first
/// occurrence in canonical order.
///
/// Ordering is by canonical identity first, so scanner result order can never
/// change which representative survives.
pub fn dedupe_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut ordered = findings;
    ordered.sort_by_key(finding_fingerprint);
    let mut seen: HashSet<String> = HashSet::new();
    ordered
        .into_iter()
        .filter(|f| seen.insert(finding_fingerprint(f)))
        .collect()
}

/// The platform GitHub token used for repository access.
///
/// Per-user tokens are resolved by the worker (decrypted there, never stored)
/// and arrive via [`ExecutionInput`]; this is the fallback for jobs without
/// one, sufficient for public repositories. An empty value means an
/// unauthenticated (public-only) fetch.
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
async fn log_phase_skipped(
    pool: &PgPool,
    job_id: &str,
    execution_id: Option<&str>,
    phase: &str,
    reason: &str,
) -> Result<()> {
    let now = Utc::now().naive_utc();
    let _ = sqlx::query("INSERT INTO phase_ledger (id, job_id, execution_id, phase_name, status, mode, started_at, ended_at, duration_sec, error_message) VALUES ($1,$2,$3,$4,'skipped','skipped',$5,$5,0,$6)")
        .bind(generate_uuid())
        .bind(job_id)
        .bind(execution_id)
        .bind(phase)
        .bind(now)
        .bind(reason)
        .execute(pool)
        .await;
    Ok(())
}

async fn log_phase_started(
    pool: &PgPool,
    job_id: &str,
    execution_id: Option<&str>,
    phase: &str,
) -> Result<()> {
    let id = generate_uuid();
    let _ = sqlx::query("INSERT INTO phase_ledger (id, job_id, execution_id, phase_name, status, mode, started_at) VALUES ($1,$2,$3,$4,'started','real',$5)")
        .bind(id).bind(job_id).bind(execution_id).bind(phase).bind(Utc::now().naive_utc()).execute(pool).await;
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
