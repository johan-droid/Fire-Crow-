//! Durable execution identity for an audit.
//!
//! An audit is a question ("what is in this repository at this snapshot?") and
//! an *execution* is one attempt to answer it. Before this module a retry reused
//! the job row: `started_at` was overwritten, there was no attempt number, and
//! nothing recorded why an earlier attempt ended. That made three questions from
//! the Phase 12 criterion unanswerable — how many attempts, which is current,
//! and why did each end.
//!
//! Ownership is a lease. `begin_execution` mints an `owner_token`; only the
//! holder may finalize, and a worker that lost the token is refused at the
//! database rather than in process memory. That is what makes a stale worker
//! safe: it cannot overwrite a newer execution because it no longer owns one.
use crate::error::{AppError, Result};
use crate::schemas::ai_narrative::ReportNarrative;
use crate::utils::generate_uuid;
use chrono::NaiveDateTime;
use sqlx::PgPool;

/// Persisted AI narrative, keyed by execution.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredAiNarrative {
    pub execution_id: String,
    pub job_id: String,
    pub attempt_number: i32,
    pub narrative_schema_version: i32,
    pub narrative: ReportNarrative,
}

/// One attempt at auditing a job.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditExecution {
    pub id: String,
    pub job_id: String,
    pub attempt_number: i32,
    pub status: String,
    pub commit_sha: Option<String>,
    pub started_at: NaiveDateTime,
    pub finished_at: Option<NaiveDateTime>,
    pub failure_reason: Option<String>,
    pub owner_token: Option<String>,
    pub heartbeat_at: Option<NaiveDateTime>,
    pub canonical_json: Option<serde_json::Value>,
}

/// An execution opened by this worker, together with the token proving ownership.
#[derive(Debug, Clone)]
pub struct ExecutionLease {
    pub execution_id: String,
    pub job_id: String,
    pub attempt_number: i32,
    pub owner_token: String,
}
/// Begin the next attempt for a job.
///
/// Returns the new execution with a fresh owner token. The attempt number is
/// derived from the database (`MAX(attempt_number) + 1`, backed by the
/// `(job_id, attempt_number)` unique constraint) rather than from a counter in
/// memory, so two racing workers cannot both believe they are attempt 2: the
/// loser's insert violates the constraint and it recomputes.
pub async fn begin_execution(pool: &PgPool, job_id: &str) -> Result<ExecutionLease> {
    // A job may have at most one running execution. If one is already open this
    // is a duplicate worker, and it must not open a second attempt.
    if let Some((existing,)) = sqlx::query_as::<_, (String,)>(
        "SELECT id FROM audit_executions WHERE job_id=$1 AND status='running'",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?
    {
        return Err(AppError::Conflict(format!(
            "job {job_id} already has running execution {existing}"
        )));
    }

    let owner_token = generate_uuid();
    for _ in 0..5 {
        let (next,): (i32,) = sqlx::query_as(
            "SELECT COALESCE(MAX(attempt_number), 0) + 1 FROM audit_executions WHERE job_id=$1",
        )
        .bind(job_id)
        .fetch_one(pool)
        .await
        .map_err(AppError::Database)?;
        let execution_id = generate_uuid();
        let inserted = sqlx::query(
            "INSERT INTO audit_executions (id, job_id, attempt_number, status, owner_token,
                                           heartbeat_at, started_at)
             VALUES ($1,$2,$3,'running',$4,NOW(),NOW())",
        )
        .bind(&execution_id)
        .bind(job_id)
        .bind(next)
        .bind(&owner_token)
        .execute(pool)
        .await;
        match inserted {
            Ok(_) => {
                return Ok(ExecutionLease {
                    execution_id,
                    job_id: job_id.to_string(),
                    attempt_number: next,
                    owner_token,
                })
            }
            Err(sqlx::Error::Database(err)) if err.code().as_deref() == Some("23505") => {
                // Another worker took this attempt number between our read and
                // our write. Recompute and try the next one.
                continue;
            }
            Err(err) => return Err(AppError::Database(err)),
        }
    }
    Err(AppError::Internal(format!(
        "could not open an execution for job {job_id} after repeated conflicts"
    )))
}

/// Bind an execution to the snapshot it judges.
///
/// Immutable afterwards: a database trigger rejects rebinding an execution that
/// already carries a snapshot, so two trees can never be mixed inside one
/// execution.
pub async fn bind_snapshot(
    pool: &PgPool,
    execution_id: &str,
    owner_token: &str,
    commit_sha: &str,
) -> Result<()> {
    let updated =
        sqlx::query("UPDATE audit_executions SET commit_sha=$1 WHERE id=$2 AND owner_token=$3")
            .bind(commit_sha)
            .bind(execution_id)
            .bind(owner_token)
            .execute(pool)
            .await
            .map_err(AppError::Database)?
            .rows_affected();
    if updated != 1 {
        return Err(AppError::Conflict(format!(
            "execution {execution_id} is not owned by this worker"
        )));
    }
    Ok(())
}

/// Prove this worker still holds the execution.
///
/// Cheap liveness check used before expensive work. A worker that has lost the
/// token stops rather than finishing work it may no longer commit.
pub async fn holds_lease(pool: &PgPool, execution_id: &str, owner_token: &str) -> Result<bool> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM audit_executions WHERE id=$1 AND owner_token=$2 AND status='running'",
    )
    .bind(execution_id)
    .bind(owner_token)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(row.is_some())
}

/// Refresh the liveness timestamp the reaper reads.
///
/// Ownership is paired with an explicit heartbeat so the reaper does not
/// conclude a worker is dead merely because a wall-clock threshold elapsed
/// while that worker is demonstrably alive.
pub async fn heartbeat(pool: &PgPool, execution_id: &str, owner_token: &str) -> Result<bool> {
    let updated = sqlx::query(
        "UPDATE audit_executions SET heartbeat_at=NOW()
         WHERE id=$1 AND owner_token=$2 AND status='running'",
    )
    .bind(execution_id)
    .bind(owner_token)
    .execute(pool)
    .await
    .map_err(AppError::Database)?
    .rows_affected();
    Ok(updated == 1)
}

/// Close an execution whose owner stopped heartbeating.
///
/// Phase 12.1 reaper path. The caller proves abandonment by passing the
/// last-known heartbeat (or start) cutoff: the UPDATE only closes an
/// execution that is still `running` *and* older than the cutoff, so a live
/// worker that heartbeated concurrently is never reaped. Returns true when
/// this call closed the execution. The job is released back to `queued` only
/// when no live execution remains, so a retry opens a fresh attempt rather
/// than inheriting a dead one.
pub async fn reap_abandoned_execution(
    pool: &PgPool,
    execution_id: &str,
    stale_before: &chrono::NaiveDateTime,
    reason: &str,
) -> Result<bool> {
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    let row: Option<(String, chrono::NaiveDateTime)> = sqlx::query_as(
        "SELECT job_id, COALESCE(heartbeat_at, started_at) FROM audit_executions
          WHERE id=$1 AND status='running'
            AND COALESCE(heartbeat_at, started_at) < $2 FOR UPDATE",
    )
    .bind(execution_id)
    .bind(stale_before)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    let Some((job_id, _)) = row else {
        return Ok(false);
    };
    sqlx::query(
        "UPDATE audit_executions SET status='failed', finished_at=NOW(),
                failure_reason=$1, heartbeat_at=NOW()
          WHERE id=$2 AND status='running'",
    )
    .bind(reason)
    .bind(execution_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    // The dead attempt also consumed any pending cancellation request: it was
    // a request to *this* execution, and the next attempt must start clean.
    // Without this a job reaped once could never retry into success (G3).
    sqlx::query(
        "UPDATE audit_jobs SET cancel_requested=false, cancel_requested_at=NULL
          WHERE id=$1",
    )
    .bind(&job_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    let live: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_executions WHERE job_id=$1 AND status='running'",
    )
    .bind(&job_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    if live.0 == 0 {
        sqlx::query(
            "UPDATE audit_jobs SET status='queued'
              WHERE id=$1 AND status='running'",
        )
        .bind(&job_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;
    }
    tx.commit().await.map_err(AppError::Database)?;
    Ok(true)
}

/// Fail whatever execution is currently running for a job, if any.
///
/// Phase 12.1 worker fallback. `run_audit_job` only learns that the pipeline
/// failed *after* the fact (an `Err` return or a 30-minute timeout), at which
/// point it holds no lease. Writing `audit_jobs.status='failed'` directly —
/// as the old `mark_job_failed` did — would leave the still-`running`
/// execution open forever (findings under a failed job, attempt history with
/// no ending). This closes the running execution first, through the same
/// ownership/terminality rules as any other finalization, then moves the job
/// with it in the same transaction. If no execution is running (claim-time
/// failure before `begin_execution`), it falls back to a guarded job-only
/// write that still refuses to clobber a terminal audit.
pub async fn fail_running_execution(pool: &PgPool, job_id: &str, reason: &str) -> Result<()> {
    let running: Option<(String, String)> = sqlx::query_as(
        "SELECT id, owner_token FROM audit_executions WHERE job_id=$1 AND status='running'",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;
    if let Some((execution_id, owner_token)) = running {
        let lease = ExecutionLease {
            execution_id,
            job_id: job_id.to_string(),
            attempt_number: 0,
            owner_token,
        };
        // The lease was read from the row itself, so ownership holds; the
        // reaper cannot interleave here into a different owner because there
        // is only one running execution per job (partial unique index).
        return finalize_without_findings(pool, &lease, "failed", reason).await;
    }
    let _ = sqlx::query(
        "UPDATE audit_jobs SET status='failed', error_message=$1, finished_at=NOW()
          WHERE id=$2 AND status IN ('queued','running')",
    )
    .bind(reason)
    .bind(job_id)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(())
}

/// Reconstruct a finalized audit entirely from PostgreSQL.
///
/// Given a job, returns the latest execution with its scanner runs, findings,
/// canonical document, and score — everything the API needs without touching
/// in-memory orchestrator state. This is the Phase 12.1 exit-criterion read
/// path: if the production pipeline finalized through `finalize_execution`,
/// this rebuilds the same audit the pipeline committed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReconstructedAudit {
    pub execution_id: String,
    pub job_id: String,
    pub attempt_number: i32,
    pub status: String,
    pub commit_sha: Option<String>,
    pub failure_reason: Option<String>,
    pub scanner_runs: Vec<ScannerRunSummary>,
    pub finding_count: i64,
    pub canonical_json: Option<serde_json::Value>,
    pub security_score: Option<f64>,
}

/// One scanner row in the reconstructed audit.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScannerRunSummary {
    pub scanner: String,
    pub status: String,
    pub coverage_known: bool,
    pub finding_count: Option<i32>,
    pub limitations: Vec<String>,
}
/// Reconstruct the latest attempt of a job from persisted rows only.
pub async fn reconstruct_latest_audit(
    pool: &PgPool,
    job_id: &str,
) -> Result<Option<ReconstructedAudit>> {
    let exec: Option<AuditExecution> = sqlx::query_as(
        "SELECT * FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number DESC LIMIT 1",
    )
    .bind(job_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;
    let Some(exec) = exec else {
        return Ok(None);
    };
    let runs: Vec<(String, String, bool, Option<i32>, serde_json::Value)> = sqlx::query_as(
        "SELECT scanner, status, coverage_known, finding_count, limitations
           FROM audit_scanner_runs WHERE execution_id=$1 ORDER BY scanner",
    )
    .bind(&exec.id)
    .fetch_all(pool)
    .await
    .map_err(AppError::Database)?;
    let finding_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM findings WHERE execution_id=$1")
            .bind(&exec.id)
            .fetch_one(pool)
            .await
            .map_err(AppError::Database)?;
    let score: (Option<f64>,) = sqlx::query_as("SELECT security_score FROM audit_jobs WHERE id=$1")
        .bind(job_id)
        .fetch_one(pool)
        .await
        .map_err(AppError::Database)?;
    Ok(Some(ReconstructedAudit {
        execution_id: exec.id.clone(),
        job_id: exec.job_id.clone(),
        attempt_number: exec.attempt_number,
        status: exec.status.clone(),
        commit_sha: exec.commit_sha.clone(),
        failure_reason: exec.failure_reason.clone(),
        scanner_runs: runs
            .into_iter()
            .map(
                |(scanner, status, coverage_known, finding_count, limitations)| ScannerRunSummary {
                    scanner,
                    status,
                    coverage_known,
                    finding_count,
                    limitations: limitations
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                },
            )
            .collect(),
        finding_count: finding_count.0,
        canonical_json: exec.canonical_json.clone(),
        security_score: score.0,
    }))
}

/// The canonical audit of one execution plus the identity needed to present it.
///
/// This is the *only* read path a report is built from. It is returned only for
/// a terminal execution that carries a canonical document, so a report can never
/// be produced for a queued, running, or abandoned run, nor for one that never
/// reached a canonical result.
#[derive(Debug, Clone)]
pub struct ReportSource {
    pub audit: crate::schemas::canonical_audit::CanonicalAudit,
    pub execution_id: String,
    pub attempt_number: i32,
    pub execution_status: String,
}

/// A report as persisted, keyed by execution.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredReport {
    pub execution_id: String,
    pub job_id: String,
    pub attempt_number: i32,
    pub execution_status: String,
    pub report_schema_version: i32,
    pub canonical_schema_version: Option<i32>,
    pub markdown: Option<String>,
    pub html: Option<String>,
    pub json: Option<serde_json::Value>,
}

/// One `audit_reports` row, in the column order `load_stored_report` selects.
///
/// Named so the query stays readable: the tuple form made the shape opaque and
/// easy to transpose incorrectly when a column is added.
type StoredReportRow = (
    String,
    Option<String>,
    Option<String>,
    Option<serde_json::Value>,
    i32,
    Option<i32>,
);

/// Resolve an execution by explicit id, or the latest attempt when none is given.
async fn resolve_execution(
    pool: &PgPool,
    job_id: &str,
    execution_id: Option<&str>,
) -> Result<Option<AuditExecution>> {
    match execution_id {
        Some(id) => sqlx::query_as::<_, AuditExecution>(
            "SELECT * FROM audit_executions WHERE id=$1 AND job_id=$2",
        )
        .bind(id)
        .bind(job_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::Database),
        None => sqlx::query_as::<_, AuditExecution>(
            "SELECT * FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number DESC LIMIT 1",
        )
        .bind(job_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::Database),
    }
}

/// Reconstruct the canonical audit to report on, enforcing the terminal guard.
///
/// Refuses a `running` execution (queued/abandoned attempts never carry a
/// canonical document, so they surface as a missing-audit conflict), refuses an
/// execution with no canonical document, and refuses a canonical document whose
/// schema version this build does not understand.
pub async fn reconstruct_report_source(
    pool: &PgPool,
    job_id: &str,
    execution_id: Option<&str>,
) -> Result<Option<ReportSource>> {
    let Some(exec) = resolve_execution(pool, job_id, execution_id).await? else {
        return Ok(None);
    };
    if exec.status == "running" {
        return Err(AppError::Conflict(format!(
            "execution {} is still running and has no finalized report",
            exec.id
        )));
    }
    let Some(canonical) = exec.canonical_json.clone() else {
        return Err(AppError::Conflict(format!(
            "execution {} reached no canonical audit; there is nothing to report",
            exec.id
        )));
    };
    let audit: crate::schemas::canonical_audit::CanonicalAudit = serde_json::from_value(canonical)
        .map_err(|error| {
            AppError::Internal(format!(
                "persisted canonical audit for execution {} is unreadable: {error}",
                exec.id
            ))
        })?;
    if audit.schema_version != crate::schemas::canonical_audit::CANONICAL_AUDIT_VERSION {
        return Err(AppError::Conflict(format!(
            "execution {} carries canonical schema version {}, which this build does not support",
            exec.id, audit.schema_version
        )));
    }
    Ok(Some(ReportSource {
        audit,
        execution_id: exec.id,
        attempt_number: exec.attempt_number,
        execution_status: exec.status,
    }))
}

/// Load the report already persisted for an execution.
///
/// Returns `Ok(None)` when the execution exists and is terminal but has no
/// report row (e.g. a build that finalized without a report). A running
/// execution is refused outright.
pub async fn load_stored_report(
    pool: &PgPool,
    job_id: &str,
    execution_id: Option<&str>,
) -> Result<Option<StoredReport>> {
    let Some(exec) = resolve_execution(pool, job_id, execution_id).await? else {
        return Ok(None);
    };
    if exec.status == "running" {
        return Err(AppError::Conflict(format!(
            "execution {} is still running and has no finalized report",
            exec.id
        )));
    }
    let row: Option<StoredReportRow> = sqlx::query_as(
        "SELECT execution_id, markdown_content, html_content, report_json,
                report_schema_version, canonical_schema_version
           FROM audit_reports WHERE execution_id=$1",
    )
    .bind(&exec.id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(row.map(
        |(execution_id, markdown, html, json, report_schema_version, canonical_schema_version)| {
            StoredReport {
                execution_id,
                job_id: exec.job_id.clone(),
                attempt_number: exec.attempt_number,
                execution_status: exec.status.clone(),
                report_schema_version,
                canonical_schema_version,
                markdown,
                html,
                json,
            }
        },
    ))
}

/// Everything the terminal moment of an execution makes durable.
#[derive(Debug, Clone, Default)]
pub struct Finalization {
    pub findings: Vec<crate::schemas::audit_state::Finding>,
    pub scanner_runs: Vec<ScannerRunRecord>,
    pub coverage_status: String,
    pub coverage_complete: bool,
    pub coverage_limitations: Vec<String>,
    pub summary: Option<serde_json::Value>,
    pub canonical_json: Option<serde_json::Value>,
    pub report_markdown: Option<String>,
    pub report_json: Option<serde_json::Value>,
    pub report_html: Option<String>,
    pub security_score: Option<f64>,
    pub job_status: String,
    pub failure_reason: Option<String>,
}

/// One scanner's outcome, as persisted per execution.
#[derive(Debug, Clone)]
pub struct ScannerRunRecord {
    pub scanner: String,
    pub version: String,
    pub parser: String,
    pub mode: String,
    pub image: String,
    pub status: String,
    pub finding_count: Option<i32>,
    pub coverage_known: bool,
    pub detail: Option<String>,
    pub limitations: Vec<String>,
}

/// Commit an execution's entire final state in one transaction.
///
/// This is the single commit point. Findings, scanner runs, coverage, the
/// canonical document, the report row, the execution's terminal status, and the
/// job's status either all become visible together or none of them do. The
/// previously possible states — terminal status with findings missing, or
/// findings present under an audit that never finalized — are no longer
/// reachable by a crash, because there is no commit between them.
///
/// The execution row is locked `FOR UPDATE` first, so a stale worker that has
/// lost ownership is refused here rather than overwriting a newer execution.
#[allow(clippy::too_many_arguments)]
pub async fn finalize_execution(
    pool: &PgPool,
    lease: &ExecutionLease,
    finalization: &Finalization,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(AppError::Database)?;

    // Ownership + terminality, decided by the database under a row lock. Two
    // workers cannot finalize the same execution: the second blocks on the lock
    // and then finds the row already terminal.
    let current: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT status, owner_token FROM audit_executions WHERE id=$1 FOR UPDATE")
            .bind(&lease.execution_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;
    let Some((status, owner)) = current else {
        return Err(AppError::NotFound(format!(
            "audit execution {}",
            lease.execution_id
        )));
    };
    if owner.as_deref() != Some(lease.owner_token.as_str()) {
        return Err(AppError::Conflict(format!(
            "execution {} is owned by another worker; this one is stale",
            lease.execution_id
        )));
    }
    if status != "running" {
        return Err(AppError::Conflict(format!(
            "execution {} is already {status} and is immutable",
            lease.execution_id
        )));
    }

    // Cancellation is decided here, inside the transaction, not by whichever
    // writer happened to run last. If a cancellation was requested, it wins:
    // a cancelled execution never finalizes successfully.
    let cancelled: bool =
        sqlx::query_scalar("SELECT cancel_requested FROM audit_jobs WHERE id=$1 FOR UPDATE")
            .bind(&lease.job_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::Database)?;
    // The request is a statement about *this* execution, so it is cleared in the
    // same transaction that acts on it. Leaving it set would let one
    // cancellation poison every later attempt: the job could never be retried
    // into a successful audit.
    if cancelled {
        sqlx::query(
            "UPDATE audit_jobs SET cancel_requested=false, cancel_requested_at=NULL WHERE id=$1",
        )
        .bind(&lease.job_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;
    }
    let (final_status, score) = if cancelled && finalization.job_status != "cancelled" {
        ("cancelled".to_string(), None)
    } else {
        (finalization.job_status.clone(), finalization.security_score)
    };
    // A score may only be stored by an execution that actually completed with
    // complete coverage. Incomplete coverage keeps it null.
    let score = if finalization.coverage_complete && final_status == "completed" {
        score
    } else {
        None
    };

    // Findings: replace this execution's set, and only ever this execution's.
    let ids: Vec<String> = finalization
        .findings
        .iter()
        .map(|finding| finding.id.clone())
        .collect();
    for finding in &finalization.findings {
        sqlx::query(
            "INSERT INTO findings (id, job_id, execution_id, agent_source, title, description,
                                   severity, evidence, remediation, cwe_id, owasp_category,
                                   confidence, scanner_name, scanner_mode, file_path,
                                   line_number, metadata_json, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,CAST($17 AS JSONB),NOW())
             ON CONFLICT (id) DO UPDATE SET
                execution_id=EXCLUDED.execution_id,
                title=EXCLUDED.title,
                description=EXCLUDED.description,
                severity=EXCLUDED.severity,
                evidence=EXCLUDED.evidence,
                metadata_json=EXCLUDED.metadata_json",
        )
        .bind(&finding.id)
        .bind(&lease.job_id)
        .bind(&lease.execution_id)
        .bind(&finding.agent_source)
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(finding.severity.as_str())
        .bind(finding.evidence.as_deref())
        .bind(finding.remediation.as_deref())
        .bind(finding.cwe_id.as_deref())
        .bind(finding.owasp_category.as_deref())
        .bind(finding.confidence.as_deref())
        .bind(finding.scanner_name.as_deref())
        .bind(finding.scanner_mode.as_deref())
        .bind(finding.file_path.as_deref())
        .bind(finding.line_number)
        .bind(finding.metadata_json.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;
    }
    // Drop findings this execution produced earlier but no longer reports.
    // Scoped to this execution: another attempt's findings are never touched.
    sqlx::query(
        "DELETE FROM findings WHERE execution_id=$1 AND NOT (id = ANY(CAST($2 AS TEXT[])))",
    )
    .bind(&lease.execution_id)
    .bind(&ids)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    for run in &finalization.scanner_runs {
        sqlx::query(
            "INSERT INTO audit_scanner_runs (id, execution_id, scanner, version, parser, mode,
                                            image, status, finding_count, coverage_known,
                                            detail, limitations)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CAST($12 AS JSONB))
             ON CONFLICT (execution_id, scanner) DO UPDATE SET
                status=EXCLUDED.status,
                finding_count=EXCLUDED.finding_count,
                coverage_known=EXCLUDED.coverage_known,
                detail=EXCLUDED.detail,
                limitations=EXCLUDED.limitations",
        )
        .bind(crate::utils::generate_uuid())
        .bind(&lease.execution_id)
        .bind(&run.scanner)
        .bind(&run.version)
        .bind(&run.parser)
        .bind(&run.mode)
        .bind(&run.image)
        .bind(&run.status)
        .bind(run.finding_count)
        .bind(run.coverage_known)
        .bind(run.detail.as_deref())
        .bind(serde_json::to_string(&run.limitations).unwrap_or_else(|_| "[]".into()))
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;
    }

    // The report row is keyed by the *execution*, not the job. A retry opens a
    // new execution and writes its own report; it can never overwrite the report
    // of an earlier attempt. The versions are extracted from the stored model so
    // a reader can refuse a document it does not understand.
    if let Some(markdown) = &finalization.report_markdown {
        let report_schema_version = finalization
            .report_json
            .as_ref()
            .and_then(|value| value.get("report_schema_version"))
            .and_then(|value| value.as_i64())
            .unwrap_or(1) as i32;
        let canonical_schema_version = finalization
            .report_json
            .as_ref()
            .and_then(|value| value.get("identity"))
            .and_then(|value| value.get("canonical_schema_version"))
            .and_then(|value| value.as_i64())
            .map(|value| value as i32);
        sqlx::query(
            "INSERT INTO audit_reports
                (id, job_id, execution_id, markdown_content, html_content, report_json,
                 report_schema_version, canonical_schema_version, created_at)
             VALUES ($1,$2,$3,$4,$5,CAST($6 AS JSONB),$7,$8,NOW())
             ON CONFLICT (execution_id) WHERE execution_id IS NOT NULL DO UPDATE SET
                markdown_content=EXCLUDED.markdown_content,
                html_content=EXCLUDED.html_content,
                report_json=EXCLUDED.report_json,
                report_schema_version=EXCLUDED.report_schema_version,
                canonical_schema_version=EXCLUDED.canonical_schema_version",
        )
        .bind(crate::utils::generate_uuid())
        .bind(&lease.job_id)
        .bind(&lease.execution_id)
        .bind(markdown)
        .bind(finalization.report_html.as_deref())
        .bind(
            finalization
                .report_json
                .as_ref()
                .map(|value| value.to_string()),
        )
        .bind(report_schema_version)
        .bind(canonical_schema_version)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;
    }

    // The execution's own terminal row. This is the last write before commit,
    // so the trigger that freezes terminal executions cannot block it: the
    // `running` -> terminal transition is exactly what is permitted.
    sqlx::query(
        "UPDATE audit_executions
            SET status=$1, finished_at=NOW(), failure_reason=$2, canonical_json=CAST($3 AS JSONB),
                heartbeat_at=NOW()
          WHERE id=$4 AND owner_token=$5 AND status='running'",
    )
    .bind(&final_status)
    .bind(finalization.failure_reason.as_deref())
    .bind(
        finalization
            .canonical_json
            .as_ref()
            .map(|value| value.to_string()),
    )
    .bind(&lease.execution_id)
    .bind(&lease.owner_token)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    // The job's status moves with it, in the same commit, so an audit is never
    // terminal in one table and unfinished in another.
    //
    // The guard excludes the *previous attempt's* terminal status rather than
    // every terminal status: a retry legitimately reopens a job that a failed or
    // cancelled attempt left behind. What it still refuses is clobbering a job
    // some *other* execution already finalized — the stale-worker case, which is
    // decided by the ownership check above instead.
    sqlx::query(
        "UPDATE audit_jobs
            SET status=$1, finished_at=NOW(), security_score=$2, error_message=$3
          WHERE id=$4 AND status IN ('queued','running','failed','cancelled','partial','engine_unavailable')",
    )
    .bind(&final_status)
    .bind(score)
    .bind(finalization.failure_reason.as_deref())
    .bind(&lease.job_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    tx.commit().await.map_err(AppError::Database)?;
    Ok(())
}

/// Finalize an execution that ended without a result (failure, cancellation,
/// or a crash the reaper recovered).
///
/// It deliberately commits **no findings**: an execution that never produced a
/// trustworthy result must not leave evidence behind that a reader could
/// mistake for a finding set. Its purpose is to close the attempt with an
/// honest status and reason, so the attempt history is reconstructable.
pub async fn finalize_without_findings(
    pool: &PgPool,
    lease: &ExecutionLease,
    status: &str,
    reason: &str,
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(AppError::Database)?;
    let current: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT status, owner_token FROM audit_executions WHERE id=$1 FOR UPDATE")
            .bind(&lease.execution_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;
    let Some((current_status, owner)) = current else {
        return Err(AppError::NotFound(format!(
            "audit execution {}",
            lease.execution_id
        )));
    };
    if owner.as_deref() != Some(lease.owner_token.as_str()) {
        return Err(AppError::Conflict(format!(
            "execution {} is owned by another worker; this one is stale",
            lease.execution_id
        )));
    }
    if current_status != "running" {
        return Err(AppError::Conflict(format!(
            "execution {} is already {current_status} and is immutable",
            lease.execution_id
        )));
    }
    sqlx::query(
        "UPDATE audit_executions
            SET status=$1, finished_at=NOW(), failure_reason=$2, heartbeat_at=NOW()
          WHERE id=$3 AND owner_token=$4 AND status='running'",
    )
    .bind(status)
    .bind(reason)
    .bind(&lease.execution_id)
    .bind(&lease.owner_token)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    sqlx::query(
        "UPDATE audit_jobs SET status=$1, finished_at=NOW(), security_score=NULL, error_message=$2
          WHERE id=$3 AND status IN ('queued','running','failed','cancelled','partial','engine_unavailable')",
    )
    .bind(status)
    .bind(reason)
    .bind(&lease.job_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    // The request describes *this* execution and is consumed by whichever
    // finalization observes it. Also cleared here (not only in
    // `finalize_execution`) so a cancelled-then-retried job starts its next
    // attempt clean (G3): without this a single cancellation poisons every
    // future retry back into `cancelled`.
    sqlx::query(
        "UPDATE audit_jobs SET cancel_requested=false, cancel_requested_at=NULL WHERE id=$1",
    )
    .bind(&lease.job_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;
    tx.commit().await.map_err(AppError::Database)?;
    Ok(())
}

/// Persist a validated AI narrative for a finalized execution.
///
/// The narrative's job is *defined* by its execution, so only the execution id
/// is written: lineage is a foreign-key chain, not a value a caller can get
/// wrong. A duplicate insert fails on the unique index rather than silently
/// doing nothing -- a second narrative for one execution is a bug, and a
/// swallowed write would hide it.
///
/// The preconditions are re-proved here rather than trusted from the caller:
/// this execution must have a finalized deterministic report, and the narrative
/// must validate against *that* report. Otherwise a narrative validated against
/// attempt 1 could be persisted onto attempt 2 and read back as if it explained
/// it. `validate_narrative` is the Phase 14 validator, reused as-is; the
/// database trigger enforces report existence independently, so this is the
/// semantic half of one invariant, not a second source of truth.
pub async fn persist_ai_narrative(
    pool: &PgPool,
    execution_id: &str,
    narrative: &ReportNarrative,
) -> Result<()> {
    let job_id: Option<String> =
        sqlx::query_scalar("SELECT job_id FROM audit_executions WHERE id=$1")
            .bind(execution_id)
            .fetch_optional(pool)
            .await
            .map_err(AppError::Database)?;
    let Some(job_id) = job_id else {
        return Err(AppError::NotFound(format!(
            "execution {execution_id} does not exist"
        )));
    };
    // Refuses a `running` execution and an execution with no canonical document.
    let source = reconstruct_report_source(pool, &job_id, Some(execution_id))
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "execution {execution_id} has no finalized deterministic report"
            ))
        })?;
    let report = crate::schemas::report::build_report(
        &source.audit,
        &crate::schemas::report::ExecutionIdentity {
            execution_id: source.execution_id.clone(),
            attempt_number: source.attempt_number,
        },
    )
    .map_err(|error| AppError::Internal(error.to_string()))?;
    crate::schemas::ai_narrative::validate_narrative(&report, narrative).map_err(|violation| {
        AppError::Internal(format!(
            "refusing to persist an AI narrative for execution {execution_id}: {violation}"
        ))
    })?;

    let narrative_json = serde_json::to_value(narrative).map_err(|error| {
        AppError::Internal(format!("failed to serialize AI narrative: {error}"))
    })?;
    sqlx::query(
        "INSERT INTO ai_narratives (id, execution_id, narrative_json, narrative_schema_version, created_at)
         VALUES ($1, $2, CAST($3 AS JSONB), $4, NOW())",
    )
    .bind(generate_uuid())
    .bind(execution_id)
    .bind(narrative_json.to_string())
    // Mirrored from the document itself, so the column can never claim a
    // version the payload does not carry.
    .bind(narrative.narrative_schema_version as i32)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(())
}

/// Load the persisted AI narrative for an execution.
///
/// `execution_id = None` resolves the job's latest execution, exactly like
/// report retrieval; there is no fallback to an earlier attempt.
pub async fn load_ai_narrative(
    pool: &PgPool,
    job_id: &str,
    execution_id: Option<&str>,
) -> Result<Option<StoredAiNarrative>> {
    let exec = resolve_execution(pool, job_id, execution_id).await?;
    let Some(exec) = exec else {
        return Ok(None);
    };
    if exec.status == "running" {
        return Err(AppError::Conflict(format!(
            "execution {} is still running and has no finalized narrative",
            exec.id
        )));
    }
    let row: Option<(serde_json::Value, i32)> = sqlx::query_as(
        "SELECT narrative_json, narrative_schema_version
         FROM ai_narratives WHERE execution_id=$1",
    )
    .bind(&exec.id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;
    match row {
        Some((narrative_json, schema_version)) => {
            if schema_version != crate::schemas::ai_narrative::AI_NARRATIVE_SCHEMA_VERSION as i32 {
                return Err(AppError::Internal(format!(
                    "persisted AI narrative for execution {} has unsupported schema version {}",
                    exec.id, schema_version
                )));
            }
            let narrative: ReportNarrative =
                serde_json::from_value(narrative_json).map_err(|error| {
                    AppError::Internal(format!(
                        "persisted AI narrative for execution {} is unreadable: {error}",
                        exec.id
                    ))
                })?;
            Ok(Some(StoredAiNarrative {
                job_id: exec.job_id,
                execution_id: exec.id,
                attempt_number: exec.attempt_number,
                narrative_schema_version: schema_version,
                narrative,
            }))
        }
        None => Ok(None),
    }
}
