//! AI narrative orchestration (Phase 15B).
//!
//! Everything here is about *which* audit gets explained and *where* the result
//! is stored. The model boundary itself lives in [`crate::services::narrative`]
//! and knows nothing about this module. Keeping the split is what makes the
//! ordering property enforceable rather than aspirational:
//!
//! ```text
//! finalized execution -> deterministic report -> AI explanation
//! ```
//!
//! The audit is already committed before this module is reached. Generation runs
//! afterwards, in its own transaction, so an AI failure cannot leave a
//! half-finished audit behind: there is nothing to roll back, because nothing
//! deterministic was open.
//!
//! Execution identity is a required parameter, never an `Option`. There is no
//! code path here that can resolve "the latest execution", so it is impossible
//! to explain attempt N with attempt N+1's report by omission.

use crate::error::{AppError, Result};
use crate::orchestrator::execution::{
    load_ai_narrative, persist_ai_narrative, reconstruct_report_source, StoredAiNarrative,
};
use crate::schemas::report::{build_report, CanonicalAuditReport, ExecutionIdentity};
use crate::services::narrative::{failure_category, generate_narrative, ModelConfig};
use sqlx::PgPool;
use std::future::Future;
use std::time::Instant;

/// Load the finalized deterministic report for exactly this execution.
///
/// Distinct from [`reconstruct_report_source`] in one respect: a missing report
/// is an error here, not `None`. Generation is an explicit request about a named
/// execution, so "no report" must stop the pipeline before the model is called
/// rather than degrade into an explanation of nothing.
async fn deterministic_report(
    pool: &PgPool,
    job_id: &str,
    execution_id: &str,
) -> Result<CanonicalAuditReport> {
    // Resolving through the job is what proves the execution belongs to the
    // caller's job; an execution from another job does not resolve.
    let source = reconstruct_report_source(pool, job_id, Some(execution_id))
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "execution {execution_id} has no finalized deterministic report"
            ))
        })?;
    build_report(
        &source.audit,
        &ExecutionIdentity {
            execution_id: source.execution_id,
            attempt_number: source.attempt_number,
        },
    )
    .map_err(|error| AppError::Internal(error.to_string()))
}

/// Explain one execution, or return the narrative it already has.
///
/// Idempotent by design. Phase 15A made a duplicate insert fail, and a narrative
/// is a final record of one explanation, so an existing narrative is returned
/// as-is rather than regenerated or overwritten. There is deliberately no
/// regeneration path: none is required by any existing contract, and adding one
/// would mean a second way for a finalized audit's prose to change.
///
/// `completion` is the model transport; see [`crate::services::narrative`].
pub async fn ensure_ai_narrative<F, Fut>(
    pool: &PgPool,
    job_id: &str,
    execution_id: &str,
    model_config: &ModelConfig,
    completion: F,
) -> Result<StoredAiNarrative>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    let report = deterministic_report(pool, job_id, execution_id).await?;

    if let Some(existing) = load_ai_narrative(pool, job_id, Some(execution_id)).await? {
        return Ok(existing);
    }

    let started = Instant::now();
    let outcome = generate_narrative(&report, model_config, completion).await;
    let elapsed = started.elapsed();

    // Metadata only: no prompt, no response, no narrative content, no evidence.
    // Enough to diagnose an AI failure without retaining anything sensitive.
    match outcome {
        Ok(narrative) => {
            tracing::info!(
                execution_id,
                attempt_number = report.identity.attempt_number,
                provider = model_config.provider,
                model = %model_config.model,
                duration_ms = elapsed.as_millis() as u64,
                outcome = "generated",
                "AI narrative validated"
            );
            // Phase 15A re-proves the narrative against this execution's report.
            // Kept deliberately: generation validated against the in-memory
            // report, persistence re-validates against what was committed. Two
            // boundaries, two checks.
            if let Err(error) = persist_ai_narrative(pool, execution_id, &narrative).await {
                // Two requests for one execution can both pass the "does a
                // narrative exist" check above and both reach here. The unique
                // index is the arbiter: the loser's insert fails, and the winner's
                // narrative is returned rather than overwritten. Taking a
                // database lock instead would mean holding a transaction across
                // the provider call, which this design deliberately avoids.
                if !is_duplicate_narrative(&error) {
                    return Err(error);
                }
                tracing::info!(
                    execution_id,
                    outcome = "raced",
                    "a concurrent request persisted this execution's narrative first"
                );
            }
            load_ai_narrative(pool, job_id, Some(execution_id))
                .await?
                .ok_or_else(|| {
                    AppError::Internal(format!(
                        "narrative for execution {execution_id} vanished after it was persisted"
                    ))
                })
        }
        Err(error) => {
            let category = failure_category(&error);
            tracing::warn!(
                execution_id,
                attempt_number = report.identity.attempt_number,
                provider = model_config.provider,
                model = %model_config.model,
                duration_ms = elapsed.as_millis() as u64,
                outcome = "rejected",
                failure_category = category,
                "AI narrative generation failed; deterministic audit is unaffected"
            );
            // The deterministic audit, report, findings, coverage, score, and
            // execution are all untouched: nothing was opened for writing and
            // nothing was written.
            Err(error)
        }
    }
}

/// Whether this failure is the unique-index refusing a second narrative.
///
/// PostgreSQL `unique_violation`. Narrow on purpose: any other persistence
/// failure is a real error and must not be mistaken for a benign race, because
/// swallowing it would report success for a narrative that was never stored.
fn is_duplicate_narrative(error: &AppError) -> bool {
    matches!(
        error,
        AppError::Database(sqlx::Error::Database(db))
            if db.code().as_deref() == Some("23505")
    )
}
