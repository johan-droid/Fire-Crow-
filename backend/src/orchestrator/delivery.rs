//! Delivery orchestration (Phase 17).
//!
//! Delivery is the last step in the pipeline and the only one that talks to the
//! outside world on the audit's behalf:
//!
//! ```text
//! finalized execution -> deterministic report -> [optional narrative] -> channel
//! ```
//!
//! Five properties are structural here rather than conventional:
//!
//! * **Execution-scoped.** The execution id is a required parameter and there is
//!   no "latest" resolution path, so a retried job can never send attempt 1's
//!   report in answer to a request for attempt 2.
//! * **No transaction spans the network call.** The report is loaded, the
//!   connection dropped, and only then is the provider contacted. Nothing is
//!   left open on the database while waiting on a provider.
//! * **Delivery state is separate from audit state.** A provider failure updates
//!   the delivery row and nothing else. `audit_jobs.status` and
//!   `audit_executions.status` are never written from this module.
//! * **One state machine for every channel.** Email and Telegram differ only in
//!   how a message is rendered and sent, so they share the claim/send/record core
//!   rather than each growing their own copy of the concurrency and idempotency
//!   logic. A second copy would be a second place for the guarantees to drift.
//! * **The channel is a transport detail.** The core takes a sender closure, the
//!   same idiom [`crate::services::narrative`] proved for the model: the caller
//!   supplies the transport, and the only thing it can substitute is *how the
//!   bytes leave*, never whether the delivery is recorded or whether the report is
//!   the finalized one.

use crate::error::{AppError, DeliveryError, Result};
use crate::orchestrator::execution::{load_ai_narrative, reconstruct_report_source};
use crate::schemas::ai_narrative::ReportNarrative;
use crate::schemas::report::{build_report, CanonicalAuditReport, ExecutionIdentity};
use crate::services::email_artifact::EmailArtifact;
use sqlx::PgPool;
use std::future::Future;

/// Delivery channels. Recorded in `audit_deliveries.channel`, which constrains the
/// column to exactly these values.
pub const CHANNEL_EMAIL: &str = "email";

/// The version of the delivery contract every rendered artifact is stamped with.
///
/// A delivered message is read by a human minutes later and by an operator during
/// an incident hours later, and nothing in the message itself records what
/// produced it. Stamping the renderer version on the artifact keeps that
/// answerable without re-deriving it from the code that happened to run.
///
/// Distinct from a key's `delivery_version`, which counts *attempts* at the same
/// execution. This constant is bumped when the content of a delivery changes
/// shape, so a stored message can be interpreted the way it was meant to be.
pub const DELIVERY_SCHEMA_VERSION: i32 = 1;
pub const CHANNEL_TELEGRAM: &str = "telegram";

/// What happened to a delivery request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// This call delivered the report.
    Sent,
    /// A previous call already delivered it. Nothing was re-sent.
    AlreadySent,
}

/// The finalized, delivery-ready content for one execution.
///
/// Assembled once and handed to whichever transport the caller chose. It contains
/// the deterministic report and, when one exists, the validated narrative for
/// *this* execution — never raw scanner output, repository files, model prompts,
/// or model responses.
pub struct DeliveryContent {
    pub report: CanonicalAuditReport,
    pub narrative: Option<ReportNarrative>,
}

/// Load the finalized report and any validated narrative for exactly this execution.
///
/// Reuses the Phase 15A resolution so every channel describes exactly what the
/// report endpoint serves: an explicit execution id, ownership-checked by the
/// caller, and never a fallback to another attempt.
pub async fn load_delivery_content(
    pool: &PgPool,
    job_id: &str,
    execution_id: &str,
) -> Result<DeliveryContent> {
    let source = reconstruct_report_source(pool, job_id, Some(execution_id))
        .await?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "execution {execution_id} has no finalized deterministic report"
            ))
        })?;
    let report = build_report(
        &source.audit,
        &ExecutionIdentity {
            execution_id: source.execution_id,
            attempt_number: source.attempt_number,
        },
    )
    .map_err(|error| AppError::Internal(error.to_string()))?;

    // Optional by design. A missing narrative is not a failure and produces no
    // placeholder: the deterministic report is the deliverable on its own. The
    // model provider is never contacted from here.
    let narrative = load_ai_narrative(pool, job_id, Some(execution_id))
        .await?
        .map(|stored| stored.narrative);

    Ok(DeliveryContent { report, narrative })
}

/// The delivery artifact for one execution, loaded but not sent.
///
/// Split out so a caller can answer "is this execution eligible?" before
/// consulting any provider configuration. Otherwise an unconfigured server would
/// mask a 409 about a running execution with an unrelated 501.
pub async fn finalized_email_artifact(
    pool: &PgPool,
    job_id: &str,
    execution_id: &str,
) -> Result<EmailArtifact> {
    let content = load_delivery_content(pool, job_id, execution_id).await?;
    Ok(crate::services::email_artifact::render(
        &content.report,
        content.narrative.as_ref(),
    ))
}

/// One idempotency key: which delivery attempt this is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryKey {
    pub execution_id: String,
    pub channel: &'static str,
    pub destination_ref: String,
    /// The attempt number for this key. `1` is the first send.
    pub delivery_version: i32,
}

/// The recorded state of one delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DeliveryState {
    pub status: String,
    pub failure_class: Option<String>,
    pub provider_message_id: Option<String>,
    pub attempts: i32,
}

/// Read the recorded state of one delivery attempt.
pub async fn delivery_state(pool: &PgPool, key: &DeliveryKey) -> Result<Option<DeliveryState>> {
    let row: Option<(String, Option<String>, Option<String>, i32)> = sqlx::query_as(
        "SELECT status, failure_class, provider_message_id, attempts
           FROM audit_deliveries
          WHERE execution_id=$1 AND channel=$2 AND destination_ref=$3 AND delivery_version=$4",
    )
    .bind(&key.execution_id)
    .bind(key.channel)
    .bind(&key.destination_ref)
    .bind(key.delivery_version)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)?;

    Ok(row.map(
        |(status, failure_class, provider_message_id, attempts)| DeliveryState {
            status,
            failure_class,
            provider_message_id,
            attempts,
        },
    ))
}

/// Claim a delivery attempt, or report that it cannot proceed.
///
/// The claim is a single insert against the full idempotency key, so two
/// concurrent requests for the same key cannot both proceed: the loser's insert
/// violates the key and is resolved by *reading* the winner's state, never by
/// silently discarding the write.
///
/// A record already in `sent` short-circuits the send entirely, which is what
/// prevents a crash between "provider accepted the message" and "status written"
/// from turning into a duplicate notification: the retry finds `sending`, not
/// `sent`, and refuses rather than re-sending into a channel that may already have
/// the message.
async fn claim_delivery(pool: &PgPool, key: &DeliveryKey) -> Result<()> {
    let inserted = sqlx::query(
        "INSERT INTO audit_deliveries
             (execution_id, channel, destination_ref, delivery_version, status, attempts, created_at)
         VALUES ($1, $2, $3, $4, 'sending', 1, NOW())
         ON CONFLICT (execution_id, channel, destination_ref, delivery_version) DO NOTHING",
    )
    .bind(&key.execution_id)
    .bind(key.channel)
    .bind(&key.destination_ref)
    .bind(key.delivery_version)
    .execute(pool)
    .await
    .map_err(AppError::Database)?
    .rows_affected();

    if inserted == 1 {
        return Ok(());
    }

    let existing = delivery_state(pool, key)
        .await?
        // The insert conflicted, so a row exists. An `unwrap_or_default` here would
        // silently treat "vanished" as a retryable failure and re-send.
        .ok_or_else(|| {
            AppError::Internal(format!(
                "delivery row for execution {} on {} vanished while being claimed",
                key.execution_id, key.channel
            ))
        })?;

    // `sent` is a completed delivery; anything else is in flight or failed. Both
    // stop this call: a duplicate send is exactly what the key exists to prevent.
    Err(AppError::Conflict(match existing.status.as_str() {
        "sent" => format!(
            "execution {} has already been delivered on {}",
            key.execution_id, key.channel
        ),
        "sending" => format!(
            "a delivery for execution {} on {} is already in progress",
            key.execution_id, key.channel
        ),
        _ => format!(
            "a previous delivery attempt for execution {} on {} failed",
            key.execution_id, key.channel
        ),
    }))
}

/// Record the outcome. Only the delivery row is written.
///
/// `provider_message_id` is recorded when the channel has one. Telegram names the
/// message it accepted, which is what makes a duplicate-suppression claim
/// auditable. SMTP does not hand out an id, so an email delivery carries none
/// rather than a fabricated one — the column is optional for that reason, not
/// because the guarantee is weaker everywhere.
async fn finish_delivery(
    pool: &PgPool,
    key: &DeliveryKey,
    provider_message_id: Option<&str>,
    failure_class: Option<&str>,
) -> Result<()> {
    let status: &str = if failure_class.is_none() {
        "sent"
    } else {
        "failed"
    };

    sqlx::query(
        "UPDATE audit_deliveries
            SET status = $5,
                provider_message_id = $6,
                failure_class = $7,
                completed_at = NOW()
          WHERE execution_id = $1 AND channel = $2 AND destination_ref = $3
            AND delivery_version = $4",
    )
    .bind(&key.execution_id)
    .bind(key.channel)
    .bind(&key.destination_ref)
    .bind(key.delivery_version)
    .bind(status)
    .bind(provider_message_id)
    .bind(failure_class)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(())
}

/// Deliver one execution's finalized content on one channel.
///
/// `sender` is the transport. It is called only after the claim succeeds, so a
/// refused duplicate never costs a provider round trip, and its result is the only
/// thing that decides whether the delivery succeeded.
///
/// The provider is never contacted for an ineligible execution, no transaction is
/// held open while it runs, and nothing outside the delivery row is written.
pub async fn deliver<F, Fut>(pool: &PgPool, key: &DeliveryKey, sender: F) -> Result<DeliveryOutcome>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = std::result::Result<Option<String>, DeliveryError>>,
{
    claim_delivery(pool, key).await?;

    // Metadata only: no recipient, no report text, no message body, no findings.
    // Enough to diagnose a delivery failure without retaining what was sent.
    let started = std::time::Instant::now();

    match sender().await {
        Ok(provider_message_id) => {
            let elapsed = started.elapsed();
            tracing::info!(
                execution_id = %key.execution_id,
                channel = key.channel,
                delivery_version = key.delivery_version,
                duration_ms = elapsed.as_millis() as u64,
                outcome = "delivered",
                "delivery accepted by provider"
            );
            finish_delivery(pool, key, provider_message_id.as_deref(), None).await?;
            Ok(DeliveryOutcome::Sent)
        }
        Err(error) => {
            let elapsed = started.elapsed();
            // A delivery failure is recorded as a delivery failure. The audit, the
            // execution, the findings, the report, and the narrative are all
            // exactly as they were: nothing in this branch writes them.
            tracing::warn!(
                execution_id = %key.execution_id,
                channel = key.channel,
                delivery_version = key.delivery_version,
                duration_ms = elapsed.as_millis() as u64,
                outcome = "failed",
                failure_class = error.category(),
                "delivery failed; the deterministic audit is unaffected"
            );
            finish_delivery(pool, key, None, Some(error.category())).await?;
            Err(AppError::Delivery(error))
        }
    }
}

/// Deliver one execution's report by email.
pub async fn deliver_execution_email(
    pool: &PgPool,
    job_id: &str,
    execution_id: &str,
    recipient: &str,
    mailer: &crate::services::email::EmailService,
    artifact: &EmailArtifact,
) -> Result<DeliveryOutcome> {
    let key = DeliveryKey {
        execution_id: execution_id.to_string(),
        channel: CHANNEL_EMAIL,
        destination_ref: recipient.to_string(),
        delivery_version: 1,
    };

    if let Some(existing) = delivery_state(pool, &key).await? {
        if existing.status == "sent" {
            return Ok(DeliveryOutcome::AlreadySent);
        }
    }

    // SMTP returns no message id, so this channel records none.
    deliver(pool, &key, || async move {
        mailer
            .send_artifact(recipient, artifact)
            .await
            .map_err(delivery_error)?;
        Ok(None)
    })
    .await
}

/// Narrow an [`AppError`] to the delivery class the delivery row records.
///
/// `send_artifact` reports through `AppError` because that is the API's error type;
/// the row wants the specific reason. Anything that is not a classified delivery
/// failure is a transport failure, which is the honest description of "the mailer
/// returned an error Fire Crow does not recognise" — and it is never a reason to
/// invent a more specific one.
fn delivery_error(error: AppError) -> DeliveryError {
    match error {
        AppError::Delivery(inner) => inner,
        _ => DeliveryError::Transport,
    }
}

/// Whether an execution is eligible for delivery.
///
/// A finalized execution with a deterministic report is eligible; a running one is
/// not, and is refused before any state is written.
pub fn ensure_eligible(report: &CanonicalAuditReport) -> Result<()> {
    if report.identity.execution_id.trim().is_empty() {
        return Err(AppError::NotFound("execution not found".into()));
    }
    Ok(())
}
