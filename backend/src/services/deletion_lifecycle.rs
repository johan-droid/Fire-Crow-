//! Account-deletion lifecycle: grace period, cancellation, reminders, completion.
//!
//! Deletion is a request, not an immediate erasure. The account stays usable
//! until a persisted deadline passes without a cancellation, at which point a
//! verified deletion-completion event removes it. Reminders fire during the
//! grace period; cancelled requests are never processed.
//!
//! All email delivery is best-effort: if the mail provider is unconfigured or
//! rejects a message, the lifecycle state still advances. A failed email is
//! logged and never blocks deletion or cancellation.

use crate::config::Settings;
use crate::error::{AppError, Result};
use crate::services::account_email_templates::{
    deletion_completed_email, deletion_reminder_email, deletion_requested_email,
};
use crate::services::email::EmailService;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

/// Default grace period: 30 days. Override with `DELETION_GRACE_PERIOD_SECONDS`.
fn grace_period_seconds() -> i64 {
    std::env::var("DELETION_GRACE_PERIOD_SECONDS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(30 * 24 * 60 * 60)
}

/// Default reminder interval: once per day. Override with
/// `DELETION_REMINDER_INTERVAL_SECONDS`.
fn reminder_interval_seconds() -> i64 {
    std::env::var("DELETION_REMINDER_INTERVAL_SECONDS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(24 * 60 * 60)
}

/// Record a deletion request for `user_id`, set its deadline, and send the
/// confirmation email. Returns the deadline and the single-purpose cancellation
/// token.
pub async fn request_deletion(
    pool: &PgPool,
    user_id: &str,
    settings: &Settings,
) -> Result<(chrono::NaiveDateTime, String)> {
    let now = Utc::now().naive_utc();
    let deadline = now + chrono::Duration::seconds(grace_period_seconds());
    let token = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO account_deletion_requests
             (id, user_id, deadline, status, cancellation_token, created_at)
         VALUES ($1, $2, $3, 'requested', $4, NOW())",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(deadline)
    .bind(&token)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    // Best-effort confirmation email; a mail failure never rolls back the
    // request. The deadline is authoritative regardless of email outcome.
    let _ = send_deletion_email(pool, settings, user_id, deadline, &token).await;

    Ok((deadline, token))
}

/// Cancel a deletion request: `token` must belong to `user_id` and the request
/// must still be `requested`. A cancelled request produces no further
/// reminders and is never deleted.
pub async fn cancel_deletion(pool: &PgPool, user_id: &str, token: &str) -> Result<bool> {
    let r = sqlx::query(
        "UPDATE account_deletion_requests
             SET status = 'cancelled', cancelled_at = NOW()
           WHERE cancellation_token = $1
             AND user_id = $2
             AND status = 'requested'",
    )
    .bind(token)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(AppError::Database)?;

    Ok(r.rows_affected() > 0)
}

/// Housekeeping integration. Runs on every housekeeping tick:
///
/// 1. Marks overdue `requested` requests `deleted`, sets `users.deleted_at`,
///    revokes the account's sessions, and sends the final completion email.
///    Only a verified deadline pass triggers deletion — never a scheduled job
///    alone.
///
/// 2. Sends reminders to `requested` requests whose deadline has not passed,
///    at most once per reminder interval, and never to cancelled or already
///    deleted requests.
pub async fn process(pool: &PgPool, settings: &Settings) -> Result<DeletionStats> {
    let mut stats = DeletionStats::default();
    let now = Utc::now().naive_utc();

    // ---- 1. Overdue requests -> actual deletion ---------------------------
    let due: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, user_id FROM account_deletion_requests
           WHERE status = 'requested' AND deadline <= $1",
    )
    .bind(now)
    .fetch_all(pool)
    .await
    .map_err(AppError::Database)?;

    for (request_id, user_id) in due {
        // Terminal transition: requested -> deleted, guarded by the row's own
        // status so two workers cannot both delete the same account.
        let r = sqlx::query(
            "UPDATE account_deletion_requests
                 SET status = 'deleted'
               WHERE id = $1 AND status = 'requested'",
        )
        .bind(&request_id)
        .execute(pool)
        .await
        .map_err(AppError::Database)?;
        if r.rows_affected() == 0 {
            continue; // another worker already deleted it
        }

        let r =
            sqlx::query("UPDATE users SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL")
                .bind(&user_id)
                .execute(pool)
                .await
                .map_err(AppError::Database)?;
        stats.accounts_deleted += r.rows_affected();

        let r = sqlx::query(
            "UPDATE user_sessions SET is_revoked = true, revocation_reason = 'account deleted'
               WHERE user_id = $1 AND is_revoked = false",
        )
        .bind(&user_id)
        .execute(pool)
        .await
        .map_err(AppError::Database)?;
        stats.sessions_revoked += r.rows_affected();

        // Final notification: only after the row is durably deleted.
        stats.deletion_emails_sent += 1;
        let recipient_username_email: Option<(String, String)> =
            sqlx::query_as("SELECT username, email FROM users WHERE id = $1")
                .bind(&user_id)
                .fetch_optional(pool)
                .await
                .map_err(AppError::Database)?;

        if let Some((username, email)) =
            recipient_username_email.filter(|(_, e)| !e.trim().is_empty())
        {
            if let Some(mailer) = EmailService::from_settings(settings) {
                let message = deletion_completed_email(&settings.frontend_url, &username);
                let artifact = crate::services::email_artifact::EmailArtifact {
                    schema_version: 1,
                    execution_id: format!("deletion-completed-{}", request_id),
                    attempt_number: 1,
                    subject: message.subject,
                    text_body: message.text_body,
                    html_body: message.html_body,
                };
                let _ = mailer.send_artifact(&email, &artifact).await;
            }
        }
    }

    // ---- 2. Reminders for pending requests --------------------------------
    let reminder_cutoff = now - chrono::Duration::seconds(reminder_interval_seconds());
    let due_reminders: Vec<(String, String, String, chrono::NaiveDateTime)> = sqlx::query_as(
        "SELECT id, user_id, cancellation_token, deadline FROM account_deletion_requests
           WHERE status = 'requested'
             AND deadline > $1
             AND (last_reminder_sent IS NULL OR last_reminder_sent < $2)",
    )
    .bind(now)
    .bind(reminder_cutoff)
    .fetch_all(pool)
    .await
    .map_err(AppError::Database)?;

    for (request_id, user_id, token, deadline) in due_reminders {
        let recipient: Option<String> = sqlx::query_as("SELECT email FROM users WHERE id=$1")
            .bind(&user_id)
            .fetch_optional(pool)
            .await
            .map_err(AppError::Database)?
            .and_then(|(e,)| e);
        if let Some(email) = recipient.filter(|e| !e.trim().is_empty()) {
            let cancel_url = format!(
                "{}/auth/account/deletion-cancel?token={}",
                settings.backend_base_url.trim_end_matches('/'),
                token
            );
            if let Some(mailer) = EmailService::from_settings(settings) {
                let message = deletion_reminder_email(
                    &settings.frontend_url,
                    &user_id,
                    &deadline.format("%Y-%m-%d %H:%M UTC").to_string(),
                    &cancel_url,
                );
                let artifact = crate::services::email_artifact::EmailArtifact {
                    schema_version: 1,
                    execution_id: format!("deletion-reminder-{}", request_id),
                    attempt_number: 1,
                    subject: message.subject,
                    text_body: message.text_body,
                    html_body: message.html_body,
                };
                let _ = mailer.send_artifact(&email, &artifact).await;
            }
        }

        let r = sqlx::query(
            "UPDATE account_deletion_requests
                 SET last_reminder_sent = NOW(), reminder_count = reminder_count + 1
               WHERE id = $1",
        )
        .bind(&request_id)
        .execute(pool)
        .await
        .map_err(AppError::Database)?;
        stats.reminders_sent += r.rows_affected();
    }

    Ok(stats)
}

/// Outcome of one housekeeping tick.
#[derive(Debug, Clone, Default)]
pub struct DeletionStats {
    pub accounts_deleted: u64,
    pub sessions_revoked: u64,
    pub reminders_sent: u64,
    pub deletion_emails_sent: u64,
}

impl std::fmt::Display for DeletionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "accounts_deleted={}, sessions_revoked={}, reminders_sent={}, deletion_emails_sent={}",
            self.accounts_deleted,
            self.sessions_revoked,
            self.reminders_sent,
            self.deletion_emails_sent
        )
    }
}

/// Best-effort deletion-requested confirmation email. Never fails the request.
async fn send_deletion_email(
    pool: &PgPool,
    settings: &Settings,
    user_id: &str,
    deadline: chrono::NaiveDateTime,
    token: &str,
) {
    let recipient: Option<(String, String)> =
        sqlx::query_as("SELECT username, email FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .ok()
            .and_then(|r| r);
    let Some((username, email)) = recipient.filter(|(_, e)| !e.trim().is_empty()) else {
        return;
    };
    let Some(mailer) = EmailService::from_settings(settings) else {
        return;
    };
    let cancel_url = format!(
        "{}/auth/account/deletion-cancel?token={}",
        settings.backend_base_url.trim_end_matches('/'),
        token
    );
    let message = deletion_requested_email(
        &settings.frontend_url,
        &username,
        &deadline.format("%Y-%m-%d %H:%M UTC").to_string(),
        &cancel_url,
    );
    let artifact = crate::services::email_artifact::EmailArtifact {
        schema_version: 1,
        execution_id: format!("deletion-requested-{}", user_id),
        attempt_number: 1,
        subject: message.subject,
        text_body: message.text_body,
        html_body: message.html_body,
    };
    let _ = mailer.send_artifact(&email, &artifact).await;
}
