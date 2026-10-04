//! GitHub App webhook boundary (Phase 19B.5).
//!
//! ```text
//!   GitHub webhook → raw bytes → HMAC-SHA256 → parse → dedup → route
//! ```
//!
//! The signature is verified against the exact raw bytes *before* the JSON
//! is parsed, and a delivery ID is recorded before anything is acted on, so
//! a replay can neither forge nor duplicate an effect. Unknown events are
//! acknowledged without effect; only `ping` and `installation` events act in
//! 19B.5. Push/PR events arrive here verified and deduplicated in 19B.6.

use crate::error::{AppError, Result};
use axum::{body::Bytes, extract::State, http::HeaderMap, routing::post, Json, Router};
use std::sync::Arc;

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new().route("/webhook", post(github_webhook))
}

/// GitHub webhook deliveries. Unauthenticated by design — the HMAC signature
/// *is* the authentication — but fail-closed: an unconfigured secret refuses
/// everything rather than accepting unverified bodies.
pub async fn github_webhook(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>> {
    use crate::services::github_app::{
        mark_webhook_outcome, record_webhook_delivery, verify_webhook_signature,
        webhook_body_sha256, DeliveryReplay, GITHUB_WEBHOOK_MAX_BYTES,
    };

    let secret = state.settings().github_app_webhook_secret.clone();
    if secret.trim().is_empty() {
        return Err(AppError::NotImplemented(
            "GitHub webhooks are not configured".into(),
        ));
    }

    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("GitHub webhook signature is missing".into()))?;

    if body.len() > GITHUB_WEBHOOK_MAX_BYTES {
        return Err(AppError::PayloadTooLarge);
    }
    if !verify_webhook_signature(&secret, &body, signature) {
        return Err(AppError::Unauthorized(
            "GitHub webhook signature is invalid".into(),
        ));
    }

    // Only now is the body trustworthy enough to parse.
    let payload: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("GitHub webhook body is not valid JSON".into()))?;

    let delivery_id = headers
        .get("x-github-delivery")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|id| !id.is_empty() && id.len() <= 128)
        .ok_or_else(|| AppError::BadRequest("GitHub webhook delivery ID is missing".into()))?;
    let event = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|event| !event.is_empty() && event.len() <= 64)
        .ok_or_else(|| AppError::BadRequest("GitHub webhook event is missing".into()))?;

    let installation_id = payload
        .get("installation")
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_i64())
        .filter(|id| *id > 0);
    let replay = record_webhook_delivery(
        state.pool(),
        delivery_id,
        event,
        &webhook_body_sha256(&body),
        installation_id,
    )
    .await?;
    if replay == DeliveryReplay::Duplicate {
        return Ok(Json(serde_json::json!({
            "status": "duplicate",
            "delivery_id": delivery_id,
        })));
    }

    let outcome = match event {
        "ping" => ping_outcome(),
        "installation" => handle_installation_event(state.pool(), &payload).await,
        // 19B.6: a verified push becomes an audit through the one submission
        // path — never a second pipeline. 19B.7: a PR event pins the PR head
        // and queues through the same door.
        "push" => handle_push_event(&state, delivery_id, &payload).await,
        "pull_request" => handle_pull_request_event(&state, delivery_id, &payload).await,
        _ => Ok((
            Json(serde_json::json!({
                "status": "ignored",
                "event": event,
                "delivery_id": delivery_id,
            })),
            "ignored",
        )),
    };
    let (response, outcome) = outcome?;
    mark_webhook_outcome(state.pool(), delivery_id, outcome).await?;
    Ok(response)
}

/// A `ping` only proves the route is wired and signed: no state changes.
fn ping_outcome() -> Result<(Json<serde_json::Value>, &'static str)> {
    Ok((Json(serde_json::json!({ "status": "pong" })), "processed"))
}

/// Turn a verified `push` into an audit job through the existing submission
/// path.
///
/// ```text
///   verified push → head SHA + owner/repo from the payload
///       ↓
///   installation known, owned, usable (database)
///       ↓
///   repository authorized under the installation token (GitHub)
///       ↓
///   create_audit_job_attributed — the same door as user submissions
/// ```
///
/// Anything unverifiable is acknowledged without effect (`ignored`): a
/// deleted branch, a malformed SHA, an unknown installation, or a repository
/// the installation cannot see. Only transient provider failures propagate
/// as errors, so GitHub redelivers and the delivery record (still `pending`)
/// allows the retry to finish the work.
async fn handle_push_event(
    state: &Arc<crate::AppState>,
    delivery_id: &str,
    payload: &serde_json::Value,
) -> Result<(Json<serde_json::Value>, &'static str)> {
    use crate::services::github_app::{authorize_installation_repo, AppIdentity};

    let ignored = |reason: &str| {
        Ok((
            Json(serde_json::json!({
                "status": "ignored",
                "reason": reason,
            })),
            "ignored",
        ))
    };

    let installation_id = payload
        .get("installation")
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_i64())
        .filter(|id| *id > 0);
    let Some(installation_id) = installation_id else {
        return ignored("push without an installation");
    };

    // The pushed head. All zeros is a branch deletion: nothing to audit.
    let after = payload
        .get("after")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");
    if after.is_empty() || after.chars().all(|c| c == '0') {
        return ignored("branch deletion carries no snapshot");
    }
    if !crate::agents::fetch::is_valid_commit_sha(after) {
        return ignored("push head is not a commit SHA");
    }

    let full_name = payload
        .get("repository")
        .and_then(|v| v.get("full_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let (owner, repo) = full_name.split_once('/').unwrap_or(("", ""));
    if owner.is_empty() || repo.is_empty() {
        return ignored("push names no repository");
    }
    // Display label only: the audit pins `after`, never this ref.
    let branch = payload
        .get("ref")
        .and_then(|v| v.as_str())
        .and_then(|r| r.strip_prefix("refs/heads/"))
        .filter(|b| !b.trim().is_empty())
        .unwrap_or("main");

    let Some(identity) = AppIdentity::from_settings(state.settings())? else {
        return ignored("GitHub App is not configured");
    };

    // The installation row names the owning Fire Crow user; the chain below
    // proves ownership, usability, and repository access through GitHub.
    // Unknown or suspended is a terminal ignore, never a retry: no future
    // redelivery of this push changes it, and the answer reveals nothing
    // about which installations exist.
    let installer =
        match crate::services::github_app::get_installation(state.pool(), installation_id).await? {
            Some(row) if !row.suspended => row.installed_by_user_id.clone(),
            _ => return ignored("push installation is unknown or suspended"),
        };

    let authorized = authorize_installation_repo(
        state.pool(),
        &crate::agents::fetch::github_api_base(),
        &identity,
        &installer,
        installation_id,
        owner,
        repo,
    )
    .await;
    let authorized = match authorized {
        Ok(authorized) => authorized,
        // Permanent refusals are terminal ignores; transient provider
        // failures propagate so GitHub redelivers into a `pending` record.
        Err(AppError::NotFound(_)) | Err(AppError::Forbidden(_)) | Err(AppError::BadRequest(_)) => {
            return ignored("repository not authorized")
        }
        Err(other) => return Err(other),
    };

    let job_id = crate::api::routes_audit::create_audit_job_attributed(
        state.pool(),
        state.settings().max_active_jobs_per_user.max(1) as i64,
        &installer,
        None,
        &format!(
            "https://github.com/{}/{}",
            authorized.owner, authorized.repo
        ),
        branch,
        Some(after),
        Some(crate::api::routes_audit::WebhookJob {
            delivery_id: delivery_id.to_string(),
            installation_id,
        }),
    )
    .await?;
    Ok((
        Json(serde_json::json!({
            "status": "queued",
            "job_id": job_id,
        })),
        "processed",
    ))
}

/// Turn a verified `pull_request` event into an audit of the PR head.
///
/// Only `opened`, `synchronize`, and `reopened` queue work — and only the
/// head SHA, pinned exactly like a push. Everything else (closed, labeled,
/// review events) is acknowledged without effect. The audit itself is the
/// same job the push path creates; reporting back happens via Check Runs
/// when the worker finishes (19B.7), not here.
async fn handle_pull_request_event(
    state: &Arc<crate::AppState>,
    delivery_id: &str,
    payload: &serde_json::Value,
) -> Result<(Json<serde_json::Value>, &'static str)> {
    let ignored = |reason: &str| {
        Ok((
            Json(serde_json::json!({
                "status": "ignored",
                "reason": reason,
            })),
            "ignored",
        ))
    };

    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if !matches!(action, "opened" | "synchronize" | "reopened") {
        return ignored("pull request action carries no new snapshot");
    }
    // Re-shape the PR head as a push-equivalent revision and reuse the push
    // path verbatim: one revision-queuing implementation, two event shapes.
    let head = payload
        .get("pull_request")
        .and_then(|pr| pr.get("head"))
        .map(|head| {
            serde_json::json!({
                "ref": format!("refs/heads/{}", head.get("ref").and_then(|v| v.as_str()).unwrap_or("main")),
                "after": head.get("sha").and_then(|v| v.as_str()).unwrap_or(""),
                "repository": payload.get("repository").cloned().unwrap_or(serde_json::Value::Null),
                "installation": payload.get("installation").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .unwrap_or(serde_json::Value::Null);
    handle_push_event(state, delivery_id, &head).await
}

/// Route an `installation` event to the identity store.
///
/// `created` registers the installation, attributing it to the Fire Crow
/// account linked to the installing GitHub user (`users.github_id`). An
/// install by an unlinked GitHub account is acknowledged but stored nowhere:
/// an installation with no owning Fire Crow user authorizes nothing. `deleted`
/// revokes (row deletion); `suspend`/`unsuspend` flip the flag. Anything else
/// is acknowledged without effect.
async fn handle_installation_event(
    pool: &sqlx::PgPool,
    payload: &serde_json::Value,
) -> Result<(Json<serde_json::Value>, &'static str)> {
    use crate::services::github_app::{register_installation, remove_installation};

    let action = payload.get("action").and_then(|v| v.as_str()).unwrap_or("");
    let installation_id = payload
        .get("installation")
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_i64())
        .filter(|id| *id > 0)
        .ok_or_else(|| AppError::BadRequest("installation event has no installation ID".into()))?;

    match action {
        "deleted" => {
            let removed = remove_installation(pool, installation_id).await?;
            Ok((
                Json(serde_json::json!({
                    "status": "uninstalled",
                    "removed": removed,
                })),
                "processed",
            ))
        }
        "suspend" | "unsuspend" => {
            let suspended = action == "suspend";
            let known = crate::services::github_app::set_installation_suspended(
                pool,
                installation_id,
                suspended,
            )
            .await?;
            Ok((
                Json(serde_json::json!({
                    "status": "suspension_updated",
                    "suspended": suspended,
                    "known": known,
                })),
                "processed",
            ))
        }
        "created" | "new_permissions_accepted" => {
            let installation = payload.get("installation").expect("checked above");
            let account = installation
                .get("account")
                .ok_or_else(|| AppError::BadRequest("installation event has no account".into()))?;
            let account_id = account
                .get("id")
                .and_then(|v| v.as_i64())
                .filter(|id| *id > 0)
                .ok_or_else(|| {
                    AppError::BadRequest("installation event has no account ID".into())
                })?;
            let account_login = account.get("login").and_then(|v| v.as_str()).unwrap_or("");
            let account_type = account.get("type").and_then(|v| v.as_str()).unwrap_or("");
            // The installing GitHub user, resolved to the Fire Crow account
            // linked by OAuth. No link, no owner, no row.
            let sender_github_id = payload
                .get("sender")
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_i64())
                .map(|id| id.to_string())
                .unwrap_or_default();
            let installer: Option<(String,)> =
                sqlx::query_as("SELECT id FROM users WHERE github_id = $1")
                    .bind(&sender_github_id)
                    .fetch_optional(pool)
                    .await
                    .map_err(AppError::Database)?;
            let Some((installer,)) = installer.filter(|(id,)| !id.is_empty()) else {
                return Ok((
                    Json(serde_json::json!({
                        "status": "acknowledged",
                        "registered": false,
                        "reason": "installing GitHub account is not linked to a Fire Crow user",
                    })),
                    "ignored",
                ));
            };
            register_installation(
                pool,
                installation_id,
                account_id,
                account_login,
                account_type,
                &installer,
            )
            .await?;
            Ok((
                Json(serde_json::json!({
                    "status": "installed",
                    "registered": true,
                })),
                "processed",
            ))
        }
        _ => Ok((
            Json(serde_json::json!({
                "status": "ignored",
                "action": action,
            })),
            "ignored",
        )),
    }
}
