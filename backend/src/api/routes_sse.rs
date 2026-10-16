use axum::{
    extract::{Path, State},
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
    Router,
};
use futures::stream::Stream;
use std::{convert::Infallible, sync::Arc, time::Duration};

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/job/:job_id", get(sse_job))
        .route("/dashboard", get(sse_dashboard))
}

/// P1-I (ZT-01/02-24): re-check authorization while a long-lived SSE stream
/// stays open. The `AuthenticatedUser` extractor only authorizes at connect;
/// without this, a user deactivated (or a token family revoked by logout /
/// rotation) mid-stream keeps receiving events until the client disconnects.
///
/// Both SSE loops re-run this every 60s (`MissedTickBehavior::Skip`, first
/// tick consumed so connect-time authorization is not duplicated). 60s is the
/// accepted revocation-latency bound for long-lived streams: two cheap
/// indexed lookups per minute per open stream, and a revoked stream dies
/// within a minute instead of lasting hours. The revocation check mirrors
/// `services::auth::is_revoked_in_db`'s family arm inline (rather than making
/// that file's helper `pub`) — same table, same `expires_at > NOW()` window.
///
/// Returns `false` when the stream must be terminated.
async fn auth_still_valid(pool: &sqlx::PgPool, user_id: &str, token_family: &str) -> bool {
    let active: Option<bool> = sqlx::query_scalar("SELECT is_active FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
    if active != Some(true) {
        return false;
    }
    let revoked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM token_revocations WHERE token_family = $1 AND expires_at > NOW()",
    )
    .bind(token_family)
    .fetch_one(pool)
    .await
    .unwrap_or(1); // fail closed: a failed revocation lookup ends the stream
    revoked == 0
}

/// Builds the 60s revalidation ticker shared by both SSE loops.
async fn revalidation_ticker() -> tokio::time::Interval {
    let mut ticker = tokio::time::interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await; // consume the immediate first tick
    ticker
}

/// SSE stream for a single audit job — pushes updates event-driven via tokio broadcast channel.
/// Queries PostgreSQL once on connection for initial snapshot and auth check, then waits for
/// broadcast events from the orchestrator and worker pool.
async fn sse_job(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Path(job_id): Path<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let pool = state.pool().clone();
    let user_id = user.user_id.clone();
    let tenant_id = user.tenant_id.clone();
    let token_family = user.token_family.clone();
    let mut revalidate = revalidation_ticker().await;
    let mut rx = state.subscribe_job_updates();

    let stream = async_stream::stream! {
        // Query PostgreSQL ONCE on connection to verify user/tenant ownership and emit initial snapshot
        let job: Option<crate::models::AuditJob> = sqlx::query_as::<_, crate::models::AuditJob>(
            "SELECT * FROM audit_jobs WHERE id=$1 AND (user_id=$2 OR (tenant_id IS NOT NULL AND tenant_id=$3))",
        )
        .bind(&job_id)
        .bind(&user_id)
        .bind(&tenant_id)
        .fetch_optional(&pool)
        .await
        .unwrap_or(None);

        let Some(job) = job else {
            let evt = Event::default()
                .event("error")
                .data(r#"{"error":"job not found or access denied"}"#);
            yield Ok(evt);
            return;
        };

        let phases: Vec<crate::models::PhaseLedgerModel> =
            sqlx::query_as::<_, crate::models::PhaseLedgerModel>(
                "SELECT * FROM phase_ledger WHERE job_id=$1 ORDER BY started_at ASC",
            )
            .bind(&job_id)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();

        let is_terminal = job.status.is_terminal();
        let payload = serde_json::json!({
            "job": crate::schemas::audit_api::JobResponse::from(job),
            "phases": phases,
        });
        let json_str = serde_json::to_string(&payload).unwrap_or_default();

        if is_terminal {
            let done_evt = Event::default().event("done").data(json_str);
            yield Ok(done_evt);
            return;
        }

        let evt = Event::default().event("update").data(json_str);
        yield Ok(evt);

        // Listen to broadcast events (no DB polling). P1-I: `select!` also
        // polls the 60s revalidation ticker — a deactivated user or revoked
        // token family ends the stream within the 60s revocation-latency bound.
        loop {
            tokio::select! {
                _ = revalidate.tick() => {
                    if !auth_still_valid(&pool, &user_id, &token_family).await {
                        break;
                    }
                }
                msg = rx.recv() => match msg {
                Ok(event) => {
                    if event.job_id == job_id {
                        let payload = serde_json::json!({
                            "job": event.job,
                            "phases": event.phases,
                        });
                        let json_str = serde_json::to_string(&payload).unwrap_or_default();

                        if event.is_terminal {
                            let done_evt = Event::default().event("done").data(json_str);
                            yield Ok(done_evt);
                            break;
                        } else {
                            let evt = Event::default().event("update").data(json_str);
                            yield Ok(evt);
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Receiver fell behind; fetch latest state once to catch up
                    let job: Option<crate::models::AuditJob> = sqlx::query_as::<_, crate::models::AuditJob>(
                        "SELECT * FROM audit_jobs WHERE id=$1 AND (user_id=$2 OR (tenant_id IS NOT NULL AND tenant_id=$3))",
                    )
                    .bind(&job_id)
                    .bind(&user_id)
                    .bind(&tenant_id)
                    .fetch_optional(&pool)
                    .await
                    .unwrap_or(None);

                    if let Some(job) = job {
                        let phases: Vec<crate::models::PhaseLedgerModel> =
                            sqlx::query_as::<_, crate::models::PhaseLedgerModel>(
                                "SELECT * FROM phase_ledger WHERE job_id=$1 ORDER BY started_at ASC",
                            )
                            .bind(&job_id)
                            .fetch_all(&pool)
                            .await
                            .unwrap_or_default();

                        let is_term = job.status.is_terminal();
                        let payload = serde_json::json!({
                            "job": crate::schemas::audit_api::JobResponse::from(job),
                            "phases": phases,
                        });
                        let json_str = serde_json::to_string(&payload).unwrap_or_default();

                        if is_term {
                            let done_evt = Event::default().event("done").data(json_str);
                            yield Ok(done_evt);
                            break;
                        } else {
                            let evt = Event::default().event("update").data(json_str);
                            yield Ok(evt);
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

/// SSE stream for dashboard — event-driven updates via broadcast channel.
/// Emits initial dashboard summary on connect, then refreshes only when an event
/// for this user is received.
async fn sse_dashboard(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let pool = state.pool().clone();
    let user_id = user.user_id.clone();
    let tenant_id = user.tenant_id.clone();
    let token_family = user.token_family.clone();
    let mut revalidate = revalidation_ticker().await;
    let mut rx = state.subscribe_job_updates();

    let stream = async_stream::stream! {
        // Query PostgreSQL ONCE on connection to emit initial dashboard payload
        let jobs: Vec<crate::models::AuditJob> = sqlx::query_as::<_, crate::models::AuditJob>(
            "SELECT * FROM audit_jobs WHERE user_id=$1 OR (tenant_id IS NOT NULL AND tenant_id=$2) ORDER BY created_at DESC",
        )
        .bind(&user_id)
        .bind(&tenant_id)
        .fetch_all(&pool)
        .await
        .unwrap_or_default();

        let payload = serde_json::json!({
            "jobs": jobs.into_iter().map(crate::schemas::audit_api::JobResponse::from).collect::<Vec<_>>(),
            "ts": chrono::Utc::now().to_rfc3339(),
        });
        let evt = Event::default().event("dashboard").data(payload.to_string());
        yield Ok(evt);

        // Listen to broadcast events (no interval polling). P1-I: `select!`
        // also polls the 60s revalidation ticker — a deactivated user or
        // revoked token family ends the stream within the 60s bound.
        loop {
            tokio::select! {
                _ = revalidate.tick() => {
                    if !auth_still_valid(&pool, &user_id, &token_family).await {
                        break;
                    }
                }
                msg = rx.recv() => match msg {
                Ok(event) => {
                    if event.user_id == user_id {
                        let jobs: Vec<crate::models::AuditJob> = sqlx::query_as::<_, crate::models::AuditJob>(
                            "SELECT * FROM audit_jobs WHERE user_id=$1 OR (tenant_id IS NOT NULL AND tenant_id=$2) ORDER BY created_at DESC",
                        )
                        .bind(&user_id)
                        .bind(&tenant_id)
                        .fetch_all(&pool)
                        .await
                        .unwrap_or_default();

                        let payload = serde_json::json!({
                            "jobs": jobs.into_iter().map(crate::schemas::audit_api::JobResponse::from).collect::<Vec<_>>(),
                            "ts": chrono::Utc::now().to_rfc3339(),
                        });
                        let evt = Event::default().event("dashboard").data(payload.to_string());
                        yield Ok(evt);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    // Receiver fell behind; fetch latest dashboard state
                    let jobs: Vec<crate::models::AuditJob> = sqlx::query_as::<_, crate::models::AuditJob>(
                        "SELECT * FROM audit_jobs WHERE user_id=$1 OR (tenant_id IS NOT NULL AND tenant_id=$2) ORDER BY created_at DESC",
                    )
                    .bind(&user_id)
                    .bind(&tenant_id)
                    .fetch_all(&pool)
                    .await
                    .unwrap_or_default();

                    let payload = serde_json::json!({
                        "jobs": jobs.into_iter().map(crate::schemas::audit_api::JobResponse::from).collect::<Vec<_>>(),
                        "ts": chrono::Utc::now().to_rfc3339(),
                    });
                    let evt = Event::default().event("dashboard").data(payload.to_string());
                    yield Ok(evt);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}
