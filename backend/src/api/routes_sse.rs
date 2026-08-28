use axum::{
    Router,
    extract::{Path, State},
    response::sse::{Event, KeepAlive, Sse},
    routing::get,
};
use futures::stream::Stream;
use std::{convert::Infallible, sync::Arc, time::Duration};

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/job/:job_id", get(sse_job))
        .route("/dashboard", get(sse_dashboard))
}

/// SSE stream for a single audit job — emits phase + job JSON every 3 s.
/// Replaces the frontend 2 s `GET /audit/job/:id/phases` + `GET /audit/jobs` poll loop
/// with a single long-lived connection (1 auth check instead of ~30/min).
async fn sse_job(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Path(job_id): Path<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let pool = state.pool().clone();
    let user_id = user.user_id.clone();
    // 2.5s poll — keeps server load low (24 req/min per active job vs 30 before)
    // while still feeling live. Rate-limit safe: 1 SSE connection vs 30 polls/min.
    let mut interval = tokio::time::interval(Duration::from_millis(2500));
    // Skip the immediate tick so the first yield below is the instant snapshot.
    interval.tick().await;
    let mut last_hash: Option<u64> = None;

    let stream = async_stream::stream! {
        // Instant snapshot — no 3s wait (fixes “backend works but frontend blank”)
        let mut first = true;
        loop {
            if !first {
                interval.tick().await;
            }
            first = false;

            let job: Option<crate::models::AuditJob> = sqlx::query_as::<_, crate::models::AuditJob>(
                "SELECT * FROM audit_jobs WHERE id=$1 AND user_id=$2"
            )
            .bind(&job_id)
            .bind(&user_id)
            .fetch_optional(&pool)
            .await
            .unwrap_or(None);

            let Some(job) = job else {
                let evt = Event::default().event("error").data(r#"{"error":"job not found or access denied"}"#);
                yield Ok(evt);
                break;
            };

            let phases: Vec<crate::models::PhaseLedgerModel> =
                sqlx::query_as::<_, crate::models::PhaseLedgerModel>(
                    "SELECT * FROM phase_ledger WHERE job_id=$1 ORDER BY started_at ASC"
                )
                .bind(&job_id)
                .fetch_all(&pool)
                .await
                .unwrap_or_default();

            let payload = serde_json::json!({
                "job": crate::schemas::audit_api::JobResponse::from(job.clone()),
                "phases": phases,
            });
            let json_str = serde_json::to_string(&payload).unwrap_or_default();

            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            json_str.hash(&mut hasher);
            let h = hasher.finish();
            // On first tick always emit (fixes empty-screen). Afterwards dedup.
            let is_first_emit = last_hash.is_none();
            if !is_first_emit && Some(h) == last_hash {
                if matches!(job.status, crate::models::JobStatus::Completed | crate::models::JobStatus::Failed | crate::models::JobStatus::Cancelled) {
                    let done_evt = Event::default().event("done").data(json_str);
                    yield Ok(done_evt);
                    break;
                }
                continue;
            }
            last_hash = Some(h);

            // Emit as "update"; terminal jobs get "done" and close.
            if matches!(job.status, crate::models::JobStatus::Completed | crate::models::JobStatus::Failed | crate::models::JobStatus::Cancelled) {
                let done_evt = Event::default().event("done").data(json_str.clone());
                yield Ok(done_evt);
                // Grace period for client to ACK before FIN
                tokio::time::sleep(Duration::from_secs(1)).await;
                break;
            }
            let evt = Event::default().event("update").data(json_str);
            yield Ok(evt);
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

/// SSE stream for dashboard — pushes full summary only when jobs change (polls DB every 5 s).
/// Useful as fallback when frontend wants near-real-time without full polling.
async fn sse_dashboard(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let pool = state.pool().clone();
    let user_id = user.user_id.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    let mut last_hash: Option<u64> = None;

    let stream = async_stream::stream! {
        loop {
            interval.tick().await;

            // Lightweight change detector: latest job timestamp + count
            let latest: Option<(chrono::NaiveDateTime, i64)> = sqlx::query_as(
                "SELECT created_at, COUNT(*) OVER() FROM audit_jobs WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1"
            )
            .bind(&user_id)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten();

            // Also check phase ledger max timestamp
            let phase_ts: Option<chrono::NaiveDateTime> = sqlx::query_scalar(
                "SELECT MAX(started_at) FROM phase_ledger pl JOIN audit_jobs j ON j.id=pl.job_id WHERE j.user_id=$1"
            )
            .bind(&user_id)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten()
            .flatten();

            let combined = format!("{:?}-{:?}", latest, phase_ts);
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            combined.hash(&mut hasher);
            let h = hasher.finish();
            if Some(h) == last_hash {
                continue;
            }
            last_hash = Some(h);

            // Fetch full summary (re-use logic inline for SSE — keep it lightweight)
            let jobs: Vec<crate::models::AuditJob> = sqlx::query_as::<_, crate::models::AuditJob>(
                "SELECT * FROM audit_jobs WHERE user_id=$1 ORDER BY created_at DESC"
            )
            .bind(&user_id)
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
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}
