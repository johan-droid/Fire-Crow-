//! Phase 19B.8: kill/recovery rehearsal.
//!
//! Deliberate kills against the live pipeline, proving the execution model
//! holds: no duplicate execution, no mutable terminal state, no mixed
//! attempts, no orphaned findings, no fake clean result, no lost finalized
//! report.
//!
//! Covered elsewhere and referenced, not duplicated: scanner kill/timeout
//! (`sandbox_hardening`), failed fetch honesty (`scan_integrity`),
//! crash/retry/cancel races (`atomic_audit_commit`), provider-death
//! delivery survival (`email_delivery`, `telegram_delivery`).

mod support;

use firecrow_backend::orchestrator::execution::{begin_execution, reap_abandoned_execution};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn a_dead_worker_recovers_through_the_reaper_without_losing_history(pool: PgPool) {
    use firecrow_backend::models::JobStatus;

    let user = support::seed_user(&pool, "deadworker").await;
    let job = support::seed_job(&pool, &user.id, JobStatus::Running.as_str()).await;

    // Attempt 1 opens, then the worker dies: no heartbeat ever again.
    let first = begin_execution(&pool, &job).await.unwrap();
    sqlx::query("UPDATE audit_executions SET heartbeat_at = NOW() - INTERVAL '1 hour' WHERE id=$1")
        .bind(&first.execution_id)
        .execute(&pool)
        .await
        .unwrap();

    // The reaper finds abandonment, closes the execution as failed, and
    // releases the job back to queued — the only writer, by row lock.
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::minutes(10);
    assert!(
        reap_abandoned_execution(&pool, &first.execution_id, &cutoff, "test kill")
            .await
            .unwrap(),
        "an un-heartbeated execution must be reaped"
    );

    let execution_status: (String,) =
        sqlx::query_as("SELECT status FROM audit_executions WHERE id=$1")
            .bind(&first.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(execution_status.0, "failed");
    let job_status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(job_status.0, JobStatus::Queued.as_str());

    // A new worker picks the job up as attempt 2. History is additive:
    // attempt 1 stays failed and untouched.
    let second = begin_execution(&pool, &job).await.unwrap();
    assert_eq!(second.attempt_number, 2);
    let first_again: (String,) = sqlx::query_as("SELECT status FROM audit_executions WHERE id=$1")
        .bind(&first.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        first_again.0, "failed",
        "recovery must not rewrite the dead attempt"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_live_worker_is_never_reaped(pool: PgPool) {
    use firecrow_backend::models::JobStatus;

    let user = support::seed_user(&pool, "liveworker").await;
    let job = support::seed_job(&pool, &user.id, JobStatus::Running.as_str()).await;
    let lease = begin_execution(&pool, &job).await.unwrap();

    // Heartbeat is fresh: the reaper must stand down.
    let cutoff = chrono::Utc::now().naive_utc() - chrono::Duration::minutes(10);
    assert!(
        !reap_abandoned_execution(&pool, &lease.execution_id, &cutoff, "test kill")
            .await
            .unwrap(),
        "a heartbeating execution must survive the reaper"
    );
}

/// The audit pipeline must not depend on Redis: killing Redis (or never
/// configuring it) leaves fetch → scan → canonical → finalize → delivery
/// intact. This is structural — every integration test already runs with
/// `redis: None` — and this test fails if a Redis dependency is ever
/// introduced into the pipeline sources.
#[test]
fn the_audit_pipeline_has_no_redis_dependency() {
    for file in [
        "orchestrator/mod.rs",
        "orchestrator/execution.rs",
        "orchestrator/canonical_audit.rs",
        "orchestrator/delivery.rs",
        "orchestrator/ai_narrative.rs",
        "agents/fetch.rs",
        "agents/scanner.rs",
        "services/sandbox.rs",
        "services/reporter.rs",
        "services/telegram.rs",
        "services/email.rs",
    ] {
        let path = format!("src/{file}");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("pipeline source must exist: {path}"));
        assert!(
            !source.contains("redis"),
            "{file} must not depend on Redis: killing Redis must not destroy an audit"
        );
    }
}

static KILL_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// GitHub itself is down: the fetch fails fast and honestly, staging
/// nothing — no snapshot, no findings, no score, no clean verdict.
#[tokio::test]
async fn a_dead_github_api_fails_the_fetch_without_staging_anything() {
    use firecrow_backend::agents::fetch::fetch_repo_with_cancel;

    let _guard = KILL_ENV_LOCK.lock().await;
    std::env::set_var("GITHUB_API_BASE_URL", "http://127.0.0.1:1");

    let err = fetch_repo_with_cancel("https://github.com/acme/widget", "main", "", None, &|| {
        false
    })
    .await
    .expect_err("an unreachable GitHub API must fail");
    let rendered = err.to_string();
    assert!(
        !rendered.contains("clean") && !rendered.contains("0 findings"),
        "the failure must not read as a result, got: {rendered}"
    );

    std::env::remove_var("GITHUB_API_BASE_URL");
}
