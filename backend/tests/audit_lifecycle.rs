//! Phase 11: audit lifecycle and persistence integrity.
//!
//! The scanner pipeline can produce a trustworthy canonical audit (Phase 10).
//! This phase proves that result cannot then be corrupted on its way into and
//! back out of the database: no contradictory state, no duplicate execution, no
//! mutated history, no snapshot drift.
//!
//! Database-backed tests use `#[sqlx::test]`. Pure state-machine tests need no
//! database.

mod support;

use firecrow_backend::models::{JobStatus, Severity};
use firecrow_backend::schemas::audit_state::Finding;
use sqlx::PgPool;

const REPO: &str = "https://github.com/owner/repo";

// ---------------------------------------------------------------------------
// 11.1/11.2 state-machine inventory
// ---------------------------------------------------------------------------

#[test]
fn the_declared_transition_contract_is_the_one_we_enforce() {
    // Terminal states are frozen: no audit outcome may be revised in place.
    for terminal in [
        JobStatus::Completed,
        JobStatus::Partial,
        JobStatus::Failed,
        JobStatus::Cancelled,
        JobStatus::EngineUnavailable,
    ] {
        assert!(terminal.is_terminal(), "{terminal:?} must be terminal");
        for target in [
            JobStatus::Queued,
            JobStatus::Running,
            JobStatus::Completed,
            JobStatus::Partial,
            JobStatus::Failed,
            JobStatus::Cancelled,
            JobStatus::EngineUnavailable,
        ] {
            assert!(
                !terminal.can_transition(&target),
                "{terminal:?} -> {target:?} must be illegal"
            );
        }
    }
    // A job that never ran cannot claim an outcome that implies it ran.
    assert!(!JobStatus::Queued.can_transition(&JobStatus::Completed));
    assert!(!JobStatus::Queued.can_transition(&JobStatus::Partial));
    assert!(!JobStatus::Queued.can_transition(&JobStatus::EngineUnavailable));
    assert!(JobStatus::Queued.can_transition(&JobStatus::Running));
    assert!(JobStatus::Running.can_transition(&JobStatus::Completed));
}

#[test]
fn every_status_round_trips_through_its_wire_name() {
    use std::str::FromStr;
    for status in [
        JobStatus::Queued,
        JobStatus::Running,
        JobStatus::Completed,
        JobStatus::Failed,
        JobStatus::Cancelled,
        JobStatus::Partial,
        JobStatus::EngineUnavailable,
    ] {
        let parsed = JobStatus::from_str(status.as_str())
            .unwrap_or_else(|e| panic!("{status:?} must parse: {e}"));
        assert_eq!(parsed.as_str(), status.as_str());
    }
    // An unknown status is a hard error, never a silent default.
    assert!(JobStatus::from_str("clean").is_err());
}
// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

const COMMIT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const COMMIT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn finding(id: &str, title: &str, snapshot: &str) -> Finding {
    Finding {
        id: id.into(),
        agent_source: "gitleaks".into(),
        title: title.into(),
        description: "d".into(),
        severity: Severity::High,
        cvss_vector: None,
        cvss_score: None,
        evidence: Some("AWS_ACCESS_KEY_ID=[REDACTED]".into()),
        remediation: None,
        cwe_id: None,
        owasp_category: None,
        confidence: Some("high".into()),
        scanner_name: Some("gitleaks".into()),
        scanner_mode: Some("secret".into()),
        file_path: Some("config/aws.env".into()),
        line_number: Some(3),
        route: None,
        metadata_json: Some(
            serde_json::json!({
                "rule_id": "aws-access-token",
                "fingerprint": format!("gitleaks:fp-{id}"),
                "parser": "gitleaks-json-v1",
                "scanner_version": "8.18.4",
                "scanner_image": "ghcr.io/gitleaks/gitleaks:v8.18.4",
                "snapshot_commit": snapshot,
                "start_column": 21,
                "end_column": 41,
                "end_line": 3,
            })
            .to_string(),
        ),
    }
}

async fn seed_job(pool: &PgPool, status: JobStatus, commit: Option<&str>) -> String {
    let user = support::seed_user(pool, "p11").await;
    let job = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, repo_branch, status, cancel_requested,
                                 legal_hold, created_at, commit_sha)
         VALUES ($1,$2,$3,'main',$4,false,false,NOW(),$5)",
    )
    .bind(&job)
    .bind(&user.id)
    .bind(REPO)
    .bind(status.as_str())
    .bind(commit)
    .execute(pool)
    .await
    .expect("seed audit job");
    job
}

async fn status_of(pool: &PgPool, job: &str) -> String {
    sqlx::query_as::<_, (String,)>("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(job)
        .fetch_one(pool)
        .await
        .unwrap()
        .0
}

/// Move a running audit to its terminal state, as the orchestrator does once
/// its findings are committed.
async fn finalize(pool: &PgPool, job: &str) {
    sqlx::query("UPDATE audit_jobs SET status='completed', finished_at=NOW() WHERE id=$1")
        .bind(job)
        .execute(pool)
        .await
        .unwrap();
}

async fn finding_titles(pool: &PgPool, job: &str) -> Vec<String> {
    sqlx::query_as::<_, (String,)>("SELECT title FROM findings WHERE job_id=$1 ORDER BY id")
        .bind(job)
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .map(|(title,)| title)
        .collect()
}

// ---------------------------------------------------------------------------
// 11.4 persistence atomicity / 11.6 snapshot immutability
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_completed_audit_cannot_be_rewritten_by_a_second_execution(pool: PgPool) {
    use firecrow_backend::orchestrator::persist_findings;

    // Seeded as running (that is how a real audit reaches its findings), then
    // finalized: a completed audit is exactly the state that must be frozen.
    let job = seed_job(&pool, JobStatus::Running, Some(COMMIT_A)).await;
    persist_findings(&pool, &job, &[finding("f-a", "Original finding", COMMIT_A)])
        .await
        .expect("persist historical findings");
    sqlx::query("UPDATE audit_jobs SET status='completed' WHERE id=$1")
        .bind(&job)
        .execute(&pool)
        .await
        .unwrap();

    // A duplicate execution recomputes a different result from a different
    // snapshot. It must be refused, not silently applied.
    let replayed = persist_findings(
        &pool,
        &job,
        &[
            finding("f-b", "Replayed finding", COMMIT_B),
            finding("f-c", "Another replayed finding", COMMIT_B),
        ],
    )
    .await;
    assert!(
        replayed.is_err(),
        "a finalized audit must reject further finding writes"
    );

    assert_eq!(
        finding_titles(&pool, &job).await,
        vec!["Original finding".to_string()],
        "history must not be mutated by a replay"
    );
    let commits: Vec<String> = sqlx::query_as::<_, (Option<String>,)>(
        "SELECT metadata_json->>'snapshot_commit' FROM findings WHERE job_id=$1",
    )
    .bind(&job)
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|(commit,)| commit.unwrap_or_default())
    .collect();
    assert_eq!(commits, vec![COMMIT_A.to_string()]);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_unfinished_audit_is_still_writable(pool: PgPool) {
    use firecrow_backend::orchestrator::persist_findings;

    // A worker that restarts re-runs a job that never reached a terminal state.
    let job = seed_job(&pool, JobStatus::Running, Some(COMMIT_A)).await;
    let first = persist_findings(&pool, &job, &[finding("f-a", "First pass", COMMIT_A)])
        .await
        .expect("a running audit must accept findings");
    assert_eq!(first, 1);

    let second = persist_findings(
        &pool,
        &job,
        &[
            finding("f-a", "First pass", COMMIT_A),
            finding("f-b", "Second pass", COMMIT_A),
        ],
    )
    .await
    .expect("a running audit must accept a retry's findings");
    assert_eq!(second, 2);
    assert_eq!(
        finding_titles(&pool, &job).await.len(),
        2,
        "a retry converges, it does not accumulate"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn every_persisted_finding_carries_its_job_snapshot(pool: PgPool) {
    use firecrow_backend::orchestrator::persist_findings;

    let job = seed_job(&pool, JobStatus::Running, Some(COMMIT_A)).await;
    persist_findings(&pool, &job, &[finding("f-a", "Pinned", COMMIT_A)])
        .await
        .unwrap();

    // A finding produced from another snapshot may not attach to this audit.
    let drifted = persist_findings(&pool, &job, &[finding("f-b", "Drifted", COMMIT_B)]).await;
    assert!(
        drifted.is_err(),
        "a finding from a different snapshot must not attach to this audit"
    );
    assert_eq!(
        finding_titles(&pool, &job).await,
        vec!["Pinned".to_string()]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_new_snapshot_does_not_change_a_finished_audit(pool: PgPool) {
    use firecrow_backend::orchestrator::persist_findings;

    let job = seed_job(&pool, JobStatus::Running, Some(COMMIT_A)).await;
    persist_findings(
        &pool,
        &job,
        &[finding("f-a", "Snapshot A finding", COMMIT_A)],
    )
    .await
    .unwrap();
    finalize(&pool, &job).await;
    let before: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT title, metadata_json->>'snapshot_commit' FROM findings WHERE job_id=$1 ORDER BY id",
    )
    .bind(&job)
    .fetch_all(&pool)
    .await
    .unwrap();

    // The repository moves on; a new audit runs against the new head.
    let new_job = seed_job(&pool, JobStatus::Running, Some(COMMIT_B)).await;
    persist_findings(
        &pool,
        &new_job,
        &[finding("f-b", "Snapshot B finding", COMMIT_B)],
    )
    .await
    .unwrap();
    finalize(&pool, &new_job).await;

    let after: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT title, metadata_json->>'snapshot_commit' FROM findings WHERE job_id=$1 ORDER BY id",
    )
    .bind(&job)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        before, after,
        "an audit is a record of one snapshot and must never change"
    );
}

// ---------------------------------------------------------------------------
// 11.3 audit vs execution identity / 11.5 idempotent retry
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn claiming_a_terminal_job_is_refused(pool: PgPool) {
    use firecrow_backend::orchestrator::claim_job_for_execution;

    let job = seed_job(&pool, JobStatus::Completed, Some(COMMIT_A)).await;
    assert!(
        !claim_job_for_execution(&pool, &job)
            .await
            .expect("claim query runs"),
        "a terminal job must not be claimable"
    );
    assert_eq!(
        status_of(&pool, &job).await,
        "completed",
        "the refusal must change nothing"
    );

    let queued = seed_job(&pool, JobStatus::Queued, Some(COMMIT_A)).await;
    assert!(claim_job_for_execution(&pool, &queued)
        .await
        .expect("claim query runs"));
    assert_eq!(status_of(&pool, &queued).await, "running");
}

#[sqlx::test(migrations = "./migrations")]
async fn only_one_worker_can_hold_a_job(pool: PgPool) {
    use firecrow_backend::orchestrator::claim_job_for_execution;

    let job = seed_job(&pool, JobStatus::Running, Some(COMMIT_A)).await;
    assert!(
        !claim_job_for_execution(&pool, &job)
            .await
            .expect("claim query runs"),
        "a job already in progress must not be claimable a second time"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn an_in_flight_job_may_still_execute(pool: PgPool) {
    use firecrow_backend::orchestrator::may_execute_job;

    // The queue claims `queued -> running` before handing the job to the
    // pipeline, so the pipeline must accept a job that is already `running`.
    // Refusing here would silently skip every real production job.
    let running = seed_job(&pool, JobStatus::Running, Some(COMMIT_A)).await;
    assert!(
        may_execute_job(&pool, &running).await.expect("query runs"),
        "a job already claimed by the queue must still execute"
    );

    // Every terminal outcome is refused.
    for terminal in [
        JobStatus::Completed,
        JobStatus::Partial,
        JobStatus::Failed,
        JobStatus::Cancelled,
        JobStatus::EngineUnavailable,
    ] {
        let job = seed_job(&pool, terminal, Some(COMMIT_A)).await;
        assert!(
            !may_execute_job(&pool, &job).await.expect("query runs"),
            "{terminal:?} must never be executed again"
        );
    }

    // A job that does not exist has nothing to execute.
    assert!(
        !may_execute_job(&pool, "no-such-job")
            .await
            .expect("query runs"),
        "a missing job must not be executable"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_duplicate_worker_execution_changes_nothing(pool: PgPool) {
    use firecrow_backend::orchestrator::{execute_audit_job, persist_findings};

    // A finished audit plus its findings, exactly as a completed run leaves it.
    let job = seed_job(&pool, JobStatus::Running, Some(COMMIT_A)).await;
    persist_findings(&pool, &job, &[finding("f-a", "Original finding", COMMIT_A)])
        .await
        .unwrap();
    finalize(&pool, &job).await;
    let user: (String,) = sqlx::query_as("SELECT user_id FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();

    // The same worker task runs again for the same job (retry / restart).
    execute_audit_job(&pool, &job, &user.0, REPO, "main", None, None)
        .await
        .expect("a duplicate execution must not error");

    assert_eq!(status_of(&pool, &job).await, "completed");
    assert_eq!(
        finding_titles(&pool, &job).await,
        vec!["Original finding".to_string()],
        "a duplicate worker execution must not rewrite a finished audit"
    );
}

// ---------------------------------------------------------------------------
// 11.6 snapshot binding at the job level
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn an_audit_records_the_snapshot_it_judged(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Completed, Some(COMMIT_A)).await;
    let (commit,): (Option<String>,) =
        sqlx::query_as("SELECT commit_sha FROM audit_jobs WHERE id=$1")
            .bind(&job)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        commit.as_deref(),
        Some(COMMIT_A),
        "an audit must be bound to the snapshot it scanned"
    );
}
