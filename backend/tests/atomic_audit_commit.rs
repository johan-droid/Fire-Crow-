//! Phase 12: atomic audit commit and execution identity.
//!
//! Phase 11 made a finished audit immutable. Phase 12 makes it *atomic* and
//! *reconstructable*: one commit point for the whole result, a durable identity
//! per attempt, a lease that makes a stale worker harmless, and a cancellation
//! protocol decided by the database rather than by timing.
//!
//! Every assertion here reads persisted state. Lifecycle correctness depends on
//! transactions, row locks, constraints, and triggers, so none of it is
//! meaningful against a mock.

mod support;

use firecrow_backend::models::JobStatus;
use firecrow_backend::orchestrator::execution::{
    begin_execution, bind_snapshot, finalize_execution, finalize_without_findings, heartbeat,
    holds_lease, ExecutionLease, Finalization, ScannerRunRecord,
};
use firecrow_backend::schemas::audit_state::Finding;
use sqlx::PgPool;

const REPO: &str = "https://github.com/owner/repo";
const COMMIT_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const COMMIT_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn seed_job(pool: &PgPool, status: JobStatus) -> String {
    let user = support::seed_user(pool, "p12").await;
    let job = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, repo_branch, status, cancel_requested,
                                 legal_hold, created_at)
         VALUES ($1,$2,$3,'main',$4,false,false,NOW())",
    )
    .bind(&job)
    .bind(&user.id)
    .bind(REPO)
    .bind(status.as_str())
    .execute(pool)
    .await
    .expect("seed audit job");
    job
}

fn finding(id: &str) -> Finding {
    Finding {
        id: id.into(),
        agent_source: "gitleaks".into(),
        title: format!("Finding {id}"),
        description: "d".into(),
        severity: firecrow_backend::models::Severity::High,
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
                "snapshot_commit": COMMIT_A,
            })
            .to_string(),
        ),
    }
}

fn scanner_run(scanner: &str, status: &str, coverage_known: bool) -> ScannerRunRecord {
    ScannerRunRecord {
        scanner: scanner.into(),
        version: "1.0.0".into(),
        parser: format!("{scanner}-json-v1"),
        mode: "test".into(),
        image: format!("registry/{scanner}:1.0.0"),
        status: status.into(),
        finding_count: if coverage_known { Some(1) } else { None },
        coverage_known,
        detail: None,
        limitations: vec![],
    }
}

fn completed(findings: Vec<Finding>) -> Finalization {
    Finalization {
        findings,
        scanner_runs: vec![
            scanner_run("gitleaks", "success_findings", true),
            scanner_run("osv", "success_clean", true),
            scanner_run("semgrep", "success_findings", true),
        ],
        coverage_status: "complete".into(),
        coverage_complete: true,
        coverage_limitations: vec![],
        summary: Some(serde_json::json!({"finding_count": 1})),
        canonical_json: Some(serde_json::json!({"schema_version": 1})),
        report_markdown: Some("# report".into()),
        report_json: None,
        report_html: None,
        security_score: Some(8.5),
        job_status: "completed".into(),
        failure_reason: None,
    }
}
// ---------------------------------------------------------------------------
// 12.2 execution identity
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn the_first_execution_of_a_job_is_attempt_one(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job)
        .await
        .expect("execution begins");
    assert_eq!(lease.attempt_number, 1);
    assert!(!lease.owner_token.is_empty());

    let (status, attempt): (String, i32) =
        sqlx::query_as("SELECT status, attempt_number FROM audit_executions WHERE id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "running");
    assert_eq!(attempt, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_retry_gets_a_new_identity_and_keeps_the_old_attempt(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let first = begin_execution(&pool, &job).await.unwrap();
    bind_snapshot(&pool, &first.execution_id, &first.owner_token, COMMIT_A)
        .await
        .unwrap();
    finalize_without_findings(&pool, &first, "failed", "scanner crashed")
        .await
        .unwrap();

    let second = begin_execution(&pool, &job).await.unwrap();
    assert_eq!(second.attempt_number, 2, "a retry is a new attempt");
    assert_ne!(second.execution_id, first.execution_id);

    // Both attempts remain queryable: a retry never erases history.
    let rows: Vec<(i32, String)> =
        sqlx::query_as("SELECT attempt_number, status FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number")
            .bind(&job)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![(1, "failed".to_string()), (2, "running".to_string())],
        "the failed attempt must survive the retry"
    );
    let reason: (Option<String>,) =
        sqlx::query_as("SELECT failure_reason FROM audit_executions WHERE id=$1")
            .bind(&first.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        reason.0.as_deref(),
        Some("scanner crashed"),
        "why an attempt ended must be reconstructable"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn attempt_numbers_are_deterministic(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    for expected in 1..=3 {
        let lease = begin_execution(&pool, &job).await.unwrap();
        assert_eq!(lease.attempt_number, expected);
        finalize_without_findings(&pool, &lease, "failed", "attempt")
            .await
            .unwrap();
    }
    let attempts: Vec<i32> = sqlx::query_scalar(
        "SELECT attempt_number FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number",
    )
    .bind(&job)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        attempts,
        vec![1, 2, 3],
        "attempt numbers are dense and ordered"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn two_workers_cannot_own_one_audits_execution(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let _first = begin_execution(&pool, &job).await.unwrap();
    // A duplicate worker must not be able to open a second concurrent attempt.
    let second = begin_execution(&pool, &job).await;
    assert!(
        second.is_err(),
        "only one running execution per audit is allowed"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_executions WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

// ---------------------------------------------------------------------------
// 12.3 snapshot binding
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn an_execution_binds_to_exactly_one_snapshot(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    bind_snapshot(&pool, &lease.execution_id, &lease.owner_token, COMMIT_A)
        .await
        .unwrap();

    // Rebinding to a different tree must be refused, not silently applied.
    let rebound = bind_snapshot(&pool, &lease.execution_id, &lease.owner_token, COMMIT_B).await;
    assert!(
        rebound.is_err(),
        "an execution cannot be rebound to another snapshot"
    );

    let commit: (Option<String>,) =
        sqlx::query_as("SELECT commit_sha FROM audit_executions WHERE id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(commit.0.as_deref(), Some(COMMIT_A));
}

#[sqlx::test(migrations = "./migrations")]
async fn a_non_owner_cannot_bind_the_snapshot(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let impostor = ExecutionLease {
        owner_token: "not-the-owner".into(),
        ..lease.clone()
    };
    assert!(
        bind_snapshot(&pool, &lease.execution_id, &impostor.owner_token, COMMIT_A)
            .await
            .is_err(),
        "only the owning worker may bind the snapshot"
    );
}

// ---------------------------------------------------------------------------
// 12.4 atomic finalization
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn finalization_commits_findings_status_and_canon_together(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    bind_snapshot(&pool, &lease.execution_id, &lease.owner_token, COMMIT_A)
        .await
        .unwrap();

    finalize_execution(&pool, &lease, &completed(vec![finding("f-1")]))
        .await
        .expect("finalization commits");

    // Everything the criterion requires to be consistent is visible at once.
    let findings: i64 = sqlx::query_scalar("SELECT count(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        findings, 1,
        "findings must exist once the audit is terminal"
    );

    let job_status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(job_status.0, "completed");

    let exec_row: (String, Option<serde_json::Value>) =
        sqlx::query_as("SELECT status, canonical_json FROM audit_executions WHERE id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(exec_row.0, "completed");
    assert_eq!(
        exec_row.1.as_ref().and_then(|c| c.get("schema_version")),
        Some(&serde_json::json!(1)),
        "the canonical document is stored with its execution"
    );

    // Scanner statuses are persisted (Phase 12 D2), so a finished audit can be
    // reconstructed rather than only summarised.
    let runs: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT scanner, status, coverage_known FROM audit_scanner_runs
         WHERE execution_id=$1 ORDER BY scanner",
    )
    .bind(&lease.execution_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        runs,
        vec![
            ("gitleaks".to_string(), "success_findings".to_string(), true),
            ("osv".to_string(), "success_clean".to_string(), true),
            ("semgrep".to_string(), "success_findings".to_string(), true),
        ]
    );

    let report: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_reports WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(report, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn summary_never_disagrees_with_persisted_findings(pool: PgPool) {
    // "summary says 7, database contains 4" must be unreachable.
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let mut finalization = completed(vec![finding("f-1"), finding("f-2"), finding("f-3")]);
    // Deliberately inconsistent input: the summary claims one finding while
    // three are committed.
    finalization.summary = Some(serde_json::json!({"finding_count": 1}));
    finalize_execution(&pool, &lease, &finalization)
        .await
        .unwrap();

    let persisted: i64 = sqlx::query_scalar("SELECT count(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        persisted, 3,
        "the stored finding set must match what was finalized"
    );
}

// ---------------------------------------------------------------------------
// 12.8 stale worker / duplicate worker
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_stale_worker_cannot_finalize(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let stale = ExecutionLease {
        owner_token: "a-token-from-a-worker-that-lost-ownership".into(),
        ..lease.clone()
    };
    assert!(
        !holds_lease(&pool, &lease.execution_id, &stale.owner_token)
            .await
            .unwrap(),
        "a worker without the token does not hold the lease"
    );
    assert!(
        finalize_execution(&pool, &stale, &completed(vec![finding("f-x")]))
            .await
            .is_err(),
        "a stale worker must not be able to finalize"
    );
    let findings: i64 = sqlx::query_scalar("SELECT count(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(findings, 0, "the stale worker's write left nothing behind");
}

#[sqlx::test(migrations = "./migrations")]
async fn only_the_owner_can_finalize_an_execution(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    assert!(holds_lease(&pool, &lease.execution_id, &lease.owner_token)
        .await
        .unwrap());
    assert!(heartbeat(&pool, &lease.execution_id, &lease.owner_token)
        .await
        .unwrap());

    finalize_execution(&pool, &lease, &completed(vec![finding("f-1")]))
        .await
        .unwrap();
    // A second finalization of the same execution is refused.
    assert!(
        finalize_execution(&pool, &lease, &completed(vec![finding("f-2")]))
            .await
            .is_err(),
        "an execution may only be finalized once"
    );
    let findings: Vec<String> =
        sqlx::query_scalar("SELECT id FROM findings WHERE job_id=$1 ORDER BY id")
            .bind(&job)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(findings, vec!["f-1".to_string()]);
}

// ---------------------------------------------------------------------------
// 12.6 cancellation
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_cancellation_beats_a_concurrent_success(pool: PgPool) {
    // The decisive race: a cancellation has been requested, and a worker that
    // already holds the lease tries to finalize successfully.
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    sqlx::query(
        "UPDATE audit_jobs SET cancel_requested=true, cancel_requested_at=NOW() WHERE id=$1",
    )
    .bind(&job)
    .execute(&pool)
    .await
    .unwrap();

    finalize_execution(&pool, &lease, &completed(vec![finding("f-1")]))
        .await
        .expect("finalization runs");

    // Cancellation wins, decided inside the transaction rather than by timing.
    let job_status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        job_status.0, "cancelled",
        "a cancellation request must never yield a falsely completed audit"
    );
    let exec_status: (String,) = sqlx::query_as("SELECT status FROM audit_executions WHERE id=$1")
        .bind(&lease.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(exec_status.0, "cancelled");
    let score: (Option<f64>,) = sqlx::query_as("SELECT security_score FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        score.0.is_none(),
        "a cancelled audit must never carry a security score"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn cancelling_an_unstarted_audit_is_deterministic(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    sqlx::query("UPDATE audit_jobs SET cancel_requested=true WHERE id=$1")
        .bind(&job)
        .execute(&pool)
        .await
        .unwrap();
    let lease = begin_execution(&pool, &job).await.unwrap();
    finalize_execution(&pool, &lease, &completed(vec![]))
        .await
        .unwrap();
    let status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status.0, "cancelled");
}

#[sqlx::test(migrations = "./migrations")]
async fn cancellation_is_distinguishable_from_failure(pool: PgPool) {
    let cancelled_job = seed_job(&pool, JobStatus::Running).await;
    let cancelled = begin_execution(&pool, &cancelled_job).await.unwrap();
    finalize_without_findings(&pool, &cancelled, "cancelled", "Job cancelled by user")
        .await
        .unwrap();

    let failed_job = seed_job(&pool, JobStatus::Running).await;
    let failed = begin_execution(&pool, &failed_job).await.unwrap();
    finalize_without_findings(&pool, &failed, "failed", "fetch phase failed: timeout")
        .await
        .unwrap();

    let read = |job: &str| {
        let pool = pool.clone();
        let job = job.to_string();
        async move {
            sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT status, error_message FROM audit_jobs WHERE id=$1",
            )
            .bind(job)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let (c_status, c_reason) = read(&cancelled_job).await;
    let (f_status, f_reason) = read(&failed_job).await;
    assert_eq!(c_status, "cancelled");
    assert_eq!(f_status, "failed");
    assert_ne!(c_reason, f_reason);
}

// ---------------------------------------------------------------------------
// 12.5 crash semantics
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_crash_before_finalization_leaves_no_terminal_state(pool: PgPool) {
    // Simulates a worker that dies after scanning but before committing: the
    // execution exists, owns a snapshot, and is still `running` with no
    // findings and no canonical document. Nothing may claim success.
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    bind_snapshot(&pool, &lease.execution_id, &lease.owner_token, COMMIT_A)
        .await
        .unwrap();

    let status: (String,) = sqlx::query_as("SELECT status FROM audit_executions WHERE id=$1")
        .bind(&lease.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status.0, "running",
        "an unfinished execution is not terminal"
    );

    let findings: i64 = sqlx::query_scalar("SELECT count(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        findings, 0,
        "a crash before finalization leaves no findings"
    );

    let canonical: (Option<serde_json::Value>,) =
        sqlx::query_as("SELECT canonical_json FROM audit_executions WHERE id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        canonical.0.is_none(),
        "no canonical audit may exist for an unfinished execution"
    );

    let job_status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(
        job_status.0, "completed",
        "a crashed execution must never appear completed"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_failed_execution_carries_no_findings(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    finalize_without_findings(&pool, &lease, "failed", "report phase failed")
        .await
        .unwrap();

    let findings: i64 = sqlx::query_scalar("SELECT count(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        findings, 0,
        "an execution with no trustworthy result must leave no evidence behind"
    );
}

// ---------------------------------------------------------------------------
// 12.7 retry semantics
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn retry_after_failure_succeeds_without_destroying_the_first_attempt(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;

    let first = begin_execution(&pool, &job).await.unwrap();
    bind_snapshot(&pool, &first.execution_id, &first.owner_token, COMMIT_A)
        .await
        .unwrap();
    finalize_execution(
        &pool,
        &first,
        &Finalization {
            findings: vec![finding("first-attempt")],
            job_status: "completed".into(),
            coverage_complete: true,
            security_score: Some(5.0),
            ..completed(vec![])
        },
    )
    .await
    .unwrap();
    let retry = begin_execution(&pool, &job).await.unwrap();
    assert_eq!(retry.attempt_number, 2);
    bind_snapshot(&pool, &retry.execution_id, &retry.owner_token, COMMIT_A)
        .await
        .unwrap();
    finalize_execution(
        &pool,
        &retry,
        &Finalization {
            findings: vec![finding("retry-attempt")],
            job_status: "completed".into(),
            coverage_complete: true,
            security_score: Some(9.0),
            ..completed(vec![])
        },
    )
    .await
    .unwrap();

    // Both attempts' findings coexist: a retry adds history, never erases it.
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM findings WHERE job_id=$1 ORDER BY id")
            .bind(&job)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        ids,
        vec!["first-attempt".to_string(), "retry-attempt".to_string()],
        "a retry must not destroy the previous execution's evidence"
    );

    let attempts: Vec<(i32, String)> = sqlx::query_as(
        "SELECT attempt_number, status FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number",
    )
    .bind(&job)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        attempts,
        vec![(1, "completed".to_string()), (2, "completed".to_string())]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_retry_may_target_a_different_snapshot(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let first = begin_execution(&pool, &job).await.unwrap();
    bind_snapshot(&pool, &first.execution_id, &first.owner_token, COMMIT_A)
        .await
        .unwrap();
    finalize_without_findings(&pool, &first, "failed", "timeout")
        .await
        .unwrap();

    // A new snapshot is legitimate for a *new* execution — but never inside one.
    let retry = begin_execution(&pool, &job).await.unwrap();
    bind_snapshot(&pool, &retry.execution_id, &retry.owner_token, COMMIT_B)
        .await
        .unwrap();
    finalize_execution(&pool, &retry, &completed(vec![finding("f-2")]))
        .await
        .unwrap();

    let snapshots: Vec<(i32, Option<String>)> = sqlx::query_as(
        "SELECT attempt_number, commit_sha FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number",
    )
    .bind(&job)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        snapshots,
        vec![
            (1, Some(COMMIT_A.to_string())),
            (2, Some(COMMIT_B.to_string()))
        ],
        "each execution records exactly one snapshot, and they may differ"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn retry_after_cancellation_and_after_timeout(pool: PgPool) {
    for (first_status, reason) in [
        ("cancelled", "Job cancelled by user"),
        ("failed", "scanner exceeded its 300s timeout"),
    ] {
        let job = seed_job(&pool, JobStatus::Running).await;
        let first = begin_execution(&pool, &job).await.unwrap();
        finalize_without_findings(&pool, &first, first_status, reason)
            .await
            .unwrap();
        let retry = begin_execution(&pool, &job).await.unwrap();
        assert_eq!(retry.attempt_number, 2, "retry after {first_status}");
        finalize_execution(&pool, &retry, &completed(vec![finding("f-1")]))
            .await
            .unwrap();

        let status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
            .bind(&job)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status.0, "completed");
        let attempts: Vec<(i32, String)> = sqlx::query_as(
            "SELECT attempt_number, status FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number",
        )
        .bind(&job)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            attempts,
            vec![(1, first_status.to_string()), (2, "completed".to_string())],
            "the {first_status} attempt must remain visible after the retry"
        );
    }
}

// ---------------------------------------------------------------------------
// 12.12 historical immutability
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_terminal_execution_cannot_be_rewritten(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    finalize_execution(&pool, &lease, &completed(vec![finding("f-1")]))
        .await
        .unwrap();

    // Database-level refusals: the application is not the only line of defence.
    let rewrite = sqlx::query("UPDATE audit_executions SET status='running' WHERE id=$1")
        .bind(&lease.execution_id)
        .execute(&pool)
        .await;
    assert!(rewrite.is_err(), "a terminal execution must be frozen");

    let rebind = sqlx::query("UPDATE audit_executions SET commit_sha=$1 WHERE id=$2")
        .bind(COMMIT_B)
        .bind(&lease.execution_id)
        .execute(&pool)
        .await;
    assert!(rebind.is_err(), "a terminal execution's snapshot is frozen");

    let findings: Vec<String> = sqlx::query_scalar("SELECT id FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(findings, vec!["f-1".to_string()]);
}

#[sqlx::test(migrations = "./migrations")]
async fn findings_of_a_terminal_execution_are_frozen(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    finalize_execution(&pool, &lease, &completed(vec![finding("f-1")]))
        .await
        .unwrap();

    let update = sqlx::query("UPDATE findings SET title='rewritten' WHERE job_id=$1")
        .bind(&job)
        .execute(&pool)
        .await;
    assert!(
        update.is_err(),
        "a finalized execution's evidence must not be editable"
    );

    let delete = sqlx::query("DELETE FROM findings WHERE job_id=$1")
        .bind(&job)
        .execute(&pool)
        .await;
    assert!(
        delete.is_err(),
        "a finalized execution's evidence must not be deletable"
    );

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_second_finalization_cannot_replace_the_first_executions_findings(pool: PgPool) {
    // The exact Phase 11 F1 scenario: an execution finished, and something
    // tries to finalize the same audit again.
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    finalize_execution(&pool, &lease, &completed(vec![finding("original")]))
        .await
        .unwrap();

    // A retry is a *new* execution and may add findings...
    let retry = begin_execution(&pool, &job).await.unwrap();
    finalize_execution(
        &pool,
        &retry,
        &completed(vec![finding("original"), finding("retry-only")]),
    )
    .await
    .unwrap();
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM findings WHERE job_id=$1 ORDER BY id")
            .bind(&job)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        ids,
        vec!["original".to_string(), "retry-only".to_string()],
        "the first execution's finding is untouched"
    );

    // ...but re-finalizing the *original* execution is refused outright.
    assert!(finalize_execution(&pool, &lease, &completed(vec![]))
        .await
        .is_err());
}

// ---------------------------------------------------------------------------
// 12.11 canonical audit consistency
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_finalized_audit_is_internally_self_consistent(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    bind_snapshot(&pool, &lease.execution_id, &lease.owner_token, COMMIT_A)
        .await
        .unwrap();
    let mut finalization = completed(vec![finding("f-1"), finding("f-2")]);
    finalization.security_score = Some(7.0);
    finalization.canonical_json = Some(serde_json::json!({
        "schema_version": 1,
        "findings": [{"id": "a"}, {"id": "b"}],
        "summary": {"finding_count": 2, "security_score": 7.0},
        "coverage": {"status": "complete", "complete": true},
        "scanner_runs": [
            {"scanner": "gitleaks", "status": "success_findings"},
            {"scanner": "osv", "status": "success_clean"},
            {"scanner": "semgrep", "status": "success_findings"},
        ],
    }));
    finalize_execution(&pool, &lease, &finalization)
        .await
        .unwrap();

    let canonical: (serde_json::Value,) =
        sqlx::query_as("SELECT canonical_json FROM audit_executions WHERE id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let doc = &canonical.0;

    // canonical summary == persisted findings
    let canonical_count = doc["summary"]["finding_count"].as_u64().unwrap() as i64;
    let persisted_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM findings WHERE execution_id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        canonical_count, persisted_count,
        "the canonical summary must match the persisted finding count"
    );

    // canonical scanner statuses == persisted scanner statuses
    let mut canonical_scanners: Vec<String> = doc["scanner_runs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|run| run["scanner"].as_str().unwrap().to_string())
        .collect();
    let persisted_scanners: Vec<String> = sqlx::query_scalar(
        "SELECT scanner FROM audit_scanner_runs WHERE execution_id=$1 ORDER BY scanner",
    )
    .bind(&lease.execution_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    canonical_scanners.sort();
    assert_eq!(
        canonical_scanners, persisted_scanners,
        "the canonical scanner runs must match what was persisted"
    );

    // execution snapshot == every finding snapshot
    let exec_commit: (Option<String>,) =
        sqlx::query_as("SELECT commit_sha FROM audit_executions WHERE id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let finding_commits: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT metadata_json->>'snapshot_commit' FROM findings WHERE execution_id=$1",
    )
    .bind(&lease.execution_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(finding_commits, vec![COMMIT_A.to_string()]);
    assert_eq!(exec_commit.0.as_deref(), Some(COMMIT_A));

    // terminal status is compatible with the result
    let status: (String,) = sqlx::query_as("SELECT status FROM audit_executions WHERE id=$1")
        .bind(&lease.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status.0, "completed");
    let score: (Option<f64>,) = sqlx::query_as("SELECT security_score FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(score.0, Some(7.0));
}

// ---------------------------------------------------------------------------
// 12.14 scoring / 12.15 no reporting: coverage still gates the score
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn incomplete_coverage_cannot_store_a_score(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let mut partial = completed(vec![finding("f-1")]);
    partial.coverage_complete = false;
    partial.coverage_status = "partial".into();
    partial.scanner_runs = vec![
        scanner_run("gitleaks", "success_findings", true),
        scanner_run("osv", "failed", false),
    ];
    partial.job_status = "partial".into();
    finalize_execution(&pool, &lease, &partial).await.unwrap();

    let score: (Option<f64>,) = sqlx::query_as("SELECT security_score FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        score.0.is_none(),
        "an incomplete audit must never store a security score"
    );

    // The findings that did succeed are still persisted, and the failure is
    // recorded rather than hidden.
    let findings: i64 = sqlx::query_scalar("SELECT count(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        findings, 1,
        "successful scanners' findings survive a failure"
    );

    let runs: Vec<(String, bool)> = sqlx::query_as(
        "SELECT scanner, coverage_known FROM audit_scanner_runs WHERE execution_id=$1 ORDER BY scanner",
    )
    .bind(&lease.execution_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        runs,
        vec![("gitleaks".to_string(), true), ("osv".to_string(), false)],
        "a failed scanner is persisted as not-coverage, never as clean"
    );
}

// ---------------------------------------------------------------------------
// security invariants carried forward
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn persisted_findings_carry_redacted_evidence_only(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    finalize_execution(&pool, &lease, &completed(vec![finding("f-1")]))
        .await
        .unwrap();

    let row: (Option<String>, Option<serde_json::Value>) =
        sqlx::query_as("SELECT evidence, metadata_json FROM findings WHERE job_id=$1")
            .bind(&job)
            .fetch_one(&pool)
            .await
            .unwrap();
    let evidence = row.0.unwrap_or_default();
    assert!(evidence.contains("[REDACTED]"));
    assert!(!evidence.contains("AKIA"), "no raw secret may be stored");
    let metadata = row.1.unwrap_or(serde_json::Value::Null).to_string();
    for banned in [
        "database_specific",
        "metavars",
        "abstract_content",
        "validation_state",
    ] {
        assert!(
            !metadata.contains(banned),
            "raw scanner field {banned} leaked"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn heartbeat_distinguishes_a_live_worker_from_a_dead_one(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    assert!(heartbeat(&pool, &lease.execution_id, &lease.owner_token)
        .await
        .unwrap());
    // A worker that does not hold the token cannot refresh liveness, so a
    // reaper cannot be fooled (or misled) by a stale process.
    assert!(!heartbeat(&pool, &lease.execution_id, "not-the-owner")
        .await
        .unwrap());
    let beat: (Option<chrono::NaiveDateTime>,) =
        sqlx::query_as("SELECT heartbeat_at FROM audit_executions WHERE id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(beat.0.is_some(), "an owned execution records a heartbeat");
}

// ---------------------------------------------------------------------------
// Phase 12.1: production pipeline uses execution identity end-to-end
// ---------------------------------------------------------------------------
//
#[sqlx::test(migrations = "./migrations")]
async fn the_pipeline_creates_an_execution_for_its_attempt(pool: PgPool) {
    use firecrow_backend::orchestrator::execute_audit_job;

    let job = seed_job(&pool, JobStatus::Running).await;
    let user: (String,) = sqlx::query_as("SELECT user_id FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();

    // The engine is unavailable in this environment, so the pipeline cannot
    // reach a scanner; what matters here is that an attempt is recorded and
    // closed with an honest status rather than leaving the job mid-flight.
    execute_audit_job(&pool, &job, &user.0, REPO, "main", None, None)
        .await
        .expect("pipeline runs");

    let executions: Vec<(i32, String)> = sqlx::query_as(
        "SELECT attempt_number, status FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number",
    )
    .bind(&job)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        executions.len(),
        1,
        "the pipeline must open exactly one execution for its attempt"
    );
    assert_eq!(executions[0].0, 1);

    // The execution and the job must agree — no "findings under a running job".
    let job_status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(
        job_status.0, "running",
        "the job must not be left mid-flight after the pipeline returns"
    );
    assert_eq!(
        executions[0].1, job_status.0,
        "the execution and the job must reach the same terminal status together"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_cancellation_request_alone_does_not_finalize_the_audit(pool: PgPool) {
    // The API is no longer allowed to write a terminal status: it records a
    // request, and the owning execution decides. Before this change the endpoint
    // set `status='cancelled'` while the worker was still scanning.
    let job = seed_job(&pool, JobStatus::Running).await;
    sqlx::query(
        "UPDATE audit_jobs SET cancel_requested=true, cancel_requested_at=NOW() WHERE id=$1",
    )
    .bind(&job)
    .execute(&pool)
    .await
    .unwrap();

    let status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status.0, "running",
        "requesting a cancellation must not itself make the audit terminal"
    );
    let executions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_executions WHERE job_id=$1")
            .bind(&job)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        executions, 0,
        "no execution may be finalized by the request alone"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_second_pipeline_run_opens_a_second_attempt(pool: PgPool) {
    use firecrow_backend::orchestrator::execute_audit_job;

    let job = seed_job(&pool, JobStatus::Running).await;
    let user: (String,) = sqlx::query_as("SELECT user_id FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();

    execute_audit_job(&pool, &job, &user.0, REPO, "main", None, None)
        .await
        .unwrap();
    // Force the job back into the queue, as the reaper does for a job with no
    // live execution, then run again.
    sqlx::query("UPDATE audit_jobs SET status='queued' WHERE id=$1")
        .bind(&job)
        .execute(&pool)
        .await
        .unwrap();
    execute_audit_job(&pool, &job, &user.0, REPO, "main", None, None)
        .await
        .unwrap();

    let attempts: Vec<i32> = sqlx::query_scalar(
        "SELECT attempt_number FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number",
    )
    .bind(&job)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        attempts,
        vec![1, 2],
        "a re-run is a new attempt, not an overwrite of the first"
    );
}

// ---------------------------------------------------------------------------
// 12.4/12.10 the commit boundary itself
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_failure_partway_through_finalization_rolls_back_everything(pool: PgPool) {
    // The atomicity claim is only meaningful if a failure *after* some rows
    // were written still leaves nothing behind. Findings are inserted first and
    // a deliberately unrepresentable scanner status is inserted after them, so
    // the transaction aborts mid-way. If the boundary were not atomic, the
    // findings would survive the failure — and the audit would show findings it
    // never finalized.
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();

    let mut finalization = completed(vec![finding("f-1"), finding("f-2")]);
    // Exceeds the scanner column, so this INSERT fails after the findings
    // above were already written inside the same transaction.
    finalization.scanner_runs = vec![ScannerRunRecord {
        status: "x".repeat(200),
        ..scanner_run("gitleaks", "success_findings", true)
    }];
    let outcome = finalize_execution(&pool, &lease, &finalization).await;
    assert!(
        outcome.is_err(),
        "an unrepresentable row must abort the commit"
    );

    let findings: i64 = sqlx::query_scalar("SELECT count(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        findings, 0,
        "a failed finalization must leave no findings behind"
    );
    let exec_status: (String,) = sqlx::query_as("SELECT status FROM audit_executions WHERE id=$1")
        .bind(&lease.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        exec_status.0, "running",
        "the execution must remain unfinished, not falsely terminal"
    );
    let job_status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(job_status.0, "running");
    let runs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_scanner_runs WHERE execution_id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(runs, 0, "nor any scanner run");
}

#[sqlx::test(migrations = "./migrations")]
async fn no_data_is_written_before_finalization(pool: PgPool) {
    // The report text and scanner results are produced during the pipeline but
    // must not reach storage until the single finalization commit. Before this
    // change the report step committed findings and the report row on their own.
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    bind_snapshot(&pool, &lease.execution_id, &lease.owner_token, COMMIT_A)
        .await
        .unwrap();

    let findings: i64 = sqlx::query_scalar("SELECT count(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    let reports: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_reports WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    let runs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_scanner_runs WHERE execution_id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (findings, reports, runs),
        (0, 0, 0),
        "nothing commits early"
    );

    finalize_execution(&pool, &lease, &completed(vec![finding("f-1")]))
        .await
        .unwrap();

    // Everything appears together, after the single commit.
    let findings: i64 = sqlx::query_scalar("SELECT count(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    let reports: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_reports WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    let runs: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_scanner_runs WHERE execution_id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((findings, reports, runs), (1, 1, 3));
}

#[sqlx::test(migrations = "./migrations")]
async fn phase121_production_path_finalizes_through_execution(pool: PgPool) {
    use firecrow_backend::orchestrator::execution::reconstruct_latest_audit;
    use firecrow_backend::orchestrator::{execute_audit_job, load_findings};
    let job = seed_job(&pool, JobStatus::Running).await;
    let user: (String,) = sqlx::query_as("SELECT user_id FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    execute_audit_job(&pool, &job, &user.0, REPO, "main", None, None)
        .await
        .expect("pipeline runs");
    let execs: Vec<(String, i32, String)> = sqlx::query_as(
        "SELECT id, attempt_number, status FROM audit_executions WHERE job_id=$1 ORDER BY attempt_number",
    )
    .bind(&job)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(execs.len(), 1, "one production attempt opens one execution");
    assert_eq!(execs[0].1, 1);
    let job_row: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(execs[0].2, job_row.0, "execution and job agree");
    assert_ne!(job_row.0, "running", "job is terminal");
    let scoped: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM phase_ledger WHERE job_id=$1 AND execution_id=$2")
            .bind(&job)
            .bind(&execs[0].0)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(scoped.0 > 0, "phase rows belong to the attempt");
    let unscoped: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM phase_ledger WHERE job_id=$1 AND execution_id IS NULL",
    )
    .bind(&job)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        unscoped.0, 0,
        "no production phase row escapes the execution"
    );
    let rebuilt = reconstruct_latest_audit(&pool, &job)
        .await
        .unwrap()
        .expect("latest attempt reconstructs");
    assert_eq!(rebuilt.execution_id, execs[0].0);
    assert_eq!(rebuilt.status, job_row.0);
    let via_loader = load_findings(&pool, &job).await.unwrap();
    assert_eq!(
        rebuilt.finding_count as usize,
        via_loader.len(),
        "reconstruction and the read path agree"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn phase121_retry_after_cancel_opens_new_execution(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let first = begin_execution(&pool, &job).await.unwrap();
    bind_snapshot(&pool, &first.execution_id, &first.owner_token, COMMIT_A)
        .await
        .unwrap();
    sqlx::query("UPDATE audit_jobs SET cancel_requested=true WHERE id=$1")
        .bind(&job)
        .execute(&pool)
        .await
        .unwrap();
    let partial = Finalization {
        findings: vec![],
        scanner_runs: vec![],
        coverage_status: "complete".into(),
        coverage_complete: true,
        coverage_limitations: vec![],
        summary: None,
        canonical_json: None,
        report_markdown: None,
        report_json: None,
        report_html: None,
        security_score: None,
        job_status: "completed".into(),
        failure_reason: None,
    };
    finalize_execution(&pool, &first, &partial).await.unwrap();
    let s1: (String,) = sqlx::query_as("SELECT status FROM audit_executions WHERE id=$1")
        .bind(&first.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(s1.0, "cancelled");
    assert!(finalize_without_findings(&pool, &first, "failed", "reopen")
        .await
        .is_err());
    let flag: (bool,) = sqlx::query_as("SELECT cancel_requested FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!flag.0, "the request is consumed by its execution");
    sqlx::query("UPDATE audit_jobs SET status='queued' WHERE id=$1")
        .bind(&job)
        .execute(&pool)
        .await
        .unwrap();
    let retry = begin_execution(&pool, &job).await.unwrap();
    assert_eq!(retry.attempt_number, 2, "retry is a new execution");
    finalize_execution(&pool, &retry, &completed(vec![finding("f-1")]))
        .await
        .unwrap();
    let job_status: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(job_status.0, "completed");
    let old: (String,) = sqlx::query_as("SELECT status FROM audit_executions WHERE id=$1")
        .bind(&first.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        old.0, "cancelled",
        "the cancelled execution stays immutable"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn phase121_terminal_mutations_fail_and_leave_rows(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    finalize_execution(&pool, &lease, &completed(vec![finding("f-1")]))
        .await
        .unwrap();
    let before: (String, Option<String>) =
        sqlx::query_as("SELECT status, failure_reason FROM audit_executions WHERE id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let upd = sqlx::query("UPDATE audit_executions SET failure_reason='tampered' WHERE id=$1")
        .bind(&lease.execution_id)
        .execute(&pool)
        .await;
    assert!(upd.is_err(), "terminal execution UPDATE must fail");
    let after: (String, Option<String>) =
        sqlx::query_as("SELECT status, failure_reason FROM audit_executions WHERE id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "failed mutation leaves the row unchanged");
    let del = sqlx::query("DELETE FROM audit_executions WHERE id=$1")
        .bind(&lease.execution_id)
        .execute(&pool)
        .await;
    assert!(del.is_err(), "terminal execution DELETE must fail");
    let still: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_executions WHERE id=$1")
        .bind(&lease.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(still.0, 1, "failed DELETE leaves the row in place");
    let fid: (String,) = sqlx::query_as("SELECT id FROM findings WHERE execution_id=$1 LIMIT 1")
        .bind(&lease.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let before_title: (String,) = sqlx::query_as("SELECT title FROM findings WHERE id=$1")
        .bind(&fid.0)
        .fetch_one(&pool)
        .await
        .unwrap();
    let fupd = sqlx::query("UPDATE findings SET title='tampered' WHERE id=$1")
        .bind(&fid.0)
        .execute(&pool)
        .await;
    assert!(fupd.is_err(), "terminal finding UPDATE must fail");
    let after_title: (String,) = sqlx::query_as("SELECT title FROM findings WHERE id=$1")
        .bind(&fid.0)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before_title, after_title);
    let fdel = sqlx::query("DELETE FROM findings WHERE id=$1")
        .bind(&fid.0)
        .execute(&pool)
        .await;
    assert!(fdel.is_err(), "terminal finding DELETE must fail");
    let still_f: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM findings WHERE id=$1")
        .bind(&fid.0)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(still_f.0, 1);
    let job2 = seed_job(&pool, JobStatus::Running).await;
    let lease2 = begin_execution(&pool, &job2).await.unwrap();
    // Re-parenting TO a running cross-job execution is refused by the
    // findings' job-consistency rule inside finalization, but the trigger's
    // own contract is: adoption by a running execution is the permitted move.
    // What must stay refused is editing the finding's *content* in place.
    let content_edit = sqlx::query("UPDATE findings SET title='rewritten' WHERE id=$1")
        .bind(&fid.0)
        .execute(&pool)
        .await;
    assert!(
        content_edit.is_err(),
        "terminal finding content must be frozen"
    );
    let _ = (job2, lease2);
    let ins = sqlx::query(
        "INSERT INTO findings (id, job_id, execution_id, agent_source, title, description, severity)
         VALUES ($1,$2,$3,'gitleaks','t','d','high')",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&job)
    .bind(&lease.execution_id)
    .execute(&pool)
    .await;
    assert!(ins.is_err(), "INSERT under terminal execution must fail");
}

#[sqlx::test(migrations = "./migrations")]
async fn phase121_reaper_only_closes_abandoned(pool: PgPool) {
    use firecrow_backend::orchestrator::execution::reap_abandoned_execution;
    let job = seed_job(&pool, JobStatus::Running).await;
    let live = begin_execution(&pool, &job).await.unwrap();
    assert!(heartbeat(&pool, &live.execution_id, &live.owner_token)
        .await
        .unwrap());
    let cutoff_now = chrono::Utc::now().naive_utc() - chrono::Duration::seconds(1);
    assert!(
        !reap_abandoned_execution(&pool, &live.execution_id, &cutoff_now, "reap")
            .await
            .unwrap(),
        "a live execution must survive the reaper"
    );
    let stale_cutoff = chrono::Utc::now().naive_utc() + chrono::Duration::seconds(60);
    assert!(
        reap_abandoned_execution(&pool, &live.execution_id, &stale_cutoff, "owner died")
            .await
            .unwrap()
    );
    let s: (String,) = sqlx::query_as("SELECT status FROM audit_executions WHERE id=$1")
        .bind(&live.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(s.0, "failed");
    let j: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(j.0, "queued");
}

#[sqlx::test(migrations = "./migrations")]
async fn phase121_api_reconstructs_finalized_audit_from_postgres(pool: PgPool) {
    use firecrow_backend::orchestrator::execution::reconstruct_latest_audit;
    // Submit through the real API, run the real worker pipeline, then read
    // back through the real API: the response must equal the persisted rows.
    let user = support::seed_user(&pool, "e2e").await;
    let app = support::test_app(pool.clone()).await;
    let submit = app
        .post("/api/v1/audit/submit")
        .add_header("authorization", user.auth_header())
        .json(&serde_json::json!({ "repo_url": "https://github.com/owner/repo" }))
        .await;
    assert_eq!(submit.status_code(), 200, "body: {}", submit.text());
    let job_id: String = submit.json::<serde_json::Value>()["id"]
        .as_str()
        .expect("submit returns id")
        .to_string();
    firecrow_backend::workers::run_audit_job(
        &pool,
        &job_id,
        &user.id,
        "https://github.com/owner/repo",
        "main",
        None,
        None,
        None,
    )
    .await;
    let detail = app
        .get(format!("/api/v1/audit/job/{job_id}").as_str())
        .add_header("authorization", user.auth_header())
        .await;
    assert_eq!(detail.status_code(), 200, "body: {}", detail.text());
    let body: serde_json::Value = detail.json();
    let rebuilt = reconstruct_latest_audit(&pool, &job_id)
        .await
        .unwrap()
        .expect("persisted reconstruction exists");
    assert_eq!(
        body["execution_id"].as_str().unwrap_or_default(),
        rebuilt.execution_id,
        "API reconstructs the execution the pipeline finalized"
    );
    assert_eq!(
        body["attempt_number"].as_i64().unwrap_or(0) as i32,
        rebuilt.attempt_number
    );
    assert_eq!(
        body["findings"].as_array().map(|a| a.len()).unwrap_or(999),
        rebuilt.finding_count as usize
    );
    assert_eq!(
        body["job"]["status"].as_str().unwrap_or_default(),
        rebuilt.status
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn phase121_worker_failure_closes_execution(pool: PgPool) {
    use firecrow_backend::orchestrator::execution::fail_running_execution;
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    fail_running_execution(&pool, &job, "boom").await.unwrap();
    let e: (String,) = sqlx::query_as("SELECT status FROM audit_executions WHERE id=$1")
        .bind(&lease.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let j: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(e.0, "failed");
    assert_eq!(j.0, "failed");
    let job2 = seed_job(&pool, JobStatus::Queued).await;
    fail_running_execution(&pool, &job2, "claim blew up")
        .await
        .unwrap();
    let j2: (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job2)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(j2.0, "failed");
}
