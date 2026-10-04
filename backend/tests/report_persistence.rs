//! Phase 13 (database-backed half): persistence, reconstruction, and terminal
//! guarantees.
//!
//! `tests/report.rs` proves the report is a deterministic *transformation* of a
//! Canonical Audit. It deliberately runs without a database, which leaves the
//! other half of the phase unproven: that the audit a report presents is
//! reconstructable from PostgreSQL alone, that a finalized attempt's report is
//! frozen, that a retry cannot overwrite the attempt before it, and that an
//! unfinished execution can never be presented as a completed security report.
//!
//! These tests drive the real production path — `begin_execution` ->
//! `finalize_execution` -> the API — and assert on the persisted rows, so a
//! passing run means the production pipeline and the reconstruction agree.

mod support;

use firecrow_backend::agents::scanner::{ScannerOutcome, ScannerResult};
use firecrow_backend::models::{JobStatus, Severity};
use firecrow_backend::orchestrator::canonical_audit::{canonical_audit, CanonicalAuditRequest};
use firecrow_backend::orchestrator::execution::{
    begin_execution, finalize_execution, load_stored_report, reconstruct_latest_audit,
    reconstruct_report_source, ExecutionLease, Finalization, ScannerRunRecord,
};
use firecrow_backend::schemas::audit_state::Finding;
use firecrow_backend::schemas::canonical_audit::CanonicalAudit;
use firecrow_backend::schemas::report::{build_report, CoverageState, ExecutionIdentity};
use firecrow_backend::services::reporter::ReportGenerator;
use sqlx::PgPool;

const REPO: &str = "https://github.com/example/repo";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

async fn seed_job(pool: &PgPool, status: JobStatus) -> String {
    let user = support::seed_user(pool, "p13").await;
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
/// One redacted secret finding, as the canonical boundary would carry it.
///
/// `rule` is distinct per attempt in the retry tests so the rendered report
/// differs *visibly* between attempts — two attempts whose reports differed only
/// by an execution id would not prove the attempt's own findings were presented.
fn secret_finding(fingerprint: &str) -> Finding {
    Finding {
        id: format!("gitleaks-{fingerprint}"),
        agent_source: "gitleaks".into(),
        title: format!("AWS access token ({fingerprint})"),
        description: "gitleaks".into(),
        severity: Severity::High,
        cvss_vector: None,
        cvss_score: None,
        // The canonical boundary redacts; the report must never see more.
        evidence: Some("AWS_ACCESS_KEY_ID=[REDACTED]".into()),
        remediation: Some("Rotate the credential.".into()),
        cwe_id: Some("CWE-798".into()),
        owasp_category: Some("A07".into()),
        confidence: Some("high".into()),
        scanner_name: Some("gitleaks".into()),
        scanner_mode: Some("secret".into()),
        file_path: Some("config/aws.env".into()),
        line_number: Some(3),
        route: None,
        metadata_json: Some(
            serde_json::json!({
                "rule_id": "aws-access-token",
                "fingerprint": fingerprint,
                "parser": "gitleaks-json-v1",
                "scanner_version": "8.18.4",
                "scanner_image": "ghcr.io/gitleaks/gitleaks:v8.18.4",
                "snapshot_commit": COMMIT,
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

/// The authenticated bearer token for a job's owner.
async fn owner_token(pool: &PgPool, job: &str) -> String {
    let (user_id,): (String,) = sqlx::query_as("SELECT user_id FROM audit_jobs WHERE id=$1")
        .bind(job)
        .fetch_one(pool)
        .await
        .unwrap();
    support::bearer_for(pool, &user_id).await
}

/// One successful scanner run, mirroring the shape the pipeline emits.
fn success_run(scanner: &str, mode: &str, findings: Vec<Finding>) -> ScannerResult {
    let finding_count = findings.len();
    ScannerResult {
        scanner: scanner.into(),
        version: "1.0.0".into(),
        mode: mode.into(),
        outcome: ScannerOutcome::Success { finding_count },
        findings,
        execution_record: serde_json::json!({
            "scanner": scanner,
            "version": "1.0.0",
            "mode": mode,
            "image": format!("registry/{scanner}:1.0.0"),
            "parser": format!("{scanner}-json-v1"),
            "snapshot_commit": COMMIT,
            "finding_count": finding_count,
        }),
    }
}

/// Build the real Canonical Audit v1 for a three-scanner run.
fn build_audit(findings: &[Finding]) -> CanonicalAudit {
    let results: Vec<ScannerResult> = vec![
        success_run("gitleaks", "secret", findings.to_vec()),
        success_run("osv", "dependency", vec![]),
        success_run("semgrep", "sast", vec![]),
    ];
    canonical_audit(&CanonicalAuditRequest {
        scan_id: "scan-1",
        repository_url: REPO,
        repo_branch: "main",
        repo_owner: "example",
        repo_name: "repo",
        snapshot_commit: Some(COMMIT),
        snapshot_file_count: 12,
        snapshot_total_size: 4096,
        results: &results,
        findings,
        security_score: Some(8.5),
    })
    .expect("canonical audit")
}

/// A finalization carrying a genuine report model, not a stub string.
fn finalization_for(
    lease: &ExecutionLease,
    findings: &[Finding],
    canonical: &CanonicalAudit,
) -> Finalization {
    let report = build_report(
        canonical,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .expect("report builds");
    Finalization {
        findings: findings.to_vec(),
        scanner_runs: vec![
            scanner_run("gitleaks", "success_findings", true),
            scanner_run("osv", "success_clean", true),
            scanner_run("semgrep", "success_clean", true),
        ],
        coverage_status: "complete".into(),
        coverage_complete: true,
        coverage_limitations: vec![],
        summary: Some(serde_json::json!({"finding_count": findings.len()})),
        canonical_json: Some(serde_json::to_value(canonical).expect("canonical serializes")),
        report_markdown: Some(ReportGenerator::render_markdown(&report).expect("markdown")),
        report_json: Some(serde_json::to_value(&report).expect("report serializes")),
        report_html: Some(ReportGenerator::render_html(&report).expect("html")),
        security_score: Some(8.5),
        job_status: "completed".into(),
        failure_reason: None,
    }
}

// ---------------------------------------------------------------------------
// 13.16 / 13.19 — reconstruction from PostgreSQL alone
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_report_is_reconstructable_from_postgres_alone(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("fp-1")];
    let canonical = build_audit(&findings);
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &canonical),
    )
    .await
    .expect("finalization commits");

    // The reconstruction path, with no orchestrator state in play.
    let source = reconstruct_report_source(&pool, &job, None)
        .await
        .unwrap()
        .expect("a report source exists");
    assert_eq!(source.execution_id, lease.execution_id);
    assert_eq!(source.attempt_number, 1);
    assert_eq!(source.audit, canonical, "reconstruction is lossless");

    // The reconstructed audit must yield the *same report bytes* the pipeline
    // committed: the production call graph and the storage reconstruction agree.
    let identity = ExecutionIdentity {
        execution_id: source.execution_id.clone(),
        attempt_number: source.attempt_number,
    };
    let rebuilt = build_report(&source.audit, &identity).expect("report rebuilds");
    let stored = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .expect("a stored report exists");
    assert_eq!(
        stored.markdown.as_deref(),
        Some(ReportGenerator::render_markdown(&rebuilt).unwrap().as_str()),
        "the stored report must be reproducible from the reconstructed audit"
    );
    assert_eq!(stored.report_schema_version, 1);
    assert_eq!(stored.canonical_schema_version, Some(1));

    // The score shown is the persisted score, and coverage is complete.
    assert_eq!(rebuilt.coverage.state, CoverageState::SuccessFindings);
    assert_eq!(rebuilt.summary.security_score, Some(8.5));
}

#[sqlx::test(migrations = "./migrations")]
async fn a_retry_does_not_overwrite_the_previous_executions_report(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;

    let first = begin_execution(&pool, &job).await.unwrap();
    let f1 = vec![secret_finding("fp-first")];
    finalize_execution(
        &pool,
        &first,
        &finalization_for(&first, &f1, &build_audit(&f1)),
    )
    .await
    .unwrap();

    let retry = begin_execution(&pool, &job).await.unwrap();
    assert_eq!(retry.attempt_number, 2, "a retry is a new execution");
    let f2 = vec![secret_finding("fp-second")];
    finalize_execution(
        &pool,
        &retry,
        &finalization_for(&retry, &f2, &build_audit(&f2)),
    )
    .await
    .unwrap();

    // Two report rows, one per attempt: the retry added a row rather than
    // replacing one.
    let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_reports WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 2, "each execution keeps its own report");

    // Each attempt still presents *its own* audit: no mixing of attempt #1
    // findings with attempt #2 identity.
    let first_source = reconstruct_report_source(&pool, &job, Some(&first.execution_id))
        .await
        .unwrap()
        .expect("first attempt is still reconstructable");
    assert_eq!(first_source.attempt_number, 1);
    assert_eq!(first_source.audit.findings.len(), 1);
    assert_eq!(
        first_source.audit.findings[0].provenance.native_fingerprint,
        "fp-first"
    );

    let latest = reconstruct_report_source(&pool, &job, None)
        .await
        .unwrap()
        .expect("latest attempt reconstructs");
    assert_eq!(latest.attempt_number, 2);
    assert_eq!(latest.execution_id, retry.execution_id);
    assert_eq!(
        latest.audit.findings[0].provenance.native_fingerprint,
        "fp-second"
    );

    // The default read is the latest attempt; the historical read is addressed
    // explicitly — never by accident.
    let latest_stored = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .expect("latest stored report");
    assert_eq!(latest_stored.execution_id, retry.execution_id);
    assert_eq!(latest_stored.attempt_number, 2);
    let first_stored = load_stored_report(&pool, &job, Some(&first.execution_id))
        .await
        .unwrap()
        .expect("first stored report");
    assert_eq!(first_stored.attempt_number, 1);
    assert_ne!(
        first_stored.markdown, latest_stored.markdown,
        "historical reports must remain distinguishable"
    );
}

// ---------------------------------------------------------------------------
// 13.15 / 13.21 — terminal-state rules and immutability
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_running_execution_is_never_presented_as_a_finished_report(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let _lease = begin_execution(&pool, &job).await.unwrap();

    // A running execution has no canonical audit yet. The generator must refuse
    // rather than invent one or return an empty-but-authoritative report.
    let err = reconstruct_report_source(&pool, &job, None)
        .await
        .expect_err("a running execution has no report");
    assert!(
        matches!(err, firecrow_backend::error::AppError::Conflict(_)),
        "expected a conflict, got {err:?}"
    );
    assert!(load_stored_report(&pool, &job, None).await.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_terminal_execution_with_no_canonical_audit_yields_no_report(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    // An execution that failed before producing a result: terminal, but with no
    // canonical audit to present.
    firecrow_backend::orchestrator::execution::finalize_without_findings(
        &pool,
        &lease,
        "failed",
        "scanner engine unavailable",
    )
    .await
    .unwrap();

    let err = reconstruct_report_source(&pool, &job, None)
        .await
        .expect_err("an execution with no canonical audit has no report");
    assert!(matches!(
        err,
        firecrow_backend::error::AppError::Conflict(_)
    ));
    assert!(load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_finalized_report_cannot_be_rewritten(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("fp-1")];
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &build_audit(&findings)),
    )
    .await
    .unwrap();

    let before = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .expect("report")
        .markdown
        .expect("markdown");

    // Tampering with a finalized attempt's report must be refused by the
    // database, exactly as editing its findings or canonical document is.
    assert!(
        sqlx::query("UPDATE audit_reports SET markdown_content='TAMPERED' WHERE execution_id=$1")
            .bind(&lease.execution_id)
            .execute(&pool)
            .await
            .is_err(),
        "a finalized report must be immutable"
    );
    assert!(
        sqlx::query("UPDATE audit_reports SET report_json='{}'::jsonb WHERE execution_id=$1")
            .bind(&lease.execution_id)
            .execute(&pool)
            .await
            .is_err(),
        "the stored report model must be immutable"
    );
    assert!(
        sqlx::query("DELETE FROM audit_reports WHERE execution_id=$1")
            .bind(&lease.execution_id)
            .execute(&pool)
            .await
            .is_err(),
        "a finalized report must not be deletable"
    );
    assert!(
        sqlx::query(
            "INSERT INTO audit_reports (id, job_id, execution_id, markdown_content, created_at)
             VALUES ($1,$2,$3,'late report',NOW())",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&job)
        .bind(&lease.execution_id)
        .execute(&pool)
        .await
        .is_err(),
        "a finished execution cannot gain a report afterwards"
    );

    let after = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .expect("report")
        .markdown
        .expect("markdown");
    assert_eq!(before, after, "the report survived every tamper attempt");
}

#[sqlx::test(migrations = "./migrations")]
async fn report_generation_failure_does_not_destroy_scanner_findings(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("fp-keep")];

    // A finalization whose *report* leg is missing — the shape a report
    // rendering failure produces. It must not be mistaken for a scanner
    // failure, and it must not cost the audit its findings.
    let mut broken = finalization_for(&lease, &findings, &build_audit(&findings));
    broken.report_markdown = None;
    broken.report_json = None;
    broken.report_html = None;
    finalize_execution(&pool, &lease, &broken).await.unwrap();

    let (status,): (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "completed",
        "a missing report leg must not rewrite a successful scanner run as a failure"
    );
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM findings WHERE execution_id=$1")
        .bind(&lease.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "the scanner findings survive a report failure");

    // And the report is still reconstructable from the canonical audit.
    let source = reconstruct_report_source(&pool, &job, None)
        .await
        .unwrap()
        .expect("canonical audit still reconstructs");
    assert_eq!(source.audit.findings.len(), 1);
}

// ---------------------------------------------------------------------------
// 13.20 — the API
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn the_api_serves_the_deterministic_report_for_an_execution(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("fp-api")];
    let canonical = build_audit(&findings);
    let expected = finalization_for(&lease, &findings, &canonical);
    let expected_markdown = expected.report_markdown.clone().unwrap();
    let expected_report_json = expected.report_json.clone().unwrap();
    finalize_execution(&pool, &lease, &expected).await.unwrap();

    let token = owner_token(&pool, &job).await;
    let app = support::test_app(pool.clone()).await;

    let md = app
        .get(format!("/api/v1/audit/job/{job}/report").as_str())
        .add_header("authorization", &token)
        .await;
    assert_eq!(md.status_code(), 200, "body: {}", md.text());
    assert_eq!(
        md.text(),
        expected_markdown,
        "the API serves the committed report bytes verbatim"
    );

    let json = app
        .get(format!("/api/v1/audit/job/{job}/report?format=json").as_str())
        .add_header("authorization", &token)
        .await;
    assert_eq!(json.status_code(), 200, "body: {}", json.text());
    let body: serde_json::Value = json.json();
    assert_eq!(body["report_schema_version"], 1);
    assert_eq!(body["identity"]["canonical_schema_version"], 1);
    assert_eq!(body["identity"]["report_schema_version"], 1);
    assert_eq!(
        body["identity"]["execution_id"],
        lease.execution_id.as_str()
    );
    assert_eq!(body["identity"]["attempt_number"], 1);
    assert_eq!(body["identity"]["snapshot_commit"], COMMIT);
    assert_eq!(body["summary"]["finding_count"], 1);
    assert_eq!(body["coverage"]["state"], "SUCCESS_FINDINGS");
    assert_eq!(body["coverage"]["complete"], true);
    assert_eq!(body["summary"]["security_score"], 8.5);
    assert_eq!(body, expected_report_json);
    // Redacted evidence survives; no raw secret is ever introduced.
    assert!(serde_json::to_string(&body).unwrap().contains("[REDACTED]"));

    // HTML is derived from the same model, never an independent read.
    let html = app
        .get(format!("/api/v1/audit/job/{job}/report?format=html").as_str())
        .add_header("authorization", &token)
        .await;
    assert_eq!(html.status_code(), 200, "body: {}", html.text());
    assert!(html.text().contains("[REDACTED]"));
}

#[sqlx::test(migrations = "./migrations")]
async fn the_api_refuses_a_report_for_an_unfinished_execution(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let _lease = begin_execution(&pool, &job).await.unwrap();
    let token = owner_token(&pool, &job).await;
    let app = support::test_app(pool.clone()).await;

    let res = app
        .get(format!("/api/v1/audit/job/{job}/report").as_str())
        .add_header("authorization", &token)
        .await;
    assert_eq!(
        res.status_code(),
        409,
        "an unfinished execution must not be served as a completed report: {}",
        res.text()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn the_api_keeps_historical_execution_reports_distinct(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;

    let first = begin_execution(&pool, &job).await.unwrap();
    let f1 = vec![secret_finding("fp-attempt-1")];
    finalize_execution(
        &pool,
        &first,
        &finalization_for(&first, &f1, &build_audit(&f1)),
    )
    .await
    .unwrap();

    let retry = begin_execution(&pool, &job).await.unwrap();
    let f2 = vec![secret_finding("fp-attempt-2")];
    finalize_execution(
        &pool,
        &retry,
        &finalization_for(&retry, &f2, &build_audit(&f2)),
    )
    .await
    .unwrap();

    let token = owner_token(&pool, &job).await;
    let app = support::test_app(pool.clone()).await;

    let latest = app
        .get(format!("/api/v1/audit/job/{job}/report").as_str())
        .add_header("authorization", &token)
        .await;
    assert_eq!(latest.status_code(), 200);
    assert!(latest.text().contains(&retry.execution_id));
    assert!(latest.text().contains("fp-attempt-2"));

    let historical = app
        .get(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/report",
                first.execution_id
            )
            .as_str(),
        )
        .add_header("authorization", &token)
        .await;
    assert_eq!(historical.status_code(), 200);
    assert!(historical.text().contains(&first.execution_id));
    assert!(historical.text().contains("fp-attempt-1"));
    assert_ne!(
        latest.text(),
        historical.text(),
        "a historical report must never be served as the current one"
    );

    // An unknown execution id is not silently resolved to the latest attempt.
    let bogus = app
        .get(format!("/api/v1/audit/job/{job}/execution/does-not-exist/report").as_str())
        .add_header("authorization", &token)
        .await;
    assert_eq!(bogus.status_code(), 404, "body: {}", bogus.text());
}

#[sqlx::test(migrations = "./migrations")]
async fn the_reconstructed_audit_agrees_with_the_persisted_rows(pool: PgPool) {
    // The Phase 12 reconstruction and the Phase 13 report source must describe
    // the same attempt: this is the exit-criterion read path.
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("fp-agree")];
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &build_audit(&findings)),
    )
    .await
    .unwrap();

    let rebuilt = reconstruct_latest_audit(&pool, &job)
        .await
        .unwrap()
        .expect("reconstructed audit");
    let source = reconstruct_report_source(&pool, &job, None)
        .await
        .unwrap()
        .expect("report source");
    assert_eq!(rebuilt.execution_id, source.execution_id);
    assert_eq!(rebuilt.attempt_number, source.attempt_number);
    assert_eq!(rebuilt.status, source.execution_status);
    assert_eq!(rebuilt.finding_count as usize, source.audit.findings.len());
    assert_eq!(rebuilt.security_score, source.audit.summary.security_score);
    assert_eq!(
        source.audit.coverage.complete,
        rebuilt.scanner_runs.iter().all(|run| run.coverage_known)
    );
}
