//! Phase 15A: validated AI narrative persistence.
//!
//! Verifies execution-scoped storage, retry isolation, immutability, and that
//! AI failure never invalidates the deterministic audit/report.

mod support;

use firecrow_backend::agents::scanner::{ScannerOutcome, ScannerResult};
use firecrow_backend::models::{JobStatus, Severity};
use firecrow_backend::orchestrator::canonical_audit::{canonical_audit, CanonicalAuditRequest};
use firecrow_backend::orchestrator::execution::{
    begin_execution, finalize_execution, finalize_without_findings, load_ai_narrative,
    load_stored_report, persist_ai_narrative, reconstruct_latest_audit, reconstruct_report_source,
    ExecutionLease, Finalization, ScannerRunRecord,
};
use firecrow_backend::schemas::ai_narrative::{
    validate_narrative, FindingExplanation, RemediationGuidance, ReportNarrative,
    AI_NARRATIVE_SCHEMA_VERSION,
};
use firecrow_backend::schemas::audit_state::Finding;
use firecrow_backend::schemas::canonical_audit::CanonicalAudit;
use firecrow_backend::schemas::report::{build_report, CoverageState, ExecutionIdentity};
use firecrow_backend::services::reporter::ReportGenerator;
use sqlx::PgPool;

const REPO: &str = "https://github.com/example/repo";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

async fn seed_job(pool: &PgPool, status: JobStatus) -> String {
    let user = support::seed_user(pool, "p15a").await;
    let job = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, repo_branch, status, cancel_requested, legal_hold, created_at)
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

fn secret_finding(fingerprint: &str) -> Finding {
    Finding {
        id: format!("gitleaks-{fingerprint}"),
        agent_source: "gitleaks".into(),
        title: format!("AWS access token ({fingerprint})"),
        description: "gitleaks".into(),
        severity: Severity::High,
        cvss_vector: None,
        cvss_score: None,
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

fn build_audit(findings: &[Finding]) -> CanonicalAudit {
    let results: Vec<ScannerResult> = vec![
        success_run("gitleaks", "secret", findings.to_vec()),
        success_run("osv", "dependency", vec![]),
        success_run("semgrep", "sast", vec![]),
    ];
    canonical_audit(&CanonicalAuditRequest {
        scan_id: "scan-p15a",
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

fn faithful_narrative(
    report: &firecrow_backend::schemas::report::CanonicalAuditReport,
) -> ReportNarrative {
    ReportNarrative {
        narrative_schema_version: AI_NARRATIVE_SCHEMA_VERSION,
        executive_summary: format!(
            "The audit recorded {} finding(s) across the scanned snapshot.",
            report.summary.finding_count
        ),
        finding_explanations: report
            .findings
            .iter()
            .map(|f| FindingExplanation {
                finding_id: f.id.clone(),
                severity: None,
                explanation: "This credential is exposed in the repository and should be rotated."
                    .into(),
            })
            .collect(),
        remediation_guidance: report
            .findings
            .iter()
            .map(|f| RemediationGuidance {
                finding_id: f.id.clone(),
                guidance: "Consider rotating the credential and reviewing access logs.".into(),
                verified: false,
            })
            .collect(),
        limitations: report.limitations.clone(),
    }
}

// ---------------------------------------------------------------------------
// Basic persistence and reconstruction
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn narrative_persists_and_roundtrips(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("fp-n1")];
    let canonical = build_audit(&findings);
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &canonical),
    )
    .await
    .expect("finalization commits");

    let source = reconstruct_report_source(&pool, &job, None)
        .await
        .unwrap()
        .expect("report source");
    let report = build_report(
        &source.audit,
        &ExecutionIdentity {
            execution_id: source.execution_id.clone(),
            attempt_number: source.attempt_number,
        },
    )
    .expect("report");
    let narrative = faithful_narrative(&report);
    persist_ai_narrative(&pool, &lease.execution_id, &narrative)
        .await
        .expect("persist");

    let loaded = load_ai_narrative(&pool, &job, None)
        .await
        .expect("load")
        .expect("exists");
    assert_eq!(loaded.execution_id, lease.execution_id);
    assert_eq!(loaded.attempt_number, 1);
    assert_eq!(
        loaded.narrative_schema_version,
        AI_NARRATIVE_SCHEMA_VERSION as i32
    );
    assert_eq!(
        loaded.narrative.executive_summary,
        narrative.executive_summary
    );
}

// ---------------------------------------------------------------------------
// Execution isolation and retry
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn narrative_belongs_to_execution_and_retries_are_isolated(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;

    let first = begin_execution(&pool, &job).await.unwrap();
    let f1 = vec![secret_finding("fp-a")];
    finalize_execution(
        &pool,
        &first,
        &finalization_for(&first, &f1, &build_audit(&f1)),
    )
    .await
    .unwrap();
    let report1 = build_report(
        &reconstruct_report_source(&pool, &job, Some(&first.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: first.execution_id.clone(),
            attempt_number: first.attempt_number,
        },
    )
    .unwrap();
    let n1 = faithful_narrative(&report1);
    persist_ai_narrative(&pool, &first.execution_id, &n1)
        .await
        .unwrap();

    let retry = begin_execution(&pool, &job).await.unwrap();
    assert_eq!(retry.attempt_number, 2);
    let f2 = vec![secret_finding("fp-b")];
    finalize_execution(
        &pool,
        &retry,
        &finalization_for(&retry, &f2, &build_audit(&f2)),
    )
    .await
    .unwrap();
    let report2 = build_report(
        &reconstruct_report_source(&pool, &job, Some(&retry.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: retry.execution_id.clone(),
            attempt_number: retry.attempt_number,
        },
    )
    .unwrap();
    let mut n2 = faithful_narrative(&report2);
    n2.executive_summary.push_str(" (attempt 2)");
    persist_ai_narrative(&pool, &retry.execution_id, &n2)
        .await
        .unwrap();

    let loaded1 = load_ai_narrative(&pool, &job, Some(&first.execution_id))
        .await
        .unwrap()
        .unwrap();
    let loaded2 = load_ai_narrative(&pool, &job, Some(&retry.execution_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded1.attempt_number, 1);
    assert_eq!(loaded2.attempt_number, 2);
    assert_ne!(
        loaded1.narrative.executive_summary,
        loaded2.narrative.executive_summary
    );

    let latest = load_ai_narrative(&pool, &job, None).await.unwrap().unwrap();
    assert_eq!(latest.attempt_number, 2);
}

// ---------------------------------------------------------------------------
// Different jobs remain isolated
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn narratives_dont_cross_jobs(pool: PgPool) {
    let job_a = seed_job(&pool, JobStatus::Running).await;
    let job_b = seed_job(&pool, JobStatus::Running).await;

    let la = begin_execution(&pool, &job_a).await.unwrap();
    let fa = vec![secret_finding("fa")];
    finalize_execution(&pool, &la, &finalization_for(&la, &fa, &build_audit(&fa)))
        .await
        .unwrap();
    let ra = build_report(
        &reconstruct_report_source(&pool, &job_a, Some(&la.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: la.execution_id.clone(),
            attempt_number: la.attempt_number,
        },
    )
    .unwrap();
    persist_ai_narrative(&pool, &la.execution_id, &faithful_narrative(&ra))
        .await
        .unwrap();

    let lb = begin_execution(&pool, &job_b).await.unwrap();
    let fb = vec![secret_finding("fb")];
    finalize_execution(&pool, &lb, &finalization_for(&lb, &fb, &build_audit(&fb)))
        .await
        .unwrap();
    let rb = build_report(
        &reconstruct_report_source(&pool, &job_b, Some(&lb.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: lb.execution_id.clone(),
            attempt_number: lb.attempt_number,
        },
    )
    .unwrap();
    persist_ai_narrative(&pool, &lb.execution_id, &faithful_narrative(&rb))
        .await
        .unwrap();

    let na = load_ai_narrative(&pool, &job_a, None)
        .await
        .unwrap()
        .unwrap();
    let nb = load_ai_narrative(&pool, &job_b, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(na.job_id, job_a);
    assert_eq!(nb.job_id, job_b);
    assert_ne!(na.execution_id, nb.execution_id);
}

// ---------------------------------------------------------------------------
// Immutability
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn narrative_update_is_rejected(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("fu")];
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &build_audit(&findings)),
    )
    .await
    .unwrap();
    let report = build_report(
        &reconstruct_report_source(&pool, &job, Some(&lease.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .unwrap();
    persist_ai_narrative(&pool, &lease.execution_id, &faithful_narrative(&report))
        .await
        .unwrap();

    let res =
        sqlx::query("UPDATE ai_narratives SET narrative_schema_version=2 WHERE execution_id=$1")
            .bind(&lease.execution_id)
            .execute(&pool)
            .await;
    assert!(res.is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn narrative_delete_is_rejected(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("fd")];
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &build_audit(&findings)),
    )
    .await
    .unwrap();
    let report = build_report(
        &reconstruct_report_source(&pool, &job, Some(&lease.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .unwrap();
    persist_ai_narrative(&pool, &lease.execution_id, &faithful_narrative(&report))
        .await
        .unwrap();

    let res = sqlx::query("DELETE FROM ai_narratives WHERE execution_id=$1")
        .bind(&lease.execution_id)
        .execute(&pool)
        .await;
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// Terminal-state safety
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn running_execution_cannot_receive_narrative(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("fr")];
    let canonical = build_audit(&findings);
    // Do not finalize; execution is running
    let report = build_report(
        &canonical,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .unwrap();
    let res = persist_ai_narrative(&pool, &lease.execution_id, &faithful_narrative(&report)).await;
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// AI failure: deterministic report remains intact; no narrative
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn ai_failure_leaves_deterministic_report_intact_and_no_narrative(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("ff")];
    let canonical = build_audit(&findings);
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &canonical),
    )
    .await
    .unwrap();
    // No narrative persisted
    let loaded = load_ai_narrative(&pool, &job, None).await.unwrap();
    assert!(loaded.is_none());
    // Deterministic report is still available
    let stored = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.execution_id, lease.execution_id);
    assert!(stored.markdown.is_some());
    assert!(stored.json.is_some());
}

// ---------------------------------------------------------------------------
// No cross-attempt fallback, wrong execution, unknown execution
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn an_execution_without_a_narrative_does_not_fall_back_to_another(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;

    let first = begin_execution(&pool, &job).await.unwrap();
    let f1 = vec![secret_finding("fb-1")];
    finalize_execution(
        &pool,
        &first,
        &finalization_for(&first, &f1, &build_audit(&f1)),
    )
    .await
    .unwrap();
    let r1 = build_report(
        &reconstruct_report_source(&pool, &job, Some(&first.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: first.execution_id.clone(),
            attempt_number: first.attempt_number,
        },
    )
    .unwrap();
    persist_ai_narrative(&pool, &first.execution_id, &faithful_narrative(&r1))
        .await
        .unwrap();

    // Second attempt finalizes, but its AI generation never ran: no narrative.
    let retry = begin_execution(&pool, &job).await.unwrap();
    let f2 = vec![secret_finding("fb-2")];
    finalize_execution(
        &pool,
        &retry,
        &finalization_for(&retry, &f2, &build_audit(&f2)),
    )
    .await
    .unwrap();

    // Latest execution has no narrative, and must report none rather than
    // serving attempt 1's explanation of a different finding set.
    let latest = load_ai_narrative(&pool, &job, None).await.unwrap();
    assert!(
        latest.is_none(),
        "attempt 2 must not inherit attempt 1's narrative"
    );

    // Attempt 1 is still independently addressable and unchanged.
    let historical = load_ai_narrative(&pool, &job, Some(&first.execution_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(historical.attempt_number, 1);

    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ai_narratives n
         JOIN audit_executions e ON e.id = n.execution_id
         WHERE e.job_id = $1",
    )
    .bind(&job)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1, "exactly one narrative exists for this job");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_narrative_is_not_reachable_through_another_jobs_execution(pool: PgPool) {
    let job_a = seed_job(&pool, JobStatus::Running).await;
    let job_b = seed_job(&pool, JobStatus::Running).await;

    let la = begin_execution(&pool, &job_a).await.unwrap();
    let fa = vec![secret_finding("wa")];
    finalize_execution(&pool, &la, &finalization_for(&la, &fa, &build_audit(&fa)))
        .await
        .unwrap();
    let ra = build_report(
        &reconstruct_report_source(&pool, &job_a, Some(&la.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: la.execution_id.clone(),
            attempt_number: la.attempt_number,
        },
    )
    .unwrap();
    persist_ai_narrative(&pool, &la.execution_id, &faithful_narrative(&ra))
        .await
        .unwrap();

    // Job B's execution id presented against job A's narrative: job B does not
    // own it, so the resolution must find nothing rather than leak.
    assert!(load_ai_narrative(&pool, &job_b, Some(&la.execution_id))
        .await
        .unwrap()
        .is_none());
    assert!(
        load_ai_narrative(&pool, &job_a, Some(&uuid::Uuid::new_v4().to_string()))
            .await
            .unwrap()
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Security: only validated output is persisted
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_secret_bearing_narrative_is_refused_and_never_persisted(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("sec")];
    let canonical = build_audit(&findings);
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &canonical),
    )
    .await
    .unwrap();
    let report = build_report(
        &reconstruct_report_source(&pool, &job, Some(&lease.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .unwrap();

    let mut hostile = faithful_narrative(&report);
    hostile.executive_summary =
        "The exposed key is AKIAIOSFODNN7EXAMPLE and must be rotated immediately.".into();
    assert!(
        validate_narrative(&report, &hostile).is_err(),
        "a credential-shaped narrative must be refused by the Phase 14 validator"
    );

    // Nothing is persisted, and the deterministic report is untouched.
    assert!(load_ai_narrative(&pool, &job, None)
        .await
        .unwrap()
        .is_none());
    let stored = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.json.is_some());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_narrative_inventing_a_finding_is_refused_and_never_persisted(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("inv")];
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &build_audit(&findings)),
    )
    .await
    .unwrap();
    let report = build_report(
        &reconstruct_report_source(&pool, &job, Some(&lease.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .unwrap();

    let mut hostile = faithful_narrative(&report);
    hostile.finding_explanations.push(FindingExplanation {
        finding_id: "invented-vulnerability".into(),
        severity: Some("critical".into()),
        explanation: "An undocumented backdoor grants remote access.".into(),
    });
    assert!(validate_narrative(&report, &hostile).is_err());

    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ai_narratives")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows.0, 0, "rejected output must never reach storage");
}

#[sqlx::test(migrations = "./migrations")]
async fn no_raw_prompt_repository_or_scanner_json_is_stored(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("raw")];
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &build_audit(&findings)),
    )
    .await
    .unwrap();
    let report = build_report(
        &reconstruct_report_source(&pool, &job, Some(&lease.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .unwrap();
    persist_ai_narrative(&pool, &lease.execution_id, &faithful_narrative(&report))
        .await
        .unwrap();

    let (json,): (serde_json::Value,) =
        sqlx::query_as("SELECT narrative_json FROM ai_narratives WHERE execution_id=$1")
            .bind(&lease.execution_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let text = json.to_string();
    for banned in [
        "AWS_ACCESS_KEY_ID", // redacted evidence
        "scanner_execution", // scanner execution records
        "Secret",            // raw gitleaks JSON field
        "StartLine",         // raw semgrep JSON field
        "clone_path",        // filesystem path
        "/tmp/",             // filesystem path
        "HARD RULES",        // the prompt itself
        "AUDIT FACTS",       // the prompt itself
    ] {
        assert!(
            !text.contains(banned),
            "persisted narrative leaked {banned}"
        );
    }

    // Exactly the Phase 14 shape, nothing else.
    let object = json.as_object().expect("narrative is an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "executive_summary",
            "finding_explanations",
            "limitations",
            "narrative_schema_version",
            "remediation_guidance",
        ],
        "persisted document must carry only the validated Phase 14 fields"
    );
}

// ---------------------------------------------------------------------------
// Deterministic report independence
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn persisting_a_narrative_does_not_change_the_deterministic_report(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("indep")];
    let canonical = build_audit(&findings);
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &canonical),
    )
    .await
    .unwrap();

    let before = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .unwrap();
    let report = build_report(
        &reconstruct_report_source(&pool, &job, Some(&lease.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .unwrap();
    persist_ai_narrative(&pool, &lease.execution_id, &faithful_narrative(&report))
        .await
        .unwrap();

    let after = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        before.json, after.json,
        "the deterministic report JSON is unchanged"
    );
    assert_eq!(
        before.markdown, after.markdown,
        "the deterministic Markdown is unchanged"
    );
    assert_eq!(
        before.html, after.html,
        "the deterministic HTML is unchanged"
    );
    assert_eq!(before.report_schema_version, after.report_schema_version);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_execution_keeps_its_deterministic_audit_when_ai_is_absent(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("survive")];
    let canonical = build_audit(&findings);
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &canonical),
    )
    .await
    .unwrap();

    // No AI generation at all: the audit must be complete and unaffected.
    let reconstructed = reconstruct_latest_audit(&pool, &job)
        .await
        .unwrap()
        .expect("audit");
    assert_eq!(reconstructed.status, "completed");
    assert_eq!(reconstructed.attempt_number, 1);
    assert_eq!(reconstructed.finding_count, 1);
    assert_eq!(
        reconstructed.canonical_json.unwrap(),
        serde_json::to_value(&canonical).unwrap()
    );

    let source = reconstruct_report_source(&pool, &job, None)
        .await
        .unwrap()
        .unwrap();
    let report = build_report(
        &source.audit,
        &ExecutionIdentity {
            execution_id: source.execution_id.clone(),
            attempt_number: source.attempt_number,
        },
    )
    .unwrap();
    assert_eq!(report.coverage.state, CoverageState::SuccessFindings);
    assert_eq!(report.summary.finding_count, 1);
}

// ---------------------------------------------------------------------------
// API surface
// ---------------------------------------------------------------------------

/// The owner's bearer token for a job.
async fn owner_token(pool: &PgPool, job: &str) -> String {
    let (user_id,): (String,) = sqlx::query_as("SELECT user_id FROM audit_jobs WHERE id=$1")
        .bind(job)
        .fetch_one(pool)
        .await
        .unwrap();
    support::bearer_for(pool, &user_id).await
}

/// Finalize an execution and persist a narrative for it, returning the token.
async fn finalized_with_narrative(pool: &PgPool, job: &str, fingerprint: &str) -> ExecutionLease {
    let lease = begin_execution(pool, job).await.unwrap();
    let findings = vec![secret_finding(fingerprint)];
    finalize_execution(
        pool,
        &lease,
        &finalization_for(&lease, &findings, &build_audit(&findings)),
    )
    .await
    .unwrap();
    let report = build_report(
        &reconstruct_report_source(pool, job, Some(&lease.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .unwrap();
    persist_ai_narrative(pool, &lease.execution_id, &faithful_narrative(&report))
        .await
        .unwrap();
    lease
}

#[sqlx::test(migrations = "./migrations")]
async fn the_api_serves_the_narrative_of_the_named_execution(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let first = finalized_with_narrative(&pool, &job, "api-1").await;
    let retry = begin_execution(&pool, &job).await.unwrap();
    let f2 = vec![secret_finding("api-2")];
    finalize_execution(
        &pool,
        &retry,
        &finalization_for(&retry, &f2, &build_audit(&f2)),
    )
    .await
    .unwrap();
    let r2 = build_report(
        &reconstruct_report_source(&pool, &job, Some(&retry.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: retry.execution_id.clone(),
            attempt_number: retry.attempt_number,
        },
    )
    .unwrap();
    let mut n2 = faithful_narrative(&r2);
    n2.executive_summary = format!("{} Second attempt.", n2.executive_summary);
    let second_summary = n2.executive_summary.clone();
    persist_ai_narrative(&pool, &retry.execution_id, &n2)
        .await
        .unwrap();

    let token = owner_token(&pool, &job).await;
    let app = support::test_app(pool.clone()).await;

    // Attempt 2, addressed explicitly.
    let latest = app
        .get(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/narrative",
                retry.execution_id
            )
            .as_str(),
        )
        .add_header("authorization", &token)
        .await;
    assert_eq!(latest.status_code(), 200, "body: {}", latest.text());
    let body: serde_json::Value = latest.json();
    assert_eq!(body["execution_id"], retry.execution_id.as_str());
    assert_eq!(body["attempt_number"], 2);
    assert_eq!(body["narrative_schema_version"], 1);
    assert_eq!(
        body["narrative"]["executive_summary"],
        second_summary.as_str()
    );

    // Attempt 1 still resolves to its own narrative, never attempt 2's.
    let historical = app
        .get(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/narrative",
                first.execution_id
            )
            .as_str(),
        )
        .add_header("authorization", &token)
        .await;
    assert_eq!(historical.status_code(), 200);
    let historical_body: serde_json::Value = historical.json();
    assert_eq!(historical_body["execution_id"], first.execution_id.as_str());
    assert_eq!(historical_body["attempt_number"], 1);
    assert_ne!(
        historical_body["narrative"]["executive_summary"], body["narrative"]["executive_summary"],
        "the two attempts must not be interchangeable"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn the_api_404s_an_unknown_or_foreign_execution(pool: PgPool) {
    let job_a = seed_job(&pool, JobStatus::Running).await;
    let job_b = seed_job(&pool, JobStatus::Running).await;
    let lease = finalized_with_narrative(&pool, &job_a, "owned").await;

    let token_b = owner_token(&pool, &job_b).await;
    let app = support::test_app(pool.clone()).await;

    // Job B's owner asking for job A's execution: no leak, no cross-job read.
    let foreign = app
        .get(
            format!(
                "/api/v1/audit/job/{job_b}/execution/{}/narrative",
                lease.execution_id
            )
            .as_str(),
        )
        .add_header("authorization", &token_b)
        .await;
    assert_eq!(foreign.status_code(), 404, "body: {}", foreign.text());

    // Unknown execution id.
    let unknown = app
        .get(
            format!(
                "/api/v1/audit/job/{job_b}/execution/{}/narrative",
                uuid::Uuid::new_v4()
            )
            .as_str(),
        )
        .add_header("authorization", &token_b)
        .await;
    assert_eq!(unknown.status_code(), 404);
}

#[sqlx::test(migrations = "./migrations")]
async fn the_api_404s_a_finalized_execution_without_a_narrative(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("none")];
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &build_audit(&findings)),
    )
    .await
    .unwrap();

    let token = owner_token(&pool, &job).await;
    let app = support::test_app(pool.clone()).await;
    let res = app
        .get(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/narrative",
                lease.execution_id
            )
            .as_str(),
        )
        .add_header("authorization", &token)
        .await;
    assert_eq!(
        res.status_code(),
        404,
        "a missing narrative must be an explicit absence, not another attempt's: {}",
        res.text()
    );

    // The deterministic report is still served for the same execution.
    let report = app
        .get(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/report",
                lease.execution_id
            )
            .as_str(),
        )
        .add_header("authorization", &token)
        .await;
    assert_eq!(
        report.status_code(),
        200,
        "the audit survives an absent narrative"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn the_api_refuses_a_narrative_for_a_running_execution(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let token = owner_token(&pool, &job).await;
    let app = support::test_app(pool.clone()).await;

    let res = app
        .get(
            format!(
                "/api/v1/audit/job/{job}/execution/{}/narrative",
                lease.execution_id
            )
            .as_str(),
        )
        .add_header("authorization", &token)
        .await;
    assert_ne!(
        res.status_code(),
        200,
        "a running execution must never serve a narrative: {}",
        res.text()
    );
}

// ---------------------------------------------------------------------------
// Schema guarantees, exercised directly against PostgreSQL
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn the_schema_carries_no_job_column_so_lineage_cannot_drift(pool: PgPool) {
    let columns: (String,) = sqlx::query_as(
        "SELECT string_agg(column_name, ',' ORDER BY column_name)
         FROM information_schema.columns WHERE table_name='ai_narratives'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        columns.0, "created_at,execution_id,id,narrative_json,narrative_schema_version",
        "lineage is a single execution_id column; a paired job_id could disagree"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_narrative_cannot_be_written_for_a_nonexistent_execution(pool: PgPool) {
    let res = sqlx::query(
        "INSERT INTO ai_narratives (id, execution_id, narrative_json, narrative_schema_version)
         VALUES ($1, $2, CAST($3 AS JSONB), 1)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(r#"{"narrative_schema_version":1}"#)
    .execute(&pool)
    .await;
    assert!(res.is_err(), "a fabricated execution id must be rejected");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_second_narrative_for_one_execution_is_refused_loudly(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = finalized_with_narrative(&pool, &job, "dupe").await;

    let again = persist_ai_narrative(
        &pool,
        &lease.execution_id,
        &faithful_narrative(
            &build_report(
                &reconstruct_report_source(&pool, &job, Some(&lease.execution_id))
                    .await
                    .unwrap()
                    .unwrap()
                    .audit,
                &ExecutionIdentity {
                    execution_id: lease.execution_id.clone(),
                    attempt_number: lease.attempt_number,
                },
            )
            .unwrap(),
        ),
    )
    .await;
    assert!(
        again.is_err(),
        "a duplicate persist must surface, not silently do nothing"
    );

    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ai_narratives WHERE execution_id=$1")
        .bind(&lease.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        rows.0, 1,
        "the original narrative is the only one that survives"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn the_stored_version_column_mirrors_the_document(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = finalized_with_narrative(&pool, &job, "mirror").await;

    let (column_version, document_version): (i32, i64) = sqlx::query_as(
        "SELECT narrative_schema_version,
                (narrative_json->>'narrative_schema_version')::bigint
         FROM ai_narratives WHERE execution_id=$1",
    )
    .bind(&lease.execution_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(column_version as i64, document_version);
    assert_eq!(column_version, 1);
}

// ---------------------------------------------------------------------------
// Phase 15A final hardening: the database refuses a narrative that has no
// finalized deterministic report to explain.
// ---------------------------------------------------------------------------

/// Insert a narrative with raw SQL, bypassing the Rust persistence boundary, so
/// the assertion is about the database and nothing else.
async fn raw_insert_narrative(pool: &PgPool, execution_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO ai_narratives (id, execution_id, narrative_json, narrative_schema_version)
         VALUES ($1, $2, CAST($3 AS JSONB), 1)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(execution_id)
    .bind(r#"{"narrative_schema_version":1,"executive_summary":"x","finding_explanations":[],"remediation_guidance":[],"limitations":[]}"#)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn count_narratives(pool: &PgPool) -> i64 {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ai_narratives")
        .fetch_one(pool)
        .await
        .unwrap();
    count
}

/// Begin an execution and end it terminally *without* a deterministic report,
/// the way a crashed or unavailable scanner run does.
async fn terminal_without_report(pool: &PgPool, job: &str, status: &str, reason: &str) -> String {
    let lease = begin_execution(pool, job).await.unwrap();
    finalize_without_findings(pool, &lease, status, reason)
        .await
        .unwrap_or_else(|error| panic!("finalizing as {status} should be allowed: {error}"));
    lease.execution_id
}

#[sqlx::test(migrations = "./migrations")]
async fn the_database_accepts_a_narrative_for_a_finalized_execution_with_a_report(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = begin_execution(&pool, &job).await.unwrap();
    let findings = vec![secret_finding("pass")];
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &build_audit(&findings)),
    )
    .await
    .unwrap();

    raw_insert_narrative(&pool, &lease.execution_id)
        .await
        .expect(
            "terminal execution with a committed deterministic report is a legal narrative host",
        );

    let rows: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ai_narratives WHERE execution_id=$1")
        .bind(&lease.execution_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows.0, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_failed_execution_without_a_report_cannot_gain_a_narrative(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let execution_id = terminal_without_report(&pool, &job, "failed", "scanner crashed").await;

    let err = raw_insert_narrative(&pool, &execution_id)
        .await
        .expect_err("a failed execution has no deterministic report to explain");
    let message = err.to_string();
    assert!(
        message.contains("no finalized deterministic report"),
        "the error must name the missing precondition, got: {message}"
    );
    assert_eq!(count_narratives(&pool).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_cancelled_execution_without_a_report_cannot_gain_a_narrative(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let execution_id = terminal_without_report(&pool, &job, "cancelled", "user cancelled").await;

    raw_insert_narrative(&pool, &execution_id)
        .await
        .expect_err("a cancelled execution has no deterministic report to explain");
    assert_eq!(count_narratives(&pool).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_engine_unavailable_execution_cannot_gain_a_narrative(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let execution_id =
        terminal_without_report(&pool, &job, "engine_unavailable", "no engine").await;

    raw_insert_narrative(&pool, &execution_id)
        .await
        .expect_err("an execution that never produced a report cannot be explained");
    assert_eq!(count_narratives(&pool).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_timed_out_execution_cannot_gain_a_narrative(pool: PgPool) {
    // The lifecycle vocabulary has no `timeout` status: a run that times out is
    // recorded as `failed` with the reason. Proving the status name matters
    // would duplicate the state machine, so the invariant is proven against the
    // execution's *outcome* instead.
    let job = seed_job(&pool, JobStatus::Running).await;
    let execution_id =
        terminal_without_report(&pool, &job, "failed", "gitleaks timed out after 900s").await;

    raw_insert_narrative(&pool, &execution_id)
        .await
        .expect_err("a timed-out run has no deterministic report to explain");
    assert_eq!(count_narratives(&pool).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_queued_execution_is_not_even_a_representable_state(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let res = sqlx::query(
        "INSERT INTO audit_executions (id, job_id, attempt_number, status, started_at)
         VALUES ($1, $2, 1, 'queued', NOW())",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&job)
    .execute(&pool)
    .await;
    assert!(
        res.is_err(),
        "execution lifecycle vocabulary is enforced by the database, so 'queued' cannot exist"
    );

    // And the running state, the only pre-terminal one, is refused as well.
    let lease = begin_execution(&pool, &job).await.unwrap();
    raw_insert_narrative(&pool, &lease.execution_id)
        .await
        .expect_err("a running execution has no deterministic report to explain");
    assert_eq!(count_narratives(&pool).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn the_report_backstop_survives_deleting_the_report_row(pool: PgPool) {
    // Belt and braces: even if a report could be removed, the guard is evaluated
    // per insert, so the invariant is not a one-time check that rots.
    let job = seed_job(&pool, JobStatus::Running).await;
    let lease = finalized_with_narrative(&pool, &job, "frozen").await;

    let update =
        sqlx::query("UPDATE audit_reports SET report_json='{}'::jsonb WHERE execution_id=$1")
            .bind(&lease.execution_id)
            .execute(&pool)
            .await;
    assert!(update.is_err(), "the deterministic report stays immutable");

    let delete = sqlx::query("DELETE FROM audit_reports WHERE execution_id=$1")
        .bind(&lease.execution_id)
        .execute(&pool)
        .await;
    assert!(
        delete.is_err(),
        "the deterministic report stays undeletable"
    );

    assert!(
        load_ai_narrative(&pool, &job, Some(&lease.execution_id))
            .await
            .unwrap()
            .is_some(),
        "the narrative is still readable after the report is proven frozen"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_narrative_validated_for_another_attempt_cannot_be_persisted(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let first = begin_execution(&pool, &job).await.unwrap();
    let f1 = vec![secret_finding("cross-1")];
    finalize_execution(
        &pool,
        &first,
        &finalization_for(&first, &f1, &build_audit(&f1)),
    )
    .await
    .unwrap();

    let retry = begin_execution(&pool, &job).await.unwrap();
    let f2 = vec![secret_finding("cross-2")];
    finalize_execution(
        &pool,
        &retry,
        &finalization_for(&retry, &f2, &build_audit(&f2)),
    )
    .await
    .unwrap();
    let second_report = build_report(
        &reconstruct_report_source(&pool, &job, Some(&retry.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: retry.execution_id.clone(),
            attempt_number: retry.attempt_number,
        },
    )
    .unwrap();

    // A faithful explanation of attempt 2, offered to attempt 1.
    let res = persist_ai_narrative(
        &pool,
        &first.execution_id,
        &faithful_narrative(&second_report),
    )
    .await;
    assert!(
        res.is_err(),
        "a narrative validated against attempt 2 must not attach to attempt 1"
    );
    assert_eq!(count_narratives(&pool).await, 0);

    // Offered to its own execution, it is accepted.
    persist_ai_narrative(
        &pool,
        &retry.execution_id,
        &faithful_narrative(&second_report),
    )
    .await
    .expect("attempt 2's own narrative belongs to attempt 2");
    assert_eq!(count_narratives(&pool).await, 1);
    assert!(load_ai_narrative(&pool, &job, None)
        .await
        .unwrap()
        .is_some());
    assert!(load_ai_narrative(&pool, &job, Some(&first.execution_id))
        .await
        .unwrap()
        .is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn reconstruction_is_identical_with_and_without_a_narrative(pool: PgPool) {
    let job = seed_job(&pool, JobStatus::Running).await;
    let findings = vec![secret_finding("same")];
    let canonical = build_audit(&findings);
    let lease = begin_execution(&pool, &job).await.unwrap();
    finalize_execution(
        &pool,
        &lease,
        &finalization_for(&lease, &findings, &canonical),
    )
    .await
    .unwrap();

    let audit_without = reconstruct_latest_audit(&pool, &job)
        .await
        .unwrap()
        .unwrap();
    let report_without = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .unwrap();
    let findings_without: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();

    let report = build_report(
        &reconstruct_report_source(&pool, &job, Some(&lease.execution_id))
            .await
            .unwrap()
            .unwrap()
            .audit,
        &ExecutionIdentity {
            execution_id: lease.execution_id.clone(),
            attempt_number: lease.attempt_number,
        },
    )
    .unwrap();
    persist_ai_narrative(&pool, &lease.execution_id, &faithful_narrative(&report))
        .await
        .unwrap();

    let audit_with = reconstruct_latest_audit(&pool, &job)
        .await
        .unwrap()
        .unwrap();
    let report_with = load_stored_report(&pool, &job, None)
        .await
        .unwrap()
        .unwrap();
    let findings_with: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM findings WHERE job_id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(audit_without.canonical_json, audit_with.canonical_json);
    assert_eq!(audit_without.attempt_number, audit_with.attempt_number);
    assert_eq!(audit_without.finding_count, audit_with.finding_count);
    assert_eq!(audit_without.status, audit_with.status);
    assert_eq!(report_without.json, report_with.json);
    assert_eq!(report_without.markdown, report_with.markdown);
    assert_eq!(report_without.html, report_with.html);
    assert_eq!(
        report_without.report_schema_version,
        report_with.report_schema_version
    );
    assert_eq!(findings_without, findings_with);
}
