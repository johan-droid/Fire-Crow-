//! Phase 20: live end-to-end audit of a deliberately vulnerable repository.
//!
//! Everything here is real: a real Docker sandbox, the pinned real Gitleaks
//! image, a real repository tree on disk containing real detectable secrets.
//! No mock scanner, no stand-in fixture.
//!
//! The point is to prove the deterministic chain still works end to end
//! against the actual tool:
//!
//! ```text
//!   vulnerable tree → sandboxed Gitleaks → canonical Finding
//!      → Canonical Audit v1 → deterministic report → persisted execution
//! ```
//!
//! Requires Docker with the pinned image present. Without Docker the tests
//! skip: "the sandbox could not start" is an environment fact, not a
//! security regression.

mod support;

use firecrow_backend::agents::scanner::{execute, ScanInput, Scanner, ScannerOutcome};
use firecrow_backend::orchestrator::canonical_audit::{
    canonical_audit, normalize_findings_for_persist, CanonicalAuditRequest,
};
use firecrow_backend::services::sandbox::SandboxManager;
use sqlx::PgPool;
use std::path::{Path, PathBuf};

/// A real AWS example key and a real-shaped GitHub PAT, planted on purpose.
const PLANTED_AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const PLANTED_GITHUB_PAT: &str = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// A repository tree with deliberately planted, detectable secrets.
fn vulnerable_tree(root: &Path) {
    std::fs::create_dir_all(root.join("src")).expect("tree");
    std::fs::write(
        root.join("src/config.js"),
        format!(
            "const AWS_ACCESS_KEY_ID = '{PLANTED_AWS_KEY}';\n\
             const GITHUB_TOKEN = '{PLANTED_GITHUB_PAT}';\n"
        ),
    )
    .expect("write config");
    std::fs::write(
        root.join(".env"),
        "DB_PASSWORD=SuperSecret123!\nSTRIPE_KEY=sk_live_51H8xYz2eZvKYlo2C\n",
    )
    .expect("write env");
    std::fs::write(root.join("README.md"), "# vulnerable fixture\n").expect("write readme");
}

fn temp_root(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("firecrow-p20-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

async fn run_gitleaks(root: &Path) -> firecrow_backend::agents::scanner::ScannerResult {
    let sandbox = SandboxManager::new();
    let input = ScanInput::from_dir(root);
    execute(&Scanner::gitleaks(), &input, &sandbox, &|| false).await
}

/// Build the canonical audit and deterministic report from a live scan, using
/// exactly the pipeline's own steps.
fn build_report(
    result: &firecrow_backend::agents::scanner::ScannerResult,
    normalized: &[firecrow_backend::schemas::audit_state::Finding],
) -> (
    firecrow_backend::schemas::report::CanonicalAuditReport,
    String,
) {
    let results = [result.clone()];
    let snapshot_commit = "0".repeat(40);
    let request = CanonicalAuditRequest {
        scan_id: "live-p20",
        repository_url: "https://github.com/acme/vulnerable",
        repo_branch: "main",
        repo_owner: "acme",
        repo_name: "vulnerable",
        snapshot_commit: Some(snapshot_commit.as_str()),
        snapshot_file_count: 3,
        snapshot_total_size: 1024,
        results: &results,
        findings: normalized,
        security_score: Some(7.5),
    };
    let audit = canonical_audit(&request).expect("canonical audit from live findings");
    let execution = firecrow_backend::schemas::report::ExecutionIdentity {
        execution_id: "live-exec".into(),
        attempt_number: 1,
    };
    let report =
        firecrow_backend::schemas::report::build_report(&audit, &execution).expect("report model");
    let markdown = firecrow_backend::services::reporter::ReportGenerator::render_markdown(&report)
        .expect("deterministic markdown");
    (report, markdown)
}

/// The full live chain: planted secrets → real scan → canonical audit →
/// deterministic report, with nothing redacted away and nothing faked.
#[tokio::test]
async fn live_audit_of_a_vulnerable_repository_produces_findings_and_a_report() {
    if !docker_available() {
        eprintln!("skipping: Docker unavailable");
        return;
    }
    let root = temp_root("vuln");
    vulnerable_tree(&root);

    let result = run_gitleaks(&root).await;
    let _ = std::fs::remove_dir_all(&root);

    // Surfaced so `--nocapture` proves a real container scan happened:
    // scanner, outcome, and how many findings the live tool reported.
    eprintln!(
        "live gitleaks: scanner={} outcome={:?} findings={}",
        result.scanner,
        result.outcome,
        result.findings.len()
    );

    assert!(
        matches!(result.outcome, ScannerOutcome::Success { .. }),
        "the live scan must succeed against a scannable tree, got: {:?}",
        result.outcome
    );
    assert!(
        !result.findings.is_empty(),
        "a tree with planted AWS/GitHub/DB credentials must yield findings"
    );

    // Every detected secret is redacted before it becomes a Finding.
    for finding in &result.findings {
        let evidence = finding.evidence.clone().unwrap_or_default();
        assert!(
            !evidence.contains(PLANTED_AWS_KEY),
            "a live detected key must never appear in evidence: {evidence}"
        );
        assert!(
            !evidence.contains(PLANTED_GITHUB_PAT),
            "a live detected token must never appear in evidence: {evidence}"
        );
        assert!(
            evidence.contains("[REDACTED]") || evidence.contains("[BASE64_REDACTED]"),
            "live secret evidence must carry a redaction marker: {evidence}"
        );
    }

    // The findings survive canonical validation as real canonical facts.
    let normalized = normalize_findings_for_persist(result.findings.clone());
    assert!(
        !normalized.valid.is_empty(),
        "live findings must pass canonical validation; quarantined: {:?}",
        normalized.invalid
    );

    let (report, markdown) = build_report(&result, &normalized.valid);
    assert!(
        !report.findings.is_empty(),
        "the deterministic report must carry the live findings"
    );
    assert!(!markdown.is_empty());
    assert!(
        markdown.contains("FireCrow Security Audit Report"),
        "unexpected report shape"
    );

    // Deterministic: identical inputs render byte-identical reports.
    let (_, again) = build_report(&result, &normalized.valid);
    assert_eq!(
        markdown, again,
        "the deterministic report must be reproducible"
    );
}

/// A clean repository must scan clean — the other half of "never fake clean".
#[tokio::test]
async fn live_scan_of_a_clean_tree_reports_no_findings() {
    if !docker_available() {
        eprintln!("skipping: Docker unavailable");
        return;
    }
    let root = temp_root("clean");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/main.py"),
        "def add(a, b):\n    return a + b\n",
    )
    .unwrap();
    std::fs::write(root.join("README.md"), "# clean fixture\n").unwrap();

    let result = run_gitleaks(&root).await;
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        matches!(result.outcome, ScannerOutcome::Success { .. }),
        "a clean tree is a successful scan, not a failure: {:?}",
        result.outcome
    );
    assert!(
        result.findings.is_empty(),
        "a clean tree must yield no findings, got {}",
        result.findings.len()
    );
}

/// The sandbox is a real boundary: the scan cannot modify the host tree.
#[tokio::test]
async fn live_scan_leaves_the_host_tree_unmodified() {
    if !docker_available() {
        eprintln!("skipping: Docker unavailable");
        return;
    }
    let root = temp_root("immutable");
    vulnerable_tree(&root);
    let before = std::fs::read(root.join("src/config.js")).expect("read fixture");

    let _ = run_gitleaks(&root).await;

    let after = std::fs::read(root.join("src/config.js")).expect("read fixture again");
    assert_eq!(
        before, after,
        "a sandboxed scan must not modify the host repository tree"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The live chain persists, and the whole audit is reconstructible from
/// PostgreSQL alone — with no live secret anywhere in the database.
#[sqlx::test(migrations = "./migrations")]
async fn live_findings_persist_and_carry_no_live_secret(pool: PgPool) {
    use firecrow_backend::orchestrator::execution::{
        begin_execution, finalize_execution, Finalization, ScannerRunRecord,
    };

    let user = support::seed_user(&pool, "live").await;
    let job = support::seed_job(&pool, &user.id, "running").await;
    let lease = begin_execution(&pool, &job).await.expect("execution opens");

    let root = temp_root("persist");
    vulnerable_tree(&root);
    let result = run_gitleaks(&root).await;
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        matches!(result.outcome, ScannerOutcome::Success { .. }),
        "live scan failed: {:?}",
        result.outcome
    );
    assert!(!result.findings.is_empty());

    let normalized = normalize_findings_for_persist(result.findings.clone());
    let (report, markdown) = build_report(&result, &normalized.valid);
    let finalization = Finalization {
        findings: normalized.valid.clone(),
        scanner_runs: vec![ScannerRunRecord {
            scanner: result.scanner.clone(),
            version: result.version.clone(),
            parser: "gitleaks".into(),
            mode: result.mode.clone(),
            image: "ghcr.io/gitleaks/gitleaks:v8.18.4".into(),
            status: "success".into(),
            finding_count: Some(result.findings.len() as i32),
            coverage_known: true,
            detail: None,
            limitations: Vec::new(),
        }],
        coverage_status: "complete".into(),
        coverage_complete: true,
        coverage_limitations: Vec::new(),
        summary: None,
        canonical_json: serde_json::to_value(&report).ok(),
        report_markdown: Some(markdown.clone()),
        report_json: serde_json::to_value(&report).ok(),
        report_html: None,
        security_score: Some(7.5),
        job_status: "completed".into(),
        failure_reason: None,
    };
    finalize_execution(&pool, &lease, &finalization)
        .await
        .expect("finalize with live findings");

    // Reconstruct from the database alone.
    let execution = lease.execution_id.clone();
    let stored: (String,) =
        sqlx::query_as("SELECT canonical_json::text FROM audit_executions WHERE id=$1")
            .bind(&execution)
            .fetch_one(&pool)
            .await
            .expect("canonical json persisted");
    assert!(stored.0.contains("findings"));

    let report_md: (Option<String>,) =
        sqlx::query_as("SELECT markdown_content FROM audit_reports WHERE execution_id=$1")
            .bind(&execution)
            .fetch_one(&pool)
            .await
            .expect("report persisted");
    assert_eq!(
        report_md.0.as_deref(),
        Some(markdown.as_str()),
        "the persisted report must equal the deterministic one"
    );

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM findings WHERE execution_id=$1")
        .bind(&execution)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count.0, normalized.valid.len() as i64);

    // The database holds no live secret — not in evidence, not in the report.
    let evidence: Vec<(Option<String>,)> =
        sqlx::query_as("SELECT evidence FROM findings WHERE execution_id=$1")
            .bind(&execution)
            .fetch_all(&pool)
            .await
            .unwrap();
    for (evidence,) in &evidence {
        let evidence = evidence.clone().unwrap_or_default();
        assert!(
            !evidence.contains(PLANTED_AWS_KEY) && !evidence.contains(PLANTED_GITHUB_PAT),
            "a live secret reached the database: {evidence}"
        );
    }
    assert!(!markdown.contains(PLANTED_AWS_KEY));
    assert!(!markdown.contains(PLANTED_GITHUB_PAT));
    assert!(!stored.0.contains(PLANTED_AWS_KEY));
}
