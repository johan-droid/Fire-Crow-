//! Scan-pipeline tests: T1 fixes, T2 fetch, T3 scanner, T4 scoring.
//!
//! Database-backed tests use `#[sqlx::test]` and seed rows before asserting, per
//! `TESTING.md`. Pure-function tests need no database.

mod support;

use firecrow_backend::models::{AuditJob, JobStatus, Severity};
use firecrow_backend::schemas::audit_state::Finding;
use firecrow_backend::services::reporter::ReportGenerator;
use sqlx::PgPool;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn audit_job_fixture() -> AuditJob {
    AuditJob {
        id: "job-1".into(),
        user_id: "user-1".into(),
        tenant_id: None,
        repo_url: "https://github.com/owner/repo".into(),
        repo_branch: "main".into(),
        status: JobStatus::Completed,
        created_at: chrono::Utc::now().naive_utc(),
        finished_at: None,
        cancel_requested: false,
        cancel_requested_at: None,
        report_pdf_url: None,
        report_id: None,
        error_message: None,
        security_score: Some(8.0),
        legal_hold: false,
    }
}

fn finding_with_evidence(evidence: &str) -> Finding {
    Finding {
        id: "f1".into(),
        agent_source: "gitleaks".into(),
        title: "Exposed secret".into(),
        description: "d".into(),
        severity: Severity::High,
        cvss_vector: None,
        cvss_score: None,
        evidence: Some(evidence.into()),
        remediation: None,
        cwe_id: None,
        owasp_category: None,
        confidence: Some("high".into()),
        scanner_name: Some("gitleaks".into()),
        scanner_mode: Some("secret".into()),
        file_path: Some("src/x.rs".into()),
        line_number: Some(1),
        route: None,
        metadata_json: None,
    }
}

// ---------------------------------------------------------------------------
// T1 — reporter: verbatim evidence in fences, n/a score
// ---------------------------------------------------------------------------

#[test]
fn evidence_in_a_fence_is_reproduced_verbatim() {
    let job = audit_job_fixture();
    let raw = "password=/etc/passwd <xml> & \"quoted\" 'a'";
    let md = ReportGenerator::generate_markdown(&job, &[finding_with_evidence(raw)], Some(8.0))
        .expect("report");

    assert!(
        md.contains(raw),
        "evidence inside a code fence must be verbatim; got:\n{md}"
    );
    assert!(!md.contains("&lt;"), "evidence must not be HTML-escaped");
    assert!(!md.contains("&#x2F;"), "evidence must not escape '/'");
}

#[test]
fn triple_backticks_in_evidence_cannot_close_the_fence() {
    let job = audit_job_fixture();
    let raw = "line1\n```\n# not a fence\n```\nline2";
    let md = ReportGenerator::generate_markdown(&job, &[finding_with_evidence(raw)], None)
        .expect("report");

    // The raw triple-backtick run must have been broken.
    assert!(
        !md.contains("```\n# not a fence"),
        "a ``` run in evidence must be neutralized; got:\n{md}"
    );
}

#[test]
fn null_score_renders_as_na() {
    let job = audit_job_fixture();
    let md = ReportGenerator::generate_markdown(&job, &[], None).expect("report");
    assert!(
        md.contains("Security Score: n/a"),
        "a null score must render as n/a: {md}"
    );
    assert!(!md.contains("10.0/10"), "must not invent a perfect score");
}

// ---------------------------------------------------------------------------
// T4 — scoring
// ---------------------------------------------------------------------------

#[test]
fn scanner_failure_yields_a_null_score() {
    assert_eq!(firecrow_backend::orchestrator::score_scan(false, 0), None);
    assert_eq!(firecrow_backend::orchestrator::score_scan(false, 4), None);
    let summary = firecrow_backend::orchestrator::risk_summary(false, 0);
    assert!(summary["score"].is_null());
    assert_eq!(summary["analysis_performed"], false);
}

#[test]
fn clean_scan_yields_a_real_score_and_says_analysis_ran() {
    let score = firecrow_backend::orchestrator::score_scan(true, 0).expect("a real score");
    assert!(
        score > 0.0 && score < 10.0,
        "a clean scan is a real score, never a perfect 10/10: {score}"
    );
    let summary = firecrow_backend::orchestrator::risk_summary(true, 0);
    assert_eq!(summary["analysis_performed"], true);
    assert!(summary["score"].as_f64().is_some());
}

#[test]
fn findings_missing_evidence_location_are_rejected_before_persist() {
    use firecrow_backend::orchestrator::prepare_findings_for_persist;

    let scanner_finding = finding_with_evidence("AWS_ACCESS_KEY_ID=[REDACTED]");
    let mut without_file = scanner_finding.clone();
    without_file.file_path = None;
    let mut without_line = scanner_finding.clone();
    without_line.line_number = None;
    let mut without_evidence = scanner_finding.clone();
    without_evidence.evidence = Some("   ".into());

    let prepared = prepare_findings_for_persist(vec![
        scanner_finding,
        without_file,
        without_line,
        without_evidence,
    ]);
    assert_eq!(prepared.raw_count, 4);
    assert_eq!(prepared.dropped_count, 3);
    assert_eq!(prepared.valid.len(), 1);
    assert!(prepared.valid[0]
        .evidence
        .as_deref()
        .unwrap()
        .contains("[REDACTED]"));
}

// ---------------------------------------------------------------------------
// T3 — gitleaks parsing and redaction
// ---------------------------------------------------------------------------

use firecrow_backend::agents::scanner::{finding_from_gitleaks, parse_gitleaks_report};

/// A fixture repository containing one planted fake secret on a known line
/// yields exactly one finding carrying that file and line, with the secret value
/// redacted in the evidence.
#[test]
fn fixture_repo_secret_yields_one_redacted_finding() {
    let dir = std::env::temp_dir().join(format!("fc-fixture-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = "AKIAIOSFODNN7EXAMPLE";
    // The secret sits on the third line of the file.
    let content = format!("# fixture repository\n\nAWS_ACCESS_KEY_ID={secret}\n");
    std::fs::write(dir.join("aws.env"), &content).unwrap();

    // The report gitleaks would emit for that file (1-based StartLine).
    let report = format!(
        r#"[{{"RuleID":"aws-access-token","Description":"AWS Access Token","File":"aws.env","StartLine":3,"Secret":"{secret}","Match":"AWS_ACCESS_KEY_ID={secret}"}}]"#
    );

    let parsed = parse_gitleaks_report(&report).expect("valid report");
    assert_eq!(parsed.len(), 1, "exactly one finding expected");

    let f = finding_from_gitleaks(&parsed[0]);
    assert_eq!(f.file_path.as_deref(), Some("aws.env"));
    assert_eq!(f.line_number, Some(3));

    // The fixture really does hold the secret on line 3.
    let on_disk = std::fs::read_to_string(dir.join("aws.env")).unwrap();
    assert!(on_disk.lines().nth(2).unwrap().contains(secret));

    let evidence = f.evidence.expect("evidence snippet");
    assert!(
        !evidence.contains(secret),
        "the secret value must be redacted: {evidence}"
    );
    assert!(
        evidence.contains("[REDACTED]"),
        "the snippet must show the redaction: {evidence}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unparseable_report_is_an_error() {
    assert!(parse_gitleaks_report("not json at all").is_err());
}

#[test]
fn empty_report_means_no_findings() {
    assert!(parse_gitleaks_report("").unwrap().is_empty());
    assert!(parse_gitleaks_report("null").unwrap().is_empty());
    assert!(parse_gitleaks_report("[]").unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// T2 — fetch: bounded, symlink-free extraction and cleanup
// ---------------------------------------------------------------------------

use firecrow_backend::agents::fetch::{extract_tarball, fetch_repo, MAX_FILE_BYTES};
use std::collections::HashSet;
use std::path::PathBuf;

fn scratch_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Minimal ustar header. The parser does not verify the checksum, so it is left
/// unset here.
fn tar_header(name: &str, typeflag: u8, size: usize) -> [u8; 512] {
    let mut h = [0u8; 512];
    let n = name.len().min(100);
    h[..n].copy_from_slice(&name.as_bytes()[..n]);
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    let size_field = format!("{:011o}\0", size);
    h[124..136].copy_from_slice(size_field.as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[148..156].copy_from_slice(b"        ");
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h
}

fn tar_entry(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = tar_header(name, typeflag, data.len()).to_vec();
    out.extend_from_slice(data);
    let pad = (512 - (data.len() % 512)) % 512;
    out.extend(std::iter::repeat(0u8).take(pad));
    out
}

fn gzify(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[test]
fn traversal_entry_is_rejected() {
    let dir = scratch_dir("fc-trav");
    let mut tar = tar_entry("pkg/../../evil.txt", b'0', b"x");
    tar.extend(tar_entry("pkg/ok.txt", b'0', b"ok"));
    assert!(
        extract_tarball(&gzify(&tar), &dir).is_err(),
        "a .. member must be rejected"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn absolute_path_entry_is_rejected() {
    let dir = scratch_dir("fc-abs");
    assert!(extract_tarball(&gzify(&tar_entry("/etc/evil", b'0', b"x")), &dir).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn symlink_entry_is_rejected() {
    let dir = scratch_dir("fc-sym");
    assert!(
        extract_tarball(&gzify(&tar_entry("link", b'2', b"../../etc/passwd")), &dir).is_err(),
        "a symlink member must be rejected"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hardlink_entry_is_rejected() {
    let dir = scratch_dir("fc-hard");
    assert!(extract_tarball(&gzify(&tar_entry("hard", b'1', b"target")), &dir).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversize_file_is_rejected() {
    let dir = scratch_dir("fc-big");
    let big = vec![0u8; (MAX_FILE_BYTES + 1) as usize];
    assert!(
        extract_tarball(&gzify(&tar_entry("pkg/big.bin", b'0', &big)), &dir).is_err(),
        "a file over MAX_FILE_BYTES must be rejected"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_valid_archive_extracts() {
    let dir = scratch_dir("fc-ok");
    let mut tar = tar_entry("pkg/src/main.rs", b'0', b"fn main() {}");
    tar.extend(tar_entry("pkg/README.md", b'0', b"# hi"));
    extract_tarball(&gzify(&tar), &dir).expect("valid archive extracts");
    let body = std::fs::read_to_string(dir.join("pkg/src/main.rs")).unwrap();
    assert_eq!(body, "fn main() {}");
    let _ = std::fs::remove_dir_all(&dir);
}

fn scan_temp_dirs() -> HashSet<PathBuf> {
    std::fs::read_dir(std::env::temp_dir())
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("firecrow-scan-"))
                .unwrap_or(false)
        })
        .collect()
}

#[tokio::test]
async fn temp_dir_is_removed_when_fetch_fails() {
    let before = scan_temp_dirs();
    // Parses as a GitHub URL but the repository does not exist / is unreachable,
    // so the fetch fails after the temp dir has been created.
    let result = fetch_repo(
        "https://github.com/firecrow-nonexistent-owner/nope",
        "main",
        "",
    )
    .await;
    assert!(result.is_err(), "fetch of a nonexistent repo must fail");

    let after = scan_temp_dirs();
    let leaked: Vec<_> = after.difference(&before).collect();
    assert!(
        leaked.is_empty(),
        "the temp scan dir must be removed on error: {leaked:?}"
    );
}

// ---------------------------------------------------------------------------
// T1 — API and lifecycle
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn email_report_returns_501_when_smtp_is_unconfigured(pool: PgPool) {
    let user = support::seed_user(&pool, "email501").await;
    let job = support::seed_job(&pool, &user.id, "completed").await;
    let app = support::test_app(pool.clone()).await;

    let res = app
        .post(&format!("/api/v1/audit/job/{job}/email"))
        .add_header("authorization", user.auth_header())
        .await;
    assert_eq!(
        res.status_code(),
        501,
        "with no SMTP configured the server must not claim the email was queued"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn submit_rejects_non_github_repository_urls(pool: PgPool) {
    let user = support::seed_user(&pool, "urls").await;
    let app = support::test_app(pool.clone()).await;

    for bad in [
        "file:///etc/passwd",
        "ssh://git@github.com/owner/repo.git",
        "git@github.com:owner/repo.git",
        "https://gitlab.com/owner/repo",
        "https://evil.example.com/owner/repo",
        "https://github.com/owner/..",
        "https://github.com/owner/repo/extra",
    ] {
        let res = app
            .post("/api/v1/audit/submit")
            .add_header("authorization", user.auth_header())
            .json(&serde_json::json!({ "repo_url": bad }))
            .await;
        assert_eq!(res.status_code(), 400, "must reject {bad}");
    }

    let ok = app
        .post("/api/v1/audit/submit")
        .add_header("authorization", user.auth_header())
        .json(&serde_json::json!({ "repo_url": "https://github.com/owner/repo" }))
        .await;
    assert_eq!(ok.status_code(), 200, "a valid GitHub URL must be accepted");
}

#[sqlx::test(migrations = "./migrations")]
async fn cancelled_running_job_ends_cancelled(pool: PgPool) {
    let user = support::seed_user(&pool, "cancel").await;
    let repo = "https://github.com/owner/repo";
    let job = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO audit_jobs (id, user_id, repo_url, status, cancel_requested, cancel_requested_at, legal_hold, created_at)
         VALUES ($1,$2,$3,'running',true,NOW(),false,NOW())",
    )
    .bind(&job)
    .bind(&user.id)
    .bind(repo)
    .execute(&pool)
    .await
    .unwrap();

    firecrow_backend::orchestrator::execute_audit_job(
        &pool, &job, &user.id, repo, "main", None, None,
    )
    .await
    .expect("orchestrator must not error");

    let (status,): (String,) = sqlx::query_as("SELECT status FROM audit_jobs WHERE id=$1")
        .bind(&job)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        status, "cancelled",
        "a cancellation is its own terminal outcome, never a failure"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn late_failure_does_not_overwrite_a_completed_job(pool: PgPool) {
    let user = support::seed_user(&pool, "late").await;
    let job = support::seed_job(&pool, &user.id, "completed").await;
    sqlx::query("UPDATE audit_jobs SET security_score=7.5 WHERE id=$1")
        .bind(&job)
        .execute(&pool)
        .await
        .unwrap();

    // The worker path. The job is already terminal, so nothing may flip it.
    firecrow_backend::workers::run_audit_job(
        &pool,
        &job,
        &user.id,
        "https://gitlab.com/owner/repo",
        "main",
        None,
    )
    .await;

    let (status, score, err): (String, Option<f64>, Option<String>) =
        sqlx::query_as("SELECT status, security_score, error_message FROM audit_jobs WHERE id=$1")
            .bind(&job)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        status, "completed",
        "a terminal status must never be overwritten"
    );
    assert_eq!(score, Some(7.5), "the recorded score must survive");
    assert!(
        err.is_none(),
        "a late failure must not attach an error to a finished job"
    );
}

// ---------------------------------------------------------------------------
// End-to-end (requires Docker and network to pull the gitleaks image)
// ---------------------------------------------------------------------------

/// Proves the whole scan phase: a fixture repository with a planted secret,
/// scanned by the real gitleaks in the hardened sandbox, yields exactly one
/// finding that carries a repo-relative file, a line, and redacted evidence.
///
/// Ignored by default because it needs Docker and the gitleaks image. Run with:
/// `cargo test --test scan_pipeline -- --ignored`.
#[tokio::test]
#[ignore]
async fn e2e_real_gitleaks_scan_finds_and_redacts() {
    let dir = std::env::temp_dir().join(format!("fc-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let secret = "AKIAIOSFODNN7EXAMPLE";
    std::fs::write(dir.join("aws.env"), format!("AWS_ACCESS_KEY_ID={secret}\n")).unwrap();

    let sandbox = firecrow_backend::services::sandbox::SandboxManager::new("", "");
    let outcome = firecrow_backend::agents::scanner::run_secret_scan(&dir, &sandbox).await;

    assert!(
        !outcome.failed,
        "scan must not fail: {:?}",
        outcome.scanner_execution
    );
    assert_eq!(outcome.findings.len(), 1, "exactly one secret expected");

    let f = &outcome.findings[0];
    assert_eq!(f.file_path.as_deref(), Some("aws.env"));
    assert_eq!(f.line_number, Some(1));
    let evidence = f.evidence.clone().unwrap_or_default();
    assert!(
        !evidence.contains(secret),
        "the secret value must be redacted: {evidence}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[sqlx::test(migrations = "./migrations")]
async fn re_running_findings_persist_is_idempotent(pool: PgPool) {
    use firecrow_backend::orchestrator::{load_findings, persist_findings};

    let user = support::seed_user(&pool, "persist-idem").await;
    let job = support::seed_job(&pool, &user.id, "running").await;

    let scanner_finding = finding_with_evidence("AWS_ACCESS_KEY_ID=[REDACTED]");
    let mut duplicate = scanner_finding.clone();
    duplicate.id = format!("{}-dup", scanner_finding.id);

    let stored = persist_findings(&pool, &job, &[scanner_finding.clone(), duplicate])
        .await
        .expect("persist findings");
    assert_eq!(stored, 2);

    // Re-running with one of the original findings treats it as an update and
    // removes the other row, so the table ends with the same single finding.
    let stored = persist_findings(&pool, &job, std::slice::from_ref(&scanner_finding))
        .await
        .expect("persist findings again");
    assert_eq!(stored, 1);

    let rows = load_findings(&pool, &job).await.expect("load findings");
    assert_eq!(
        rows.len(),
        1,
        "exactly the requested findings may be stored"
    );
    assert_eq!(rows[0].id, scanner_finding.id);
    assert_eq!(rows[0].file_path.as_deref(), Some("src/x.rs"));
    let line_number: Option<i32> = rows[0].line_number;
    assert_eq!(line_number, Some(1));
    assert!(rows[0].evidence.as_deref().unwrap().contains("[REDACTED]"));
}
