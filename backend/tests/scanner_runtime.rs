//! Phase 5 scanner-runtime tests: execute real security tools safely.
//!
//! Covers the four exhaustive outcomes — SUCCESS, FAILED, TIMEOUT, CANCELLED —
//! and the invariant that matters most: **scanner failure is never zero
//! findings**. Classification is exercised as a pure function, so no Docker or
//! scanner image is needed.

use firecrow_backend::agents::scanner::{
    classify, execute, run_secret_scan, ScanInput, Scanner, ScannerOutcome,
};
use firecrow_backend::error::AppError;
use firecrow_backend::services::sandbox::{ResourceLimits, SandboxManager, SandboxOutput};

fn gitleaks() -> Scanner {
    Scanner::gitleaks()
}

fn input() -> ScanInput {
    ScanInput {
        source_dir: std::env::temp_dir().join("firecrow-scanner-runtime-fixture"),
        commit_sha: Some("0123456789abcdef0123456789abcdef01234567".to_string()),
        file_count: 12,
        total_size: 4096,
    }
}

fn ok(stdout: &str) -> Result<SandboxOutput, AppError> {
    Ok(SandboxOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        success: true,
    })
}

fn nonzero_exit(stderr: &str) -> Result<SandboxOutput, AppError> {
    Ok(SandboxOutput {
        stdout: String::new(),
        stderr: stderr.to_string(),
        success: false,
    })
}

fn one_finding_report() -> String {
    r#"[{"RuleID":"aws-access-token","Description":"AWS Access Token","File":"aws.env","StartLine":3,"Secret":"AKIAIOSFODNN7EXAMPLE","Match":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}]"#.to_string()
}

// ---------------------------------------------------------------------------
// SUCCESS
// ---------------------------------------------------------------------------

#[test]
fn success_reports_the_scanners_own_count() {
    let result = classify(&gitleaks(), &input(), ok(&one_finding_report()));
    assert_eq!(result.outcome, ScannerOutcome::Success { finding_count: 1 });
    assert_eq!(result.findings.len(), 1);
    assert!(result.analyzed() && result.usable());
    assert_eq!(result.scanner, "gitleaks");
    assert_eq!(result.version, "8.18.4");
    assert_eq!(result.mode, "secret");
}

#[test]
fn a_clean_scan_is_success_with_zero_findings() {
    // The only outcome that may report a finding count of 0.
    for body in ["[]", "", "null"] {
        let result = classify(&gitleaks(), &input(), ok(body));
        assert_eq!(
            result.outcome,
            ScannerOutcome::Success { finding_count: 0 },
            "an empty successful report is success with 0 findings"
        );
        assert!(result.analyzed(), "a clean scan did analyze the tree");
        assert!(result.findings.is_empty());
    }
}

#[test]
fn successful_run_records_identity_limits_and_input() {
    let result = classify(&gitleaks(), &input(), ok(&one_finding_report()));
    let record = &result.execution_record;
    assert_eq!(record["scanner"], "gitleaks");
    assert_eq!(record["version"], "8.18.4");
    assert_eq!(record["mode"], "secret");
    assert_eq!(record["image"], "ghcr.io/gitleaks/gitleaks:v8.18.4");
    assert_eq!(record["parser"], "gitleaks-json-v1");
    assert_eq!(record["timeout_secs"], 300);
    assert_eq!(record["cpus"], 1.0);
    assert_eq!(record["memory"], "512m");
    assert_eq!(record["pids_limit"], 256);
    // The input snapshot travels with the record.
    assert_eq!(record["source_file_count"], 12);
    assert_eq!(record["source_total_size"], 4096);
    assert_eq!(record["finding_count"], 1);
}

// ---------------------------------------------------------------------------
// FAILED — and never zero findings
// ---------------------------------------------------------------------------

#[test]
fn non_zero_exit_is_failed_not_zero_findings() {
    let result = classify(
        &gitleaks(),
        &input(),
        nonzero_exit("panic: rule pack corrupt"),
    );
    assert!(
        matches!(result.outcome, ScannerOutcome::Failed { .. }),
        "a non-zero exit must be Failed: {:?}",
        result.outcome
    );
    assert!(!result.analyzed(), "a failed run did not analyze the tree");
    assert!(!result.usable(), "a failed run cannot produce a report");
    assert!(result.findings.is_empty());
    // The invariant, stated directly: no finding count is asserted.
    assert!(
        result.execution_record.get("finding_count").is_none(),
        "a failed scan must not carry a finding count"
    );
    assert_eq!(result.execution_record["coverage"], "unknown");
}

#[test]
fn unparseable_report_is_failed_not_zero_findings() {
    // The scanner exited 0 but its report is unreadable: coverage is unknown,
    // not clean. This is the case most likely to be mistaken for "no findings".
    for body in ["not json at all", "[{\"RuleID\":", "}{"] {
        let result = classify(&gitleaks(), &input(), ok(body));
        assert!(
            matches!(result.outcome, ScannerOutcome::Failed { .. }),
            "unparseable report {body:?} must be Failed: {:?}",
            result.outcome
        );
        assert!(!result.analyzed());
        assert!(result.execution_record.get("finding_count").is_none());
        assert_eq!(result.execution_record["coverage"], "unknown");
    }
}

#[test]
fn spawn_failure_is_failed() {
    let err = AppError::Internal("Failed to execute sandbox: docker not found".into());
    let result = classify(&gitleaks(), &input(), Err(err));
    assert!(matches!(result.outcome, ScannerOutcome::Failed { .. }));
    assert!(!result.usable());
    assert_eq!(result.execution_record["coverage"], "unknown");
}

// ---------------------------------------------------------------------------
// TIMEOUT
// ---------------------------------------------------------------------------

#[test]
fn timeout_is_its_own_outcome_and_not_failed() {
    let err = AppError::Timeout("Sandbox execution timed out after 300s".into());
    let result = classify(&gitleaks(), &input(), Err(err));
    assert_eq!(result.outcome, ScannerOutcome::Timeout { limit_secs: 300 });
    assert!(
        !matches!(result.outcome, ScannerOutcome::Failed { .. }),
        "a timeout must not be reported as a generic failure"
    );
    assert!(!result.analyzed());
    assert!(result.findings.is_empty());
    assert_eq!(result.execution_record["coverage"], "unknown");
    assert!(result.execution_record.get("finding_count").is_none());
    // The record names the ceiling that was exceeded, for the operator.
    assert!(result.execution_record["error"]
        .as_str()
        .unwrap()
        .contains("300s"));
}

// ---------------------------------------------------------------------------
// CANCELLED
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancelled_before_start_never_launches_the_scanner() {
    // Cancelled up front: no sandbox call can happen, and no finding count.
    let sandbox = SandboxManager::new();
    let result = run_secret_scan(&input(), &sandbox, &|| true).await;
    assert_eq!(result.outcome, ScannerOutcome::Cancelled);
    assert_eq!(result.outcome.as_str(), "cancelled");
    assert!(
        !result.analyzed(),
        "a cancelled scan did not analyze the tree"
    );
    assert!(!result.usable(), "a cancelled scan is not a report");
    assert!(result.findings.is_empty());
    assert_eq!(result.execution_record["coverage"], "unknown");
    assert!(result.execution_record.get("finding_count").is_none());
}

#[tokio::test]
async fn a_cancelled_scan_is_not_a_failed_scan() {
    let sandbox = SandboxManager::new();
    let cancelled = run_secret_scan(&input(), &sandbox, &|| true).await;
    assert!(matches!(cancelled.outcome, ScannerOutcome::Cancelled));
    assert!(
        !matches!(cancelled.outcome, ScannerOutcome::Failed { .. }),
        "cancellation must stay distinct from failure"
    );
}

// ---------------------------------------------------------------------------
// Descriptor completeness
// ---------------------------------------------------------------------------

#[test]
fn scanner_descriptor_carries_every_declared_field() {
    let s = Scanner::gitleaks();
    assert_eq!(s.name, "gitleaks");
    assert_eq!(s.version, "8.18.4");
    assert_eq!(s.mode, "secret");
    assert_eq!(s.image, "ghcr.io/gitleaks/gitleaks:v8.18.4");
    assert!(!s.image.contains("latest"), "the image must stay pinned");
    assert_eq!(s.parser, "gitleaks-json-v1");
    assert_eq!(s.timeout_secs, 300);
    assert_eq!(s.resource_limits, ResourceLimits::default());
    // The report is a file artifact on the scratch area, streamed back with
    // `cat`; stdout is only the pipe. Exit 1 is kept so gitleaks still
    // signals leaks-vs-clean — the parser, not the exit, decides success.
    assert_eq!(s.entrypoint, Some("sh"));
    assert_eq!(s.command.len(), 2);
    assert_eq!(s.command[0], "-c");
    let shell = &s.command[1];
    assert!(shell.contains("--source=/scan"), "shell: {shell}");
    assert!(
        shell.contains("--report-path=/work/gitleaks.json"),
        "shell: {shell}"
    );
    assert!(shell.contains("--exit-code=1"), "shell: {shell}");
    assert!(shell.contains("cat /work/gitleaks.json"), "shell: {shell}");
    assert_eq!(s.execution_key(), "gitleaks");
}

#[test]
fn input_is_mounted_read_only_at_the_expected_path() {
    let mounts = input().mounts();
    assert_eq!(mounts.len(), 1);
    assert!(
        mounts[0].read_only,
        "the scanner must never write to the tree"
    );
    assert_eq!(mounts[0].container_path, "/scan");
}

#[test]
fn resource_limits_render_to_docker_flags() {
    let limits = ResourceLimits {
        cpus: 2.0,
        memory: "1g".into(),
        pids_limit: 512,
    };
    assert_eq!(
        limits.as_docker_args(),
        vec!["--cpus=2", "-m=1g", "--memory-swap=1g", "--pids-limit=512"]
    );
    assert_eq!(
        ResourceLimits::default().as_docker_args(),
        vec![
            "--cpus=1",
            "-m=512m",
            "--memory-swap=512m",
            "--pids-limit=256"
        ]
    );
}

#[tokio::test]
async fn execute_returns_cancelled_without_touching_the_sandbox() {
    let sandbox = SandboxManager::new();
    let result = execute(&gitleaks(), &input(), &sandbox, &|| true).await;
    assert_eq!(result.outcome, ScannerOutcome::Cancelled);
}

// ---------------------------------------------------------------------------
// The invariant, end to end
// ---------------------------------------------------------------------------

#[test]
fn only_success_ever_carries_a_finding_count() {
    let runs: Vec<Result<SandboxOutput, AppError>> = vec![
        ok(&one_finding_report()),
        ok("[]"),
        nonzero_exit("boom"),
        ok("garbage"),
        Err(AppError::Timeout("t".into())),
        Err(AppError::Internal("spawn".into())),
    ];
    for run in runs {
        let result = classify(&gitleaks(), &input(), run);
        let has_count = result.execution_record.get("finding_count").is_some();
        assert_eq!(
            has_count,
            result.outcome.is_success(),
            "only a successful run may carry a finding count, got {:?}",
            result.outcome
        );
        if !result.outcome.is_success() {
            assert!(
                result.findings.is_empty(),
                "a non-successful run must carry no findings"
            );
            assert!(!result.analyzed());
        }
    }
}

#[test]
fn outcome_names_are_stable_for_persistence() {
    assert_eq!(
        ScannerOutcome::Success { finding_count: 0 }.as_str(),
        "success"
    );
    assert_eq!(
        ScannerOutcome::Failed { reason: "x".into() }.as_str(),
        "failed"
    );
    assert_eq!(
        ScannerOutcome::Timeout { limit_secs: 1 }.as_str(),
        "timeout"
    );
    assert_eq!(ScannerOutcome::Cancelled.as_str(), "cancelled");
}
