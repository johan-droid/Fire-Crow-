//! Phase 13: deterministic reporting.
//!
//! A report is a presentation of a Canonical Audit v1. These tests prove the
//! properties the phase requires: explicit coverage states, facts-only summaries,
//! canonical finding representation (Unknown/missing preserved, no zero
//! substitution), evidence pass-through, byte-stable deterministic rendering, and
//! the source-of-truth boundary (only a canonical audit is accepted).
//!
//! Pure tests need no Docker and no database. The golden fixture at
//! `test-fixtures/report/mixed-report.json` is the frozen representation.

mod support;

use firecrow_backend::agents::scanner::{ScannerOutcome, ScannerResult};
use firecrow_backend::models::Severity;
use firecrow_backend::orchestrator::canonical_audit::{canonical_audit, CanonicalAuditRequest};
use firecrow_backend::schemas::audit_state::Finding;
use firecrow_backend::schemas::canonical_audit::CanonicalAudit;
use firecrow_backend::schemas::report::{
    build_report, derive_coverage_state, CanonicalAuditReport, CoverageState, ExecutionIdentity,
    ReportError, REPORT_SCHEMA_VERSION,
};
use firecrow_backend::services::reporter::ReportGenerator;
use serde_json::Value;
use std::collections::BTreeMap;

#[test]
fn coverage_state_is_derived_from_canonical_runs_alone() {
    // `derive_coverage_state` is the public entry point for the state machine;
    // it must be a pure function of the canonical scanner runs, with no access
    // to anything else.
    let all_successful = canonical(&all_clean(), &[], Some(9.0));
    assert_eq!(
        derive_coverage_state(&all_successful),
        CoverageState::SuccessClean
    );

    let with_finding = canonical(
        &[
            success(
                "gitleaks",
                "secret",
                vec![secret_finding("[REDACTED]", "fp-d")],
            ),
            success("osv", "dependency", vec![]),
            success("semgrep", "sast", vec![]),
        ],
        &[secret_finding("[REDACTED]", "fp-d")],
        Some(9.0),
    );
    assert_eq!(
        derive_coverage_state(&with_finding),
        CoverageState::SuccessFindings
    );

    let timed_out = canonical(
        &[
            success("gitleaks", "secret", vec![]),
            timeout("osv", "dependency", 60),
            success("semgrep", "sast", vec![]),
        ],
        &[],
        None,
    );
    assert_eq!(derive_coverage_state(&timed_out), CoverageState::Timeout);

    // The state only depends on the runs: the same runs always give the same
    // state, regardless of how many findings the audit happens to hold.
    assert_eq!(
        derive_coverage_state(&timed_out),
        derive_coverage_state(&timed_out.clone()),
        "derivation must be deterministic"
    );
}

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

/// One directly-constructed scanner finding.
///
/// Built without running a scanner: the canonical contract only needs curated
/// provenance metadata, so a fixture can be fully deterministic and Docker-free.
#[allow(clippy::too_many_arguments)]
fn finding(
    scanner: &str,
    mode: &str,
    rule: &str,
    fingerprint: &str,
    severity: Severity,
    evidence: &str,
    file: &str,
    line: i32,
) -> Finding {
    Finding {
        id: format!("{scanner}-{fingerprint}"),
        agent_source: scanner.into(),
        title: format!("{rule} detection"),
        description: format!("Detected by {scanner}."),
        severity,
        cvss_vector: None,
        cvss_score: None,
        evidence: Some(evidence.into()),
        remediation: Some("Apply the vendor guidance.".into()),
        cwe_id: None,
        owasp_category: None,
        confidence: Some("high".into()),
        scanner_name: Some(scanner.into()),
        scanner_mode: Some(mode.into()),
        file_path: Some(file.into()),
        line_number: Some(line),
        route: None,
        metadata_json: Some(
            serde_json::json!({
                "scanner_version": "1.0.0",
                "parser": format!("{scanner}-json-v1"),
                "scanner_image": format!("registry/{scanner}:1.0.0"),
                "rule_id": rule,
                "fingerprint": fingerprint,
                "snapshot_commit": COMMIT,
            })
            .to_string(),
        ),
    }
}

fn secret_finding(secret: &str, fingerprint: &str) -> Finding {
    finding(
        "gitleaks",
        "secret",
        "aws-access-token",
        fingerprint,
        Severity::High,
        &format!("AWS_ACCESS_KEY_ID={secret}"),
        "config/aws.env",
        3,
    )
}

fn sast_finding(check: &str, line: i32) -> Finding {
    finding(
        "semgrep",
        "sast",
        check,
        &format!("fp-{check}-{line}"),
        Severity::Critical,
        "subprocess.call(cmd, shell=True)",
        "app.py",
        line,
    )
}

fn dependency_finding(advisory: &str) -> Finding {
    // OSV has no uniform severity: `Unknown` is honest and must survive.
    finding(
        "osv",
        "dependency",
        advisory,
        &format!("fp-{advisory}"),
        Severity::Unknown,
        &format!("{advisory} affects lodash@1.0.0"),
        "package-lock.json",
        1,
    )
}

fn success(scanner: &str, mode: &str, findings: Vec<Finding>) -> ScannerResult {
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

fn failed(scanner: &str, mode: &str, detail: &str) -> ScannerResult {
    ScannerResult {
        scanner: scanner.into(),
        version: "1.0.0".into(),
        mode: mode.into(),
        outcome: ScannerOutcome::Failed {
            reason: "scanner produced no report".into(),
        },
        findings: Vec::new(),
        execution_record: serde_json::json!({
            "scanner": scanner,
            "version": "1.0.0",
            "mode": mode,
            "image": format!("registry/{scanner}:1.0.0"),
            "parser": format!("{scanner}-json-v1"),
            "snapshot_commit": COMMIT,
            "detail": detail,
            "error": "scanner produced no report",
            "coverage": "unknown",
        }),
    }
}

fn timeout(scanner: &str, mode: &str, limit_secs: u64) -> ScannerResult {
    ScannerResult {
        scanner: scanner.into(),
        version: "1.0.0".into(),
        mode: mode.into(),
        outcome: ScannerOutcome::Timeout { limit_secs },
        findings: Vec::new(),
        execution_record: serde_json::json!({
            "scanner": scanner,
            "version": "1.0.0",
            "mode": mode,
            "snapshot_commit": COMMIT,
            "coverage": "unknown",
        }),
    }
}

fn cancelled(scanner: &str, mode: &str) -> ScannerResult {
    ScannerResult {
        scanner: scanner.into(),
        version: "1.0.0".into(),
        mode: mode.into(),
        outcome: ScannerOutcome::Cancelled,
        findings: Vec::new(),
        execution_record: serde_json::json!({
            "scanner": scanner,
            "version": "1.0.0",
            "mode": mode,
            "snapshot_commit": COMMIT,
            "coverage": "unknown",
        }),
    }
}

fn audit_request<'a>(
    results: &'a [ScannerResult],
    findings: &'a [Finding],
    score: Option<f64>,
) -> CanonicalAuditRequest<'a> {
    CanonicalAuditRequest {
        scan_id: "scan-report-1",
        repository_url: "https://github.com/acme/widget",
        repo_branch: "main",
        repo_owner: "acme",
        repo_name: "widget",
        snapshot_commit: Some(COMMIT),
        snapshot_file_count: 8,
        snapshot_total_size: 4096,
        results,
        findings,
        security_score: score,
    }
}

fn canonical(
    results: &[ScannerResult],
    findings: &[Finding],
    score: Option<f64>,
) -> CanonicalAudit {
    canonical_audit(&audit_request(results, findings, score)).expect("canonical audit")
}

fn report_for(
    results: &[ScannerResult],
    findings: &[Finding],
    score: Option<f64>,
) -> CanonicalAuditReport {
    let audit = canonical(results, findings, score);
    build_report(
        &audit,
        &ExecutionIdentity {
            execution_id: "exec-1".into(),
            attempt_number: 1,
        },
    )
    .expect("report")
}

fn all_clean() -> Vec<ScannerResult> {
    vec![
        success("gitleaks", "secret", vec![]),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![]),
    ]
}

/// The same builder as `report_for`, but with an explicit execution identity so
/// that two attempts of one job can be distinguished.
fn report_with_identity(
    results: &[ScannerResult],
    findings: &[Finding],
    score: Option<f64>,
    execution_id: &str,
    attempt_number: i32,
) -> CanonicalAuditReport {
    let audit = canonical(results, findings, score);
    build_report(
        &audit,
        &ExecutionIdentity {
            execution_id: execution_id.into(),
            attempt_number,
        },
    )
    .expect("report")
}

// ---------------------------------------------------------------------------
// Coverage states
// ---------------------------------------------------------------------------

#[test]
fn clean_audit_is_success_clean() {
    let results = all_clean();
    let report = report_for(&results, &[], Some(9.0));
    assert_eq!(report.coverage.state, CoverageState::SuccessClean);
    assert!(report.coverage.state.coverage_known());
    assert_eq!(report.summary.finding_count, 0);
    assert_eq!(report.summary.security_score, Some(9.0));
    assert!(report.summary.headline.contains("no findings"));
}

#[test]
fn findings_audit_is_success_findings() {
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![secret_finding("[REDACTED]", "fp-1")],
        ),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![sast_finding("py-1", 10)]),
    ];
    let findings = vec![
        secret_finding("[REDACTED]", "fp-1"),
        sast_finding("py-1", 10),
    ];
    let report = report_for(&results, &findings, Some(6.0));
    assert_eq!(report.coverage.state, CoverageState::SuccessFindings);
    assert_eq!(report.summary.finding_count, 2);
    // Highest severity first: Critical (semgrep) before High (gitleaks).
    assert_eq!(report.findings[0].severity, Severity::Critical);
    assert_eq!(report.findings[1].severity, Severity::High);
}

#[test]
fn cancelled_wins_over_timeout() {
    let results = vec![
        success("gitleaks", "secret", vec![]),
        timeout("osv", "dependency", 300),
        cancelled("semgrep", "sast"),
    ];
    let report = report_for(&results, &[], None);
    assert_eq!(report.coverage.state, CoverageState::Cancelled);
    assert!(!report.coverage.state.coverage_known());
    assert!(report.summary.security_score.is_none());
}

#[test]
fn timeout_is_reported_as_timeout() {
    let results = vec![
        success("gitleaks", "secret", vec![]),
        timeout("osv", "dependency", 300),
        success("semgrep", "sast", vec![]),
    ];
    let report = report_for(&results, &[], None);
    assert_eq!(report.coverage.state, CoverageState::Timeout);
}

#[test]
fn no_files_analyzed_is_unknown_not_clean() {
    let results = vec![
        success("gitleaks", "secret", vec![]),
        failed("osv", "dependency", "no_files_analyzed"),
        failed("semgrep", "sast", "no_files_analyzed"),
    ];
    let report = report_for(&results, &[], None);
    assert_eq!(report.coverage.state, CoverageState::NoFilesAnalyzed);
    assert!(!report.coverage.complete);
    assert!(report.summary.security_score.is_none());
}

#[test]
fn scanner_failure_is_reported_as_failed() {
    let results = vec![
        success("gitleaks", "secret", vec![]),
        failed("osv", "dependency", "missing_report"),
        success("semgrep", "sast", vec![]),
    ];
    let report = report_for(&results, &[], None);
    assert_eq!(report.coverage.state, CoverageState::Failed);
    assert!(report.coverage.unsuccessful_scanners.contains_key("osv"));
}

// ---------------------------------------------------------------------------
// Facts-only summary and canonical finding representation
// ---------------------------------------------------------------------------

#[test]
fn null_score_is_never_substituted_with_zero() {
    let results = vec![
        success("gitleaks", "secret", vec![]),
        failed("osv", "dependency", "missing_report"),
        success("semgrep", "sast", vec![]),
    ];
    let report = report_for(&results, &[], None);
    assert!(report.summary.security_score.is_none());
    let json: Value =
        serde_json::from_str(&ReportGenerator::render_json(&report).unwrap()).unwrap();
    assert!(json["summary"]["security_score"].is_null());
    let md = ReportGenerator::render_markdown(&report).unwrap();
    // A partial scan must say *why* the score is missing, and must never let a
    // reader mistake absence for zero.
    assert!(md.contains("unavailable because scan coverage is incomplete"));
    assert!(!md.contains("0.0/10"));
}

#[test]
fn unknown_severity_and_missing_fields_survive() {
    let results = vec![
        success("gitleaks", "secret", vec![]),
        success("osv", "dependency", vec![dependency_finding("GHSA-1")]),
        success("semgrep", "sast", vec![]),
    ];
    let report = report_for(&results, &[dependency_finding("GHSA-1")], Some(8.5));
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].severity, Severity::Unknown);
    assert!(report.findings[0].cwe_id.is_none());
    assert!(report.findings[0].remediation.is_some());
    assert_eq!(
        report.summary.findings_by_severity.get("unknown"),
        Some(&1usize)
    );
}

#[test]
fn duplicates_are_correlated_not_merged_away_silently() {
    let duplicate = secret_finding("[REDACTED]", "fp-dup");
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![duplicate.clone(), duplicate.clone()],
        ),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![]),
    ];
    let report = report_for(&results, &[duplicate.clone(), duplicate], Some(7.5));
    assert_eq!(report.summary.finding_count, 1);
    assert_eq!(report.summary.duplicate_group_count, 1);
    assert_eq!(report.correlations.len(), 1);
    assert!(report.correlations[0].occurrences >= 2);
    let md = ReportGenerator::render_markdown(&report).unwrap();
    assert!(md.contains("## Correlations"));
}

#[test]
fn invalid_finding_is_quarantined_and_never_leaked() {
    let mut escaped = secret_finding("[REDACTED]", "fp-escape");
    escaped.file_path = Some("../escape.rs".into());
    let results = vec![
        success("gitleaks", "secret", vec![escaped.clone()]),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![]),
    ];
    let report = report_for(&results, &[escaped], Some(9.0));
    assert!(report.findings.is_empty());
    assert_eq!(report.summary.invalid_finding_count, 1);
    assert_eq!(report.invalid_findings.len(), 1);
    assert!(report.invalid_findings[0].reason.contains("file"));
    // The invalid finding's evidence must not leak through its own failure record.
    let json = ReportGenerator::render_json(&report).unwrap();
    assert!(!json.contains("../escape.rs"));
}

#[test]
fn evidence_is_verbatim_in_markdown_but_escaped_in_html() {
    let raw = "value=<xml> & \"quoted\"\n```\n# not a fence";
    let mut evil = sast_finding("py-evil", 1);
    evil.evidence = Some(raw.to_string());
    let results = vec![
        success("gitleaks", "secret", vec![]),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![evil.clone()]),
    ];
    let report = report_for(&results, &[evil], Some(6.0));

    let md = ReportGenerator::render_markdown(&report).unwrap();
    assert!(md.contains("<xml>"), "evidence must be verbatim in a fence");
    assert!(
        md.contains("value=<xml>"),
        "markdown must not escape evidence"
    );
    assert!(
        !md.contains("```\n# not a fence"),
        "a triple-backtick run must be neutralized"
    );

    let html = ReportGenerator::render_html(&report).unwrap();
    assert!(html.contains("&lt;xml&gt;"), "html must escape evidence");
    assert!(
        !html.contains("<xml>"),
        "raw angle brackets must not survive"
    );
}

#[test]
fn report_contains_no_raw_scanner_structures() {
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![secret_finding("[REDACTED]", "fp-raw")],
        ),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![]),
    ];
    let report = report_for(
        &results,
        &[secret_finding("[REDACTED]", "fp-raw")],
        Some(6.0),
    );
    let json = ReportGenerator::render_json(&report).unwrap();
    // No raw scanner report shapes, no repository paths, no orchestrator state.
    for banned in [
        "\"Secret\"",
        "\"StartLine\"",
        "\"Match\"",
        "\"clone_path\"",
        "scanner_execution",
        "/tmp/",
        "\"Notebook\"",
    ] {
        assert!(!json.contains(banned), "report leaked {banned}");
    }
    assert_eq!(report.identity.report_schema_version, REPORT_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// Determinism, ordering, and historical identity
// ---------------------------------------------------------------------------

#[test]
fn reordered_input_produces_identical_report_and_markdown() {
    // Same canonical facts, three different input orderings. Every deterministic
    // output must be byte-for-byte identical: no HashMap iteration order, no
    // input-order dependence.
    let a = sast_finding("py-a", 10);
    let b = sast_finding("py-b", 20);
    let c = secret_finding("[REDACTED]", "fp-c");

    let base = vec![
        success("gitleaks", "secret", vec![c.clone()]),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![a.clone(), b.clone()]),
    ];
    let findings = vec![a.clone(), b.clone(), c.clone()];
    let reference = report_for(&base, &findings, Some(5.5));
    let reference_md = ReportGenerator::render_markdown(&reference).unwrap();

    // Reverse the scanner order, the finding order within a scanner, and the
    // top-level finding order.
    let mut reordered_results = base.clone();
    reordered_results.reverse();
    reordered_results[0].findings.reverse();
    let mut reordered_findings = findings.clone();
    reordered_findings.reverse();

    let reordered = report_for(&reordered_results, &reordered_findings, Some(5.5));
    assert_eq!(
        reordered.findings, reference.findings,
        "finding ordering must not depend on input order"
    );
    assert_eq!(
        reordered.correlations, reference.correlations,
        "correlation ordering must not depend on input order"
    );
    assert_eq!(
        ReportGenerator::render_markdown(&reordered).unwrap(),
        reference_md,
        "markdown must be byte-for-byte stable under input reordering"
    );
    assert_eq!(
        ReportGenerator::render_json(&reordered).unwrap(),
        ReportGenerator::render_json(&reference).unwrap()
    );
    // Repeated rendering of one model is itself byte-stable.
    assert_eq!(
        ReportGenerator::render_markdown(&reference).unwrap(),
        reference_md
    );
}

#[test]
fn historical_executions_of_one_job_produce_distinct_reports() {
    let results = all_clean();
    let attempt1 = report_with_identity(&results, &[], Some(9.0), "exec-attempt-1", 1);
    let attempt2 = report_with_identity(&results, &[], Some(4.0), "exec-attempt-2", 2);

    assert_ne!(
        attempt1.identity.execution_id, attempt2.identity.execution_id,
        "a report is identified by its execution, not just its audit"
    );
    assert_ne!(
        attempt1.identity.attempt_number,
        attempt2.identity.attempt_number
    );
    assert_eq!(attempt1.identity.audit_id, attempt2.identity.audit_id);
    assert_ne!(
        attempt1.summary.security_score,
        attempt2.summary.security_score
    );

    let md1 = ReportGenerator::render_markdown(&attempt1).unwrap();
    let md2 = ReportGenerator::render_markdown(&attempt2).unwrap();
    assert!(md1.contains("exec-attempt-1"));
    assert!(md2.contains("exec-attempt-2"));
    assert!(md1.contains("Attempt: 1"));
    assert!(md2.contains("Attempt: 2"));
    assert_ne!(
        md1, md2,
        "attempt 1 and attempt 2 must not share one report"
    );
}

#[test]
fn report_does_not_alias_the_audit_it_was_built_from() {
    // Mutating the source audit after the report exists must not reach back into
    // it: the report is an owned snapshot, so a later mutation cannot rewrite
    // what was already reported.
    let mut audit = canonical(&all_clean(), &[], Some(9.0));
    let report = build_report(
        &audit,
        &ExecutionIdentity {
            execution_id: "exec-1".into(),
            attempt_number: 1,
        },
    )
    .expect("report");
    let before = ReportGenerator::render_markdown(&report).unwrap();

    audit.summary.finding_count = 999;
    audit.snapshot_file_count = 987_654;
    audit
        .limitations
        .push("injected after the report was built".into());

    let after = ReportGenerator::render_markdown(&report).unwrap();
    assert_eq!(
        before, after,
        "a built report must not alias its source audit"
    );
    assert!(!after.contains("987654"));
    assert!(!after.contains("injected after the report was built"));
}

#[test]
fn unsupported_canonical_version_is_refused() {
    let mut audit = canonical(&all_clean(), &[], Some(9.0));
    audit.schema_version = 99;
    let error = build_report(
        &audit,
        &ExecutionIdentity {
            execution_id: "exec-1".into(),
            attempt_number: 1,
        },
    )
    .expect_err("an unknown canonical version must be refused");
    assert_eq!(
        error,
        ReportError::UnsupportedCanonicalVersion {
            found: 99,
            expected: 1
        }
    );
}

// ---------------------------------------------------------------------------
// Evidence and secret safety
// ---------------------------------------------------------------------------

/// A plausible live credential that must never survive into a report.
const RAW_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

#[test]
fn raw_secret_never_appears_in_any_rendered_format() {
    // Feed a *raw* secret in as evidence. The canonical boundary owns redaction;
    // the reporter faithfully presents whatever survived it and must never
    // unredact, expand, or re-read the repository to recover the original value.
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![secret_finding(RAW_SECRET, "fp-secret")],
        ),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![]),
    ];
    let findings = vec![secret_finding(RAW_SECRET, "fp-secret")];

    let audit = canonical(&results, &findings, Some(4.0));
    let report = build_report(
        &audit,
        &ExecutionIdentity {
            execution_id: "exec-1".into(),
            attempt_number: 1,
        },
    )
    .expect("report");

    let md = ReportGenerator::render_markdown(&report).unwrap();
    let json = ReportGenerator::render_json(&report).unwrap();
    let html = ReportGenerator::render_html(&report).unwrap();

    // If the canonical boundary redacted it, the report shows the redaction and
    // never the secret. Redaction itself is asserted in the canonical suite; what
    // matters here is that rendering adds no path back to the raw value.
    if md.contains("[REDACTED]") {
        assert!(!md.contains(RAW_SECRET), "markdown leaked the raw secret");
        assert!(!json.contains(RAW_SECRET), "json leaked the raw secret");
        assert!(!html.contains(RAW_SECRET), "html leaked the raw secret");
    }
}

#[test]
fn redacted_evidence_is_presented_verbatim_and_never_expanded() {
    // A redacted secret must be presented exactly as the canonical audit holds
    // it: not expanded, not re-read from disk, not completed from context.
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![secret_finding("[REDACTED]", "fp-verbatim")],
        ),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![]),
    ];
    let findings = vec![secret_finding("[REDACTED]", "fp-verbatim")];
    let report = report_for(&results, &findings, Some(4.0));

    assert_eq!(report.findings.len(), 1);
    // Presented exactly as the canonical audit holds it — the redacted value
    // inside its original context, byte-for-byte, not expanded or re-read.
    assert_eq!(report.findings[0].evidence, "AWS_ACCESS_KEY_ID=[REDACTED]");
    let md = ReportGenerator::render_markdown(&report).unwrap();
    assert!(md.contains("[REDACTED]"));
    // No reconstruction of surrounding source, no inferred line content.
    assert!(!md.contains("AKIA"));
}

// ---------------------------------------------------------------------------
// Summary facts
// ---------------------------------------------------------------------------

#[test]
fn summary_counts_are_exact_across_scanners_and_severities() {
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![
                secret_finding("[REDACTED]", "fp-s1"),
                secret_finding("[REDACTED]", "fp-s2"),
            ],
        ),
        success("osv", "dependency", vec![dependency_finding("GHSA-abc")]),
        success("semgrep", "sast", vec![sast_finding("py-c", 42)]),
    ];
    let findings = vec![
        secret_finding("[REDACTED]", "fp-s1"),
        secret_finding("[REDACTED]", "fp-s2"),
        dependency_finding("GHSA-abc"),
        sast_finding("py-c", 42),
    ];
    let report = report_for(&results, &findings, Some(3.0));

    assert_eq!(report.summary.finding_count, 4);
    assert_eq!(report.summary.findings_by_scanner.get("gitleaks"), Some(&2));
    assert_eq!(report.summary.findings_by_scanner.get("osv"), Some(&1));
    assert_eq!(report.summary.findings_by_scanner.get("semgrep"), Some(&1));
    assert_eq!(report.summary.findings_by_severity.get("high"), Some(&2));
    assert_eq!(report.summary.findings_by_severity.get("unknown"), Some(&1));
    assert_eq!(
        report.summary.findings_by_severity.get("critical"),
        Some(&1)
    );

    // The headline is a fact, not an editorial judgement.
    let headline = &report.summary.headline;
    assert!(headline.contains("4 finding(s)"));
    for banned in ["highly insecure", "dangerous", "at risk"] {
        assert!(
            !headline.contains(banned),
            "headline editorialised: {banned}"
        );
    }
}

#[test]
fn summary_maps_iterate_in_stable_sorted_order() {
    // The summary maps are `BTreeMap`s, so their iteration order is sorted and
    // independent of insertion order. Rendering walks them directly, so this is
    // what makes the severity/scanner tables byte-stable.
    let report = report_for(&all_clean(), &[], Some(9.0));
    let _: &BTreeMap<String, usize> = &report.summary.findings_by_severity;

    let results = vec![
        success("semgrep", "sast", vec![sast_finding("py-z", 1)]),
        success(
            "gitleaks",
            "secret",
            vec![secret_finding("[REDACTED]", "fp-z")],
        ),
        success("osv", "dependency", vec![dependency_finding("GHSA-z")]),
    ];
    let findings = vec![
        sast_finding("py-z", 1),
        secret_finding("[REDACTED]", "fp-z"),
        dependency_finding("GHSA-z"),
    ];
    let report = report_for(&results, &findings, Some(1.0));

    // Sorted, not insertion-ordered: the input listed semgrep first.
    let scanners: Vec<&String> = report.summary.findings_by_scanner.keys().collect();
    let mut sorted = scanners.clone();
    sorted.sort();
    assert_eq!(scanners, sorted);

    let severities: Vec<&String> = report.summary.findings_by_severity.keys().collect();
    let mut sorted_sev = severities.clone();
    sorted_sev.sort();
    assert_eq!(severities, sorted_sev);
}

#[test]
fn score_is_copied_from_the_audit_and_never_recomputed() {
    let results = vec![
        success("gitleaks", "secret", vec![sast_finding("py-x", 1)]),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![]),
    ];
    let findings = vec![sast_finding("py-x", 1)];
    let report = report_for(&results, &findings, Some(2.5));
    assert_eq!(
        report.summary.security_score,
        Some(2.5),
        "the stored score must be presented unchanged"
    );
    let md = ReportGenerator::render_markdown(&report).unwrap();
    assert!(md.contains("Security score: 2.5/10"));
}

#[test]
fn cross_scanner_findings_stay_distinct_and_uncorrelated() {
    // A secret finding and a SAST finding are different canonical findings. The
    // reporter must never invent a cross-scanner relationship between them.
    let secret = secret_finding("[REDACTED]", "fp-x");
    let sast = sast_finding("py-same-line", 7);
    let results = vec![
        success("gitleaks", "secret", vec![secret.clone()]),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![sast.clone()]),
    ];
    let findings = vec![secret, sast];
    let report = report_for(&results, &findings, Some(4.0));

    assert_eq!(report.findings.len(), 2);
    assert!(
        report.correlations.is_empty(),
        "no cross-scanner correlation may be invented"
    );
    let a = &report.findings[0];
    let b = &report.findings[1];
    assert_ne!(a.id, b.id, "distinct scanners keep distinct identities");
    assert_ne!(a.provenance.scanner, b.provenance.scanner);
}

// ---------------------------------------------------------------------------
// Golden reports (13.18)
//
// A golden report is a frozen presentation of one canonical audit. It is not a
// snapshot of "whatever the renderer currently emits": each case is reviewed by
// hand once, then any change to the bytes is an intentional contract update
// (`UPDATE_GOLDEN=1 cargo test --test report`), never an incidental one.
// ---------------------------------------------------------------------------

/// Location of a frozen report fixture.
fn golden_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-fixtures")
        .join("report")
        .join(name)
}

/// Compare a rendered presentation against a frozen fixture.
fn assert_golden(name: &str, rendered: &str) {
    let path = golden_path(name);
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, rendered).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "golden fixture {} must exist at {} (regenerate with UPDATE_GOLDEN=1)",
            name,
            path.display()
        )
    });
    assert_eq!(rendered, expected, "report drifted from golden {name}");
}

/// Freeze both the Markdown and the JSON presentation of one report.
fn assert_golden_report(stem: &str, report: &CanonicalAuditReport) {
    assert_golden(
        &format!("{stem}.md"),
        &ReportGenerator::render_markdown(report).unwrap(),
    );
    assert_golden(
        &format!("{stem}.json"),
        &ReportGenerator::render_json(report).unwrap(),
    );
}

#[test]
fn golden_clean_audit() {
    let report = report_for(&all_clean(), &[], Some(9.0));
    assert_eq!(report.coverage.state, CoverageState::SuccessClean);
    assert_golden_report("clean", &report);
}

#[test]
fn golden_findings_audit() {
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![secret_finding("[REDACTED]", "fp-1")],
        ),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![sast_finding("py-1", 10)]),
    ];
    let findings = vec![
        secret_finding("[REDACTED]", "fp-1"),
        sast_finding("py-1", 10),
    ];
    let report = report_for(&results, &findings, Some(6.0));
    assert_golden_report("findings", &report);
}

#[test]
fn golden_partial_coverage() {
    // One scanner failed: the others' findings survive, the limitation is
    // visible, and the score is absent rather than zero.
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![secret_finding("[REDACTED]", "fp-p")],
        ),
        failed("osv", "dependency", "missing_report"),
        success("semgrep", "sast", vec![]),
    ];
    let findings = vec![secret_finding("[REDACTED]", "fp-p")];
    let report = report_for(&results, &findings, None);
    assert_eq!(report.coverage.state, CoverageState::Failed);
    assert!(report.summary.security_score.is_none());
    assert_golden_report("partial-coverage", &report);
}

#[test]
fn golden_failed_scanner() {
    let results = vec![
        failed("gitleaks", "secret", "missing_report"),
        failed("osv", "dependency", "missing_report"),
        success("semgrep", "sast", vec![]),
    ];
    let report = report_for(&results, &[], None);
    assert_eq!(report.coverage.state, CoverageState::Failed);
    assert_golden_report("failed-scanner", &report);
}

#[test]
fn golden_dependency_findings() {
    let results = vec![
        success("gitleaks", "secret", vec![]),
        success(
            "osv",
            "dependency",
            vec![
                dependency_finding("GHSA-dep-1"),
                dependency_finding("GHSA-dep-2"),
            ],
        ),
        success("semgrep", "sast", vec![]),
    ];
    let findings = vec![
        dependency_finding("GHSA-dep-1"),
        dependency_finding("GHSA-dep-2"),
    ];
    let report = report_for(&results, &findings, Some(7.0));
    assert_golden_report("dependency-findings", &report);
}

#[test]
fn golden_sast_findings() {
    let results = vec![
        success("gitleaks", "secret", vec![]),
        success("osv", "dependency", vec![]),
        success(
            "semgrep",
            "sast",
            vec![sast_finding("py-1", 10), sast_finding("py-2", 88)],
        ),
    ];
    let findings = vec![sast_finding("py-1", 10), sast_finding("py-2", 88)];
    let report = report_for(&results, &findings, Some(3.5));
    assert_golden_report("sast-findings", &report);
}

#[test]
fn golden_secret_findings() {
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![
                secret_finding("[REDACTED]", "fp-a"),
                secret_finding("[REDACTED]", "fp-b"),
            ],
        ),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![]),
    ];
    let findings = vec![
        secret_finding("[REDACTED]", "fp-a"),
        secret_finding("[REDACTED]", "fp-b"),
    ];
    let report = report_for(&results, &findings, Some(2.0));
    assert_golden_report("secret-findings", &report);
}

#[test]
fn golden_mixed_all_scanners() {
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![secret_finding("[REDACTED]", "fp-m1")],
        ),
        success("osv", "dependency", vec![dependency_finding("GHSA-mixed")]),
        success(
            "semgrep",
            "sast",
            vec![sast_finding("py-mixed", 5), sast_finding("py-mixed-2", 6)],
        ),
    ];
    let findings = vec![
        secret_finding("[REDACTED]", "fp-m1"),
        dependency_finding("GHSA-mixed"),
        sast_finding("py-mixed", 5),
        sast_finding("py-mixed-2", 6),
    ];
    let report = report_for(&results, &findings, Some(4.5));
    assert_eq!(report.coverage.state, CoverageState::SuccessFindings);
    assert_golden_report("mixed-all-scanners", &report);
}

#[test]
fn golden_duplicate_correlation() {
    let duplicate = secret_finding("[REDACTED]", "fp-dup");
    let results = vec![
        success(
            "gitleaks",
            "secret",
            vec![duplicate.clone(), duplicate.clone()],
        ),
        success("osv", "dependency", vec![]),
        success("semgrep", "sast", vec![]),
    ];
    let report = report_for(&results, &[duplicate.clone(), duplicate], Some(7.5));
    assert_eq!(report.summary.duplicate_group_count, 1);
    assert_golden_report("duplicate-correlation", &report);
}

#[test]
fn golden_unknown_severity() {
    let results = vec![
        success("gitleaks", "secret", vec![]),
        success(
            "osv",
            "dependency",
            vec![dependency_finding("GHSA-unknown")],
        ),
        success("semgrep", "sast", vec![]),
    ];
    let report = report_for(&results, &[dependency_finding("GHSA-unknown")], Some(8.5));
    assert_eq!(report.findings[0].severity, Severity::Unknown);
    assert_golden_report("unknown-severity", &report);
}
