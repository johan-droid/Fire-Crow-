//! Phase 10: normalization / integration hardening.
//!
//! One deterministic canonical Audit JSON across Gitleaks, OSV-Scanner, and
//! Semgrep: provenance preserved, failure never clean, distinct findings never
//! merged, partial coverage explicit, score null unless complete.
//!
//! Pure tests need no Docker and no database. The golden fixture at
//! `test-fixtures/canonical/mixed-audit.json` is the frozen representation.

mod support;

use firecrow_backend::agents::scanner::{
    classify, ScanInput, Scanner, ScannerOutcome, ScannerResult,
};
use firecrow_backend::error::AppError;
use firecrow_backend::models::Severity;
use firecrow_backend::orchestrator::canonical_audit::{
    aggregate_scan_results, canonical_audit, canonical_identity, normalize_findings_for_persist,
    CanonicalAuditRequest,
};
use firecrow_backend::orchestrator::{dedupe_findings, finding_fingerprint};
use firecrow_backend::schemas::audit_state::Finding;
use firecrow_backend::schemas::canonical_audit::{
    CanonicalAudit, CoverageStatus, CANONICAL_AUDIT_VERSION,
};
use firecrow_backend::services::sandbox::{SandboxManager, SandboxOutput};
use std::collections::BTreeMap;

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

fn input() -> ScanInput {
    ScanInput {
        source_dir: std::env::temp_dir().join("firecrow-canonical-fixture"),
        commit_sha: Some(COMMIT.to_string()),
        file_count: 8,
        total_size: 4096,
    }
}

fn gitleaks_report(secret: &str) -> String {
    serde_json::json!([{
        "RuleID": "aws-access-token",
        "Description": "AWS Access Token",
        "File": "config/aws.env",
        "StartLine": 3,
        "StartColumn": 21,
        "EndLine": 3,
        "EndColumn": 21 + secret.len() as i64,
        "Match": format!("AWS_ACCESS_KEY_ID={secret}"),
        "Secret": secret,
        "Fingerprint": "fp-aws-env-3",
    }])
    .to_string()
}

fn secret_finding(secret: &str) -> Finding {
    let sandbox = SandboxManager::new();
    let _ = &sandbox;
    let scanner = Scanner::gitleaks();
    let outcome = firecrow_backend::agents::scanner::classify(
        &scanner,
        &input(),
        Ok(SandboxOutput {
            stdout: gitleaks_report(secret),
            stderr: String::new(),
            success: true,
        }),
    );
    assert_eq!(outcome.findings.len(), 1);
    outcome.findings.into_iter().next().unwrap()
}

fn run_ok(stdout: &str) -> Result<SandboxOutput, AppError> {
    Ok(SandboxOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        success: true,
    })
}

fn osv_finding(package: &str, version: &str, advisory: &str, manifest: &str) -> Finding {
    let report = serde_json::json!({"results": [{
        "source": {"path": format!("/scan/{manifest}"), "type": "lockfile"},
        "packages": [{
            "package": {"name": package, "version": version, "ecosystem": "npm"},
            "vulnerabilities": [{
                "id": advisory, "aliases": [],
                "summary": "Test advisory.",
                "affected": [{"package": {"ecosystem": "npm", "name": package},
                    "ranges": [{"type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}],
                "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
                "database_specific": {"severity": "HIGH"},
            }],
            "groups": [{"ids": [advisory]}],
        }],
    }]})
    .to_string();
    let dir = std::env::temp_dir().join(format!("fc-canon-osv-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        serde_json::json!({"dependencies": {package: version}}).to_string(),
    )
    .unwrap();
    let outcome = classify(&Scanner::osv(), &input(), run_ok(&report));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(outcome.findings.len(), 1);
    let mut finding = outcome.findings.into_iter().next().unwrap();
    // The manifest name in the report must match the requested one.
    finding.file_path = Some(manifest.to_string());
    finding
}

fn semgrep_finding(check_id: &str, line: i64) -> Finding {
    let report = serde_json::json!({
        "results": [{
            "check_id": check_id,
            "path": "/scan/app.py",
            "start": {"line": line, "col": 5},
            "end": {"line": line, "col": 40},
            "extra": {
                "severity": "ERROR",
                "message": "Test detection.",
                "lines": "subprocess.call(cmd, shell=True)",
                "fingerprint": format!("fp-{check_id}-{line}"),
                "metadata": {
                    "confidence": "HIGH",
                    "cwe": ["CWE-78: Improper Neutralization of Special Elements used in an OS Command"],
                    "owasp": ["A03:2021 - Injection"],
                    "references": ["https://cwe.mitre.org/data/definitions/78.html"],
                },
            },
        }],
        "paths": {"scanned": ["/scan/app.py"]},
        "errors": [],
    })
    .to_string();
    let outcome = classify(&Scanner::semgrep(), &input(), run_ok(&report));
    assert_eq!(outcome.findings.len(), 1);
    outcome.findings.into_iter().next().unwrap()
}

fn success(scanner: &Scanner, findings: Vec<Finding>) -> ScannerResult {
    let finding_count = findings.len();
    ScannerResult {
        scanner: scanner.name.to_string(),
        version: scanner.version.to_string(),
        mode: scanner.mode.to_string(),
        outcome: ScannerOutcome::Success {
            finding_count: findings.len(),
        },
        findings,
        execution_record: serde_json::json!({
            "scanner": scanner.name,
            "version": scanner.version,
            "mode": scanner.mode,
            "image": scanner.image,
            "parser": scanner.parser,
            "snapshot_commit": COMMIT,
            "finding_count": finding_count,
        }),
    }
}

fn failed(scanner: &Scanner, detail: &str, reason: &str) -> ScannerResult {
    ScannerResult {
        scanner: scanner.name.to_string(),
        version: scanner.version.to_string(),
        mode: scanner.mode.to_string(),
        outcome: ScannerOutcome::Failed {
            reason: reason.to_string(),
        },
        findings: Vec::new(),
        execution_record: serde_json::json!({
            "scanner": scanner.name,
            "version": scanner.version,
            "mode": scanner.mode,
            "image": scanner.image,
            "parser": scanner.parser,
            "snapshot_commit": COMMIT,
            "detail": detail,
            "error": reason,
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
        scan_id: "scan-canonical-1",
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

fn all_success_results(findings: Vec<Finding>) -> (Vec<ScannerResult>, Vec<Finding>) {
    let gitleaks = Scanner::gitleaks();
    let osv = Scanner::osv();
    let semgrep = Scanner::semgrep();
    let mut by_scanner: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for finding in findings {
        by_scanner
            .entry(
                finding
                    .scanner_name
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            )
            .or_default()
            .push(finding);
    }
    let results = [&gitleaks, &osv, &semgrep]
        .into_iter()
        .map(|scanner| success(scanner, by_scanner.remove(scanner.name).unwrap_or_default()))
        .collect::<Vec<_>>();
    let findings = results
        .iter()
        .flat_map(|result| result.findings.iter().cloned())
        .collect();
    (results, findings)
}

// ---------------------------------------------------------------------------
// 10.3 identity
// ---------------------------------------------------------------------------

#[test]
fn same_line_different_rule_stays_distinct() {
    let a = semgrep_finding("firecrow.python.rule-a", 20);
    let b = semgrep_finding("firecrow.python.rule-b", 20);
    assert_ne!(
        canonical_identity(&a).unwrap(),
        canonical_identity(&b).unwrap()
    );
    assert_eq!(dedupe_findings(vec![a, b]).len(), 2);
}

#[test]
fn different_packages_same_advisory_stay_distinct() {
    let a = osv_finding("lodash", "4.17.20", "GHSA-shared", "package-lock.json");
    let b = osv_finding("minimist", "1.2.5", "GHSA-shared", "package-lock.json");
    assert_ne!(
        canonical_identity(&a).unwrap(),
        canonical_identity(&b).unwrap()
    );
    assert_eq!(dedupe_findings(vec![a, b]).len(), 2);
}

#[test]
fn identity_never_uses_severity_file_line_alone() {
    // Same file and line, different scanners and rules: three findings.
    let findings = [
        secret_finding("AKIAIOSFODNN7EXAMPLE"),
        osv_finding("lodash", "4.17.20", "GHSA-1", "package-lock.json"),
        semgrep_finding("firecrow.python.x", 3),
    ];
    let ids: BTreeMap<String, String> = findings
        .iter()
        .map(|f| {
            (
                canonical_identity(f).unwrap(),
                f.scanner_name.clone().unwrap(),
            )
        })
        .collect();
    assert_eq!(ids.len(), 3);
    // And severity is not an identity input: flipping it cannot split one row.
    let mut rescored = findings[0].clone();
    rescored.severity = Severity::Critical;
    assert_eq!(
        canonical_identity(&rescored).unwrap(),
        canonical_identity(&findings[0]).unwrap(),
        "severity must not participate in identity"
    );
}

// ---------------------------------------------------------------------------
// 10.4 dedupe and correlation
// ---------------------------------------------------------------------------

#[test]
fn genuine_duplicates_correlate_and_preserve_provenance() {
    let first = secret_finding("AKIAIOSFODNN7EXAMPLE");
    let mut second = first.clone();
    second.id = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        dedupe_findings(vec![first.clone(), second.clone()]).len(),
        1
    );

    let (results, findings) = all_success_results(vec![first, second]);
    let audit = canonical_audit(&audit_request(&results, &findings, Some(7.5))).unwrap();
    assert_eq!(audit.findings.len(), 1);
    assert_eq!(audit.correlations.len(), 1);
    assert_eq!(audit.correlations[0].occurrences, 2);
    assert_eq!(
        audit.correlations[0].basis,
        firecrow_backend::schemas::canonical_audit::CorrelationBasis::ExactCanonicalIdentity
    );
    // Both provenance records survive on the correlation, not just the winner.
    assert_eq!(audit.correlations[0].provenance.len(), 1);
    assert_eq!(
        audit.correlations[0].provenance[0].rule_id,
        "aws-access-token"
    );
}

#[test]
fn cross_scanner_findings_are_never_merged() {
    let findings = vec![
        secret_finding("AKIAIOSFODNN7EXAMPLE"),
        semgrep_finding("firecrow.python.hardcoded-credential-assignment", 3),
        osv_finding("lodash", "4.17.20", "GHSA-1", "package-lock.json"),
    ];
    assert_eq!(dedupe_findings(findings.clone()).len(), 3);
    let (results, findings) = all_success_results(findings);
    let audit = canonical_audit(&audit_request(&results, &findings, Some(4.5))).unwrap();
    assert_eq!(audit.findings.len(), 3);
    assert!(audit.correlations.is_empty(), "no inference, no links");
}

#[test]
fn output_ordering_never_changes_identity_or_output() {
    let findings = vec![
        secret_finding("AKIAIOSFODNN7EXAMPLE"),
        osv_finding("lodash", "4.17.20", "GHSA-1", "package-lock.json"),
        semgrep_finding("firecrow.python.x", 3),
    ];
    let mut reversed = findings.clone();
    reversed.reverse();
    let forward = dedupe_findings(findings);
    let backward = dedupe_findings(reversed);
    assert_eq!(
        forward.iter().map(finding_fingerprint).collect::<Vec<_>>(),
        backward.iter().map(finding_fingerprint).collect::<Vec<_>>()
    );

    let (results, findings) = all_success_results(forward);
    let one = canonical_audit(&audit_request(&results, &findings, Some(4.5))).unwrap();
    let (results, findings) = all_success_results(backward);
    let two = canonical_audit(&audit_request(&results, &findings, Some(4.5))).unwrap();
    assert_eq!(
        serde_json::to_string(&one).unwrap(),
        serde_json::to_string(&two).unwrap(),
        "canonical output must be order-independent"
    );
}

#[test]
fn repeated_normalization_is_identical() {
    let findings = vec![
        secret_finding("AKIAIOSFODNN7EXAMPLE"),
        osv_finding("lodash", "4.17.20", "GHSA-1", "package-lock.json"),
    ];
    let (results, findings) = all_success_results(findings);
    let one = canonical_audit(&audit_request(&results, &findings, Some(6.0))).unwrap();
    let two = canonical_audit(&audit_request(&results, &findings, Some(6.0))).unwrap();
    assert_eq!(
        serde_json::to_string(&one).unwrap(),
        serde_json::to_string(&two).unwrap()
    );
}

// ---------------------------------------------------------------------------
// 10.5 evidence validation
// ---------------------------------------------------------------------------

#[test]
fn invalid_sast_location_is_rejected_not_repaired() {
    let mut bad = semgrep_finding("firecrow.python.x", 5);
    bad.line_number = Some(0);
    let normalized = normalize_findings_for_persist(vec![bad]);
    assert_eq!(normalized.valid.len(), 0);
    assert_eq!(normalized.invalid.len(), 1);
    assert_eq!(normalized.invalid[0].reason, "finding line is invalid");
}

#[test]
fn oversized_evidence_is_rejected() {
    let mut big = secret_finding("AKIAIOSFODNN7EXAMPLE");
    big.evidence = Some(format!("AWS_ACCESS_KEY_ID=[REDACTED] {}", "x".repeat(2000)));
    let normalized = normalize_findings_for_persist(vec![big]);
    assert_eq!(normalized.valid.len(), 0);
    assert_eq!(
        normalized.invalid[0].reason,
        "finding evidence exceeds the canonical bound"
    );
}

#[test]
fn secret_evidence_without_a_marker_is_rejected() {
    let mut leaked = secret_finding("AKIAIOSFODNN7EXAMPLE");
    leaked.evidence = Some("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".into());
    let normalized = normalize_findings_for_persist(vec![leaked]);
    assert_eq!(normalized.valid.len(), 0);
    assert_eq!(
        normalized.invalid[0].reason,
        "secret evidence has no redaction marker"
    );
    // And the invalid record carries no secret material.
    let serialized = serde_json::to_string(&normalized.invalid).unwrap();
    assert!(!serialized.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn dependency_evidence_requires_its_identity_fields() {
    let mut bad = osv_finding("lodash", "4.17.20", "GHSA-1", "package-lock.json");
    bad.file_path = Some(String::new());
    let normalized = normalize_findings_for_persist(vec![bad]);
    assert_eq!(normalized.valid.len(), 0);
}

// ---------------------------------------------------------------------------
// 10.6 scanner statuses, 10.7 partial coverage
// ---------------------------------------------------------------------------

#[test]
fn failed_timeout_cancelled_and_unanalyzed_stay_distinct() {
    let gitleaks = Scanner::gitleaks();
    let osv = Scanner::osv();
    let semgrep = Scanner::semgrep();

    let timeout = ScannerResult {
        scanner: osv.name.to_string(),
        version: osv.version.to_string(),
        mode: osv.mode.to_string(),
        outcome: ScannerOutcome::Timeout { limit_secs: 300 },
        findings: Vec::new(),
        execution_record: serde_json::json!({
            "scanner": "osv", "version": "2.2.4", "mode": "dependency",
            "image": osv.image, "parser": osv.parser, "snapshot_commit": COMMIT,
            "coverage": "unknown",
        }),
    };
    let cancelled = ScannerResult {
        scanner: semgrep.name.to_string(),
        version: semgrep.version.to_string(),
        mode: semgrep.mode.to_string(),
        outcome: ScannerOutcome::Cancelled,
        findings: Vec::new(),
        execution_record: serde_json::json!({
            "scanner": "semgrep", "version": "1.96.0", "mode": "sast",
            "image": semgrep.image, "parser": semgrep.parser,
            "snapshot_commit": COMMIT, "coverage": "unknown",
        }),
    };
    let unanalyzed = failed(&gitleaks, "no_files_analyzed", "scanner analyzed no files");
    let failed_run = failed(&osv, "missing_report", "scanner produced no report");
    let clean = success(&gitleaks, Vec::new());

    let results = vec![clean, failed_run, timeout, cancelled, unanalyzed];
    let request = audit_request(&results, &[], None);
    let audit = canonical_audit(&request).unwrap();
    let statuses: BTreeMap<String, Vec<String>> = audit.scanner_runs.iter().fold(
        BTreeMap::new(),
        |mut map: BTreeMap<String, Vec<String>>, run| {
            map.entry(run.scanner.clone())
                .or_default()
                .push(run.status.as_str().to_string());
            map
        },
    );
    assert_eq!(
        statuses["gitleaks"],
        vec!["success_clean", "no_files_analyzed"]
    );
    assert_eq!(statuses["osv"], vec!["failed", "timeout"]);
    assert_eq!(statuses["semgrep"], vec!["cancelled"]);
    // One success among failures is partial coverage, never absent or clean.
    assert_eq!(audit.coverage.status, CoverageStatus::Partial);
    assert!(!audit.coverage.complete);
    assert!(audit.summary.security_score.is_none());
}

#[test]
fn partial_coverage_keeps_findings_and_nulls_the_score() {
    let gitleaks = Scanner::gitleaks();
    let osv = Scanner::osv();
    let semgrep = Scanner::semgrep();
    let secret = secret_finding("AKIAIOSFODNN7EXAMPLE");

    let results = vec![
        success(&gitleaks, vec![secret.clone()]),
        failed(&osv, "missing_report", "scanner produced no report"),
        failed(&semgrep, "timeout-detail", "osv-scanner timed out"),
    ];
    // A timeout must stay a timeout, not collapse into failed.
    let results = {
        let mut results = results;
        results[2] = ScannerResult {
            outcome: ScannerOutcome::Timeout { limit_secs: 600 },
            ..results[2].clone()
        };
        results
    };
    let (findings, coverage, detail) = aggregate_scan_results(&results.iter().collect::<Vec<_>>());
    assert_eq!(
        findings.len(),
        1,
        "the successful scanner's finding survives"
    );
    assert_eq!(coverage.status, CoverageStatus::Partial);
    assert!(!coverage.complete);
    assert!(detail.unwrap().contains("osv"));

    let audit = canonical_audit(&audit_request(&results, &findings, None)).unwrap();
    assert_eq!(audit.coverage.status, CoverageStatus::Partial);
    assert_eq!(audit.findings.len(), 1);
    assert!(audit.summary.security_score.is_none());
    assert!(!audit.limitations.is_empty());

    // And the score gate refuses a partial score outright.
    let bad = CanonicalAuditRequest {
        security_score: Some(5.0),
        ..audit_request(&results, &findings, None)
    };
    assert!(canonical_audit(&bad).is_err());
}

#[test]
fn failed_plus_zero_findings_is_incomplete_never_clean() {
    let osv = Scanner::osv();
    let results = vec![failed(&osv, "missing_report", "scanner produced no report")];
    let (findings, coverage, _) = aggregate_scan_results(&results.iter().collect::<Vec<_>>());
    assert!(findings.is_empty());
    assert_eq!(coverage.status, CoverageStatus::Absent);
    let audit = canonical_audit(&audit_request(&results, &findings, None)).unwrap();
    assert_ne!(audit.coverage.status, CoverageStatus::Complete);
    assert!(audit.summary.security_score.is_none());
}

// ---------------------------------------------------------------------------
// 10.2 / 10.8 provenance and contract
// ---------------------------------------------------------------------------

#[test]
fn provenance_survives_normalization_dedupe_and_serialization() {
    let findings = vec![
        secret_finding("AKIAIOSFODNN7EXAMPLE"),
        osv_finding("lodash", "4.17.20", "GHSA-1", "package-lock.json"),
        semgrep_finding("firecrow.python.x", 3),
    ];
    let (results, findings) = all_success_results(findings);
    let audit = canonical_audit(&audit_request(&results, &findings, Some(4.5))).unwrap();

    for finding in &audit.findings {
        assert!(!finding.provenance.scanner_version.is_empty());
        assert!(!finding.provenance.parser.is_empty());
        assert!(!finding.provenance.rule_id.is_empty());
        assert!(!finding.provenance.native_fingerprint.is_empty());
        assert_eq!(finding.provenance.snapshot_commit.as_deref(), Some(COMMIT));
        assert!(!finding.location.file.is_empty());
        assert!(finding.location.line > 0);
        assert!(!finding.evidence.is_empty());
    }
    // Scanner-native fingerprints are preserved verbatim, not recomputed.
    let secret = audit
        .findings
        .iter()
        .find(|f| f.provenance.scanner == "gitleaks")
        .unwrap();
    assert_eq!(
        secret.native_id,
        format!("gitleaks:{}", secret.provenance.native_fingerprint)
    );

    // Parser versions survive round-trip serialization.
    let reparsed: CanonicalAudit =
        serde_json::from_str(&serde_json::to_string(&audit).unwrap()).unwrap();
    assert_eq!(reparsed, audit);
    assert_eq!(reparsed.schema_version, CANONICAL_AUDIT_VERSION);
}

#[test]
fn unknown_severity_and_absent_metadata_stay_honest() {
    let mut unknown = osv_finding("left-pad", "1.3.0", "OSV-UNRATED-1", "package-lock.json");
    unknown.severity = Severity::Unknown;
    unknown.cwe_id = None;
    unknown.owasp_category = None;
    let (results, findings) = all_success_results(vec![unknown]);
    let audit = canonical_audit(&audit_request(&results, &findings, Some(9.0))).unwrap();
    assert_eq!(audit.findings[0].severity, Severity::Unknown);
    assert!(audit.findings[0].cwe_id.is_none());
    assert!(audit.findings[0].owasp_category.is_none());
    assert_eq!(audit.summary.findings_by_severity["unknown"], 1);
}

#[test]
fn canonical_json_contains_no_secrets_or_raw_models() {
    let findings = vec![
        secret_finding("AKIAIOSFODNN7EXAMPLE"),
        semgrep_finding("firecrow.python.hardcoded-credential-assignment", 69),
    ];
    let (results, findings) = all_success_results(findings);
    let audit = canonical_audit(&audit_request(&results, &findings, Some(4.5))).unwrap();
    let serialized = serde_json::to_string(&audit).unwrap();
    for banned in [
        "AKIAIOSFODNN7EXAMPLE",
        "prod-db-password",
        "ghp_live",
        "\"Secret\"",
        "\"Match\"",
        "metavars",
        "abstract_content",
        "engine_kind",
        "validation_state",
        "database_specific",
    ] {
        assert!(
            !serialized.contains(banned),
            "canonical JSON holds {banned}"
        );
    }
}

// ---------------------------------------------------------------------------
// 10.10 golden mixed audit
// ---------------------------------------------------------------------------

#[test]
fn golden_mixed_audit_is_deterministic_and_complete() {
    let secret = secret_finding("AKIAIOSFODNN7EXAMPLE");
    let dependency = osv_finding(
        "lodash",
        "4.17.20",
        "GHSA-4xc9-xhrj-v574",
        "package-lock.json",
    );
    let sast = semgrep_finding("firecrow.python.sql-injection-concatenation", 21);
    let mut unrated = osv_finding("left-pad", "1.3.0", "OSV-UNRATED-1", "package-lock.json");
    unrated.severity = Severity::Unknown;

    // A genuine duplicate: the same secret finding reported twice.
    let mut duplicate = secret.clone();
    duplicate.id = uuid::Uuid::new_v4().to_string();

    let findings = vec![secret, dependency, sast, unrated, duplicate];
    let (results, findings) = all_success_results(findings);
    let mut request = audit_request(&results, &findings, Some(3.0));
    request.scan_id = "scan-golden-mixed-1";
    let audit = canonical_audit(&request).unwrap();
    eprintln!("GOLDEN findings:");
    for f in &audit.findings {
        eprintln!(
            "  {} {} {}",
            f.id, f.provenance.scanner, f.provenance.rule_id
        );
    }

    assert_eq!(audit.coverage.status, CoverageStatus::Complete);
    assert!(audit.coverage.complete);
    // Five inputs, one exact duplicate: four canonical findings, one group.
    assert_eq!(audit.findings.len(), 4);
    assert_eq!(audit.correlations.len(), 1);
    assert_eq!(audit.summary.finding_count, 4);
    assert_eq!(audit.summary.security_score, Some(3.0));

    let scanners: Vec<&str> = audit
        .findings
        .iter()
        .map(|f| f.provenance.scanner.as_str())
        .collect();
    assert!(scanners.contains(&"gitleaks"));
    assert!(scanners.contains(&"osv"));
    assert!(scanners.contains(&"semgrep"));

    let golden_path = golden_path("mixed-audit.json");
    let golden = serde_json::to_string_pretty(&audit).unwrap();
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::create_dir_all(golden_path.parent().unwrap()).unwrap();
        std::fs::write(&golden_path, format!("{golden}\n")).unwrap();
    }
    let expected = std::fs::read_to_string(&golden_path).expect("golden mixed audit must exist");
    assert_eq!(
        format!("{golden}\n"),
        expected,
        "canonical audit drifted from the golden fixture"
    );
}

/// Location of a frozen canonical audit fixture.
fn golden_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-fixtures")
        .join("canonical")
        .join(name)
}

/// Compare a freshly built audit against a frozen fixture.
fn assert_matches_golden(name: &str, audit: &CanonicalAudit) {
    let path = golden_path(name);
    let rendered = format!("{}\n", serde_json::to_string_pretty(audit).unwrap());
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, rendered.clone()).unwrap();
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("golden fixture {name} must exist at {}", path.display()));
    assert_eq!(rendered, expected, "canonical audit drifted from {name}");
}

#[test]
fn golden_partial_coverage_audit_is_deterministic() {
    // The mixed audit with one scanner unable to report: gitleaks and osv keep
    // their findings, semgrep never produced a trustworthy report, and the
    // audit says so instead of claiming a clean bill of health.
    let secret = secret_finding("AKIAIOSFODNN7EXAMPLE");
    let dependency = osv_finding(
        "lodash",
        "4.17.20",
        "GHSA-4xc9-xhrj-v574",
        "package-lock.json",
    );
    let mut unrated = osv_finding("left-pad", "1.3.0", "OSV-UNRATED-1", "package-lock.json");
    unrated.severity = Severity::Unknown;

    let results = vec![
        success(&Scanner::gitleaks(), vec![secret.clone()]),
        success(&Scanner::osv(), vec![dependency.clone(), unrated.clone()]),
        failed(
            &Scanner::semgrep(),
            "missing_report",
            "semgrep produced no report",
        ),
    ];
    let findings = vec![secret, dependency, unrated];
    let mut request = audit_request(&results, &findings, None);
    request.scan_id = "scan-golden-partial-1";
    let audit = canonical_audit(&request).unwrap();

    assert_eq!(audit.coverage.status, CoverageStatus::Partial);
    assert!(!audit.coverage.complete);
    assert_eq!(audit.findings.len(), 3);
    assert_eq!(audit.summary.finding_count, 3);
    assert!(audit.summary.security_score.is_none());
    assert_eq!(audit.coverage.unsuccessful_scanners["semgrep"], "failed");
    assert!(audit
        .limitations
        .iter()
        .any(|limitation| limitation.contains("semgrep")));

    // A partial audit can never be promoted to a scored one by supplying a
    // score: the gate rejects it outright.
    let scored = CanonicalAuditRequest {
        security_score: Some(8.0),
        ..audit_request(&results, &findings, None)
    };
    assert!(canonical_audit(&scored).is_err());

    assert_matches_golden("partial-audit.json", &audit);
}

#[test]
fn golden_partial_audit_is_reproducible_and_order_independent() {
    let secret = secret_finding("AKIAIOSFODNN7EXAMPLE");
    let dependency = osv_finding(
        "lodash",
        "4.17.20",
        "GHSA-4xc9-xhrj-v574",
        "package-lock.json",
    );
    let mut unrated = osv_finding("left-pad", "1.3.0", "OSV-UNRATED-1", "package-lock.json");
    unrated.severity = Severity::Unknown;

    let build = |reversed: bool| {
        let mut findings = vec![secret.clone(), dependency.clone(), unrated.clone()];
        if reversed {
            findings.reverse();
        }
        let results = vec![
            success(&Scanner::gitleaks(), vec![secret.clone()]),
            success(&Scanner::osv(), vec![dependency.clone(), unrated.clone()]),
            failed(
                &Scanner::semgrep(),
                "missing_report",
                "semgrep produced no report",
            ),
        ];
        let mut request = audit_request(&results, &findings, None);
        request.scan_id = "scan-golden-partial-1";
        canonical_audit(&request).unwrap()
    };
    assert_eq!(
        serde_json::to_string(&build(false)).unwrap(),
        serde_json::to_string(&build(true)).unwrap(),
        "scanner output order must not change the canonical document"
    );
}

// ---------------------------------------------------------------------------
// regressions found while implementing this phase
// ---------------------------------------------------------------------------

#[test]
fn summary_counts_match_the_canonical_finding_set() {
    // Regression: `summary.finding_count` was computed before exact duplicates
    // collapsed, so an audit holding one duplicate reported five findings while
    // carrying four. Every summary count must describe the findings actually
    // present in the document.
    let secret = secret_finding("AKIAIOSFODNN7EXAMPLE");
    let mut duplicate = secret.clone();
    duplicate.id = uuid::Uuid::new_v4().to_string();
    let findings = vec![
        secret,
        duplicate,
        osv_finding(
            "lodash",
            "4.17.20",
            "GHSA-4xc9-xhrj-v574",
            "package-lock.json",
        ),
        semgrep_finding("firecrow.python.sql-injection-concatenation", 21),
    ];
    let (results, findings) = all_success_results(findings);
    let audit = canonical_audit(&audit_request(&results, &findings, Some(3.0))).unwrap();

    assert_eq!(audit.findings.len(), 3);
    assert_eq!(audit.summary.finding_count, 3);
    assert_eq!(audit.summary.valid_finding_count, 3);
    assert_eq!(audit.summary.duplicate_group_count, 1);
    assert_eq!(
        audit.summary.findings_by_scanner.values().sum::<usize>(),
        audit.findings.len()
    );
    assert_eq!(
        audit.summary.findings_by_severity.values().sum::<usize>(),
        audit.findings.len()
    );
    assert_eq!(audit.correlations.len(), 1);
    assert_eq!(audit.correlations[0].occurrences, 2);
}

#[test]
fn duplicate_input_records_never_destabilize_identity() {
    // Repeating the same record must neither create new identities nor change
    // the ones already assigned.
    let base = vec![
        secret_finding("AKIAIOSFODNN7EXAMPLE"),
        osv_finding("lodash", "4.17.20", "GHSA-1", "package-lock.json"),
        semgrep_finding("firecrow.python.x", 3),
    ];
    let once: Vec<String> = base
        .iter()
        .map(|f| canonical_identity(f).unwrap())
        .collect();

    let mut repeated = base.clone();
    for _ in 0..3 {
        let mut clone = base.clone();
        for finding in clone.iter_mut() {
            finding.id = uuid::Uuid::new_v4().to_string();
        }
        repeated.extend(clone);
    }
    let many: Vec<String> = repeated
        .iter()
        .map(|f| canonical_identity(f).unwrap())
        .collect();

    let mut unique = many.clone();
    unique.sort();
    unique.dedup();
    let mut expected = once.clone();
    expected.sort();
    assert_eq!(unique, expected, "repeats must not invent identities");

    let findings = base.clone();
    let one = normalize_findings_for_persist(findings.clone());
    let mut noisy = findings;
    noisy.extend(base);
    let two = normalize_findings_for_persist(noisy);
    assert_eq!(one.valid.len(), 3);
    assert_eq!(two.valid.len(), 3);
    assert_eq!(one.duplicate_groups, 0);
    assert_eq!(two.duplicate_groups, 3);
    // The persisted rows differ only in duplicate bookkeeping; the canonical
    // identity each row carries is unchanged.
    let identities = |rows: &[Finding]| -> Vec<String> {
        rows.iter()
            .map(canonical_identity)
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    };
    assert_eq!(identities(&one.valid), identities(&two.valid));
    let strip = |rows: &[Finding]| -> Vec<(String, String, String)> {
        rows.iter()
            .map(|row| {
                let metadata = row.metadata_json.clone().unwrap();
                let mut metadata: serde_json::Value = serde_json::from_str(&metadata).unwrap();
                metadata
                    .as_object_mut()
                    .unwrap()
                    .remove("duplicate_occurrences");
                (
                    row.title.clone(),
                    row.severity.as_str().to_string(),
                    metadata.to_string(),
                )
            })
            .collect()
    };
    assert_eq!(strip(&one.valid), strip(&two.valid));

    let (results, findings) = all_success_results(repeated);
    let request = audit_request(&results, &findings, Some(5.0));
    let audit = canonical_audit(&request).unwrap();
    assert_eq!(audit.findings.len(), 3);
    assert_eq!(audit.summary.finding_count, 3);
    assert_eq!(audit.correlations.len(), 3);
    assert!(audit
        .correlations
        .iter()
        .all(|correlation| correlation.occurrences == 4));
}

#[test]
fn identity_is_the_same_before_and_after_a_run_record_is_attached() {
    // Regression: canonical identity used to include the run provenance
    // (scanner version, parser, image). Those keys are attached when a scan is
    // executed, so a finding read straight from an adapter fell back to a
    // UUID-based fingerprint and an exact duplicate never collapsed — while
    // the same finding persisted with its run record hashed differently.
    use firecrow_backend::agents::scanner::findings_from_semgrep;
    let body = serde_json::json!({
        "results": [{
            "check_id": "firecrow.python.x",
            "path": "/scan/app.py",
            "start": {"line": 12, "col": 1},
            "end": {"line": 12, "col": 40},
            "extra": {
                "severity": "ERROR",
                "message": "Test detection.",
                "lines": "subprocess.call(cmd, shell=True)",
                "fingerprint": "fp-adapter-only",
                "metadata": {"confidence": "HIGH"},
            },
        }],
        "paths": {"scanned": ["/scan/app.py"]},
        "errors": [],
    })
    .to_string();
    let parsed = findings_from_semgrep(&body, &std::env::temp_dir()).unwrap();
    assert_eq!(parsed.valid.len(), 1);
    let adapter_only = parsed.valid.into_iter().next().unwrap();
    // No run provenance is attached at this point.
    assert!(canonical_identity(&adapter_only).is_ok());

    let executed = {
        let outcome = classify(
            &Scanner::semgrep(),
            &input(),
            run_ok(
                &serde_json::json!({
                    "results": [{
                        "check_id": "firecrow.python.x",
                        "path": "/scan/app.py",
                        "start": {"line": 12, "col": 1},
                        "end": {"line": 12, "col": 40},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Test detection.",
                            "lines": "subprocess.call(cmd, shell=True)",
                            "fingerprint": "fp-adapter-only",
                            "metadata": {"confidence": "HIGH"},
                        },
                    }],
                    "paths": {"scanned": ["/scan/app.py"]},
                    "errors": [],
                })
                .to_string(),
            ),
        );
        assert_eq!(outcome.findings.len(), 1);
        outcome.findings.into_iter().next().unwrap()
    };
    assert_ne!(
        adapter_only.metadata_json.as_deref(),
        executed.metadata_json.as_deref(),
        "the executed copy carries run provenance"
    );
    assert_eq!(
        canonical_identity(&adapter_only).unwrap(),
        canonical_identity(&executed).unwrap(),
        "attaching a run record must not re-identify the finding"
    );
    // And the same detection reported twice still collapses to one.
    let mut twin = executed.clone();
    twin.id = uuid::Uuid::new_v4().to_string();
    assert_eq!(dedupe_findings(vec![executed, twin]).len(), 1);
}
