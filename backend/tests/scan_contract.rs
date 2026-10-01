//! Phase 0 contract tests.
//!
//! These tests freeze the product contract before implementation. Every schema
//! named in the pipeline diagram is constructed, serialized, and validated
//! here; every invalid state in the rules list is rejected here. They run
//! without a database.

use firecrow_backend::schemas::scan_contract::{
    canonical_finding_id, check_report_severity_unchanged, dedupe_canonical_findings,
    normalize_raw_finding, normalize_repository_url, parse_repository_target,
    require_redacted_evidence, validate_canonical_finding, validate_report_input,
    validate_scan_result, validate_snapshot, CanonicalFinding, ContractError, Dependency,
    PipelineState, RawFinding, Report, ReportFinding, RepositorySnapshot, RepositoryTarget,
    ScanResult, Scanner, ScannerKind, ScannerRun, ScannerStatus, CONTRACT_VERSION, RULES,
};

fn snapshot() -> RepositorySnapshot {
    RepositorySnapshot {
        repository_url: "https://github.com/acme/widget".to_string(),
        branch: "main".to_string(),
        archive_sha256: "ab".repeat(32),
        tree_sha256: "cd".repeat(32),
        file_count: 3,
        total_bytes: 42,
    }
}

fn gitleaks_raw() -> RawFinding {
    RawFinding {
        scanner: ScannerKind::Gitleaks,
        rule_id: "aws-access-token".to_string(),
        file: "config/aws.env".to_string(),
        line: 3,
        snippet: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".to_string(),
    }
}

fn osv_raw() -> RawFinding {
    RawFinding {
        scanner: ScannerKind::Osv,
        rule_id: "GHSA-abcd-efgh-ijkl".to_string(),
        file: "package-lock.json".to_string(),
        line: 120,
        snippet: "lodash@4.17.20".to_string(),
    }
}

fn semgrep_raw() -> RawFinding {
    RawFinding {
        scanner: ScannerKind::Semgrep,
        rule_id: "python.lang.security.audit.subprocess-shell-true".to_string(),
        file: "src/run.py".to_string(),
        line: 9,
        snippet: "subprocess.call(cmd, shell=True)".to_string(),
    }
}

fn redacted_finding(raw: &RawFinding, version: &str) -> CanonicalFinding {
    let mut finding = normalize_raw_finding(raw, &snapshot(), version).expect("valid raw");
    finding.evidence.redacted = true;
    finding.evidence.snippet = "AWS_ACCESS_KEY_ID=[REDACTED]".to_string();
    finding
}

fn ok_run(scanner: ScannerKind) -> ScannerRun {
    ScannerRun {
        scanner,
        status: ScannerStatus::Ok,
        detail: serde_json::json!({"finding_count": 1}),
        raw_finding_count: 1,
    }
}

fn failed_run(scanner: ScannerKind) -> ScannerRun {
    ScannerRun {
        scanner,
        status: ScannerStatus::Failed,
        detail: serde_json::json!({"status": "error"}),
        raw_finding_count: 0,
    }
}

fn scan_result(state: PipelineState, runs: Vec<ScannerRun>, error: Option<String>) -> ScanResult {
    ScanResult {
        contract_version: CONTRACT_VERSION,
        scan_id: "scan-1".to_string(),
        repository: RepositoryTarget {
            repository_url: "https://github.com/acme/widget".to_string(),
            branch: "main".to_string(),
        },
        snapshot: snapshot(),
        pipeline_state: state,
        scanner_runs: runs,
        findings: vec![redacted_finding(&gitleaks_raw(), "v8.18.4")],
        dependencies: vec![Dependency {
            name: "lodash".to_string(),
            version: "4.17.20".to_string(),
            ecosystem: "npm".to_string(),
        }],
        error,
    }
}

#[test]
fn repository_target_accepts_only_canonical_github_urls() {
    let target = parse_repository_target("https://github.com/acme/widget.git/", "main").unwrap();
    assert_eq!(target.repository_url, "https://github.com/acme/widget");
    assert_eq!(target.branch, "main");

    for bad in [
        "file:///etc/passwd",
        "ssh://git@github.com/acme/widget.git",
        "git@github.com:acme/widget.git",
        "https://gitlab.com/acme/widget",
        "https://github.com/acme",
        "https://github.com/acme/widget/extra",
        "https://github.com/acme/..",
        "https://github.com/../widget",
        "",
    ] {
        assert_eq!(
            parse_repository_target(bad, "main"),
            Err(ContractError::InvalidRepositoryUrl),
            "must reject {bad}"
        );
    }
    assert_eq!(
        normalize_repository_url("https://github.com/acme/widget"),
        Ok("https://github.com/acme/widget".to_string())
    );
    assert_eq!(
        parse_repository_target("https://github.com/acme/widget", "feature/x"),
        Err(ContractError::InvalidRepositoryUrl)
    );
}

#[test]
fn snapshot_rejects_bad_digests() {
    validate_snapshot(&snapshot()).unwrap();

    let mut bad = snapshot();
    bad.archive_sha256 = "ZZ".to_string();
    assert!(validate_snapshot(&bad).is_err());

    let mut bad = snapshot();
    bad.tree_sha256 = "ab".repeat(31) + "A";
    assert!(validate_snapshot(&bad).is_err());

    let mut bad = snapshot();
    bad.repository_url = "https://gitlab.com/acme/widget".to_string();
    assert!(validate_snapshot(&bad).is_err());
}

#[test]
fn scanner_output_is_authoritative_for_detection() {
    for raw in [gitleaks_raw(), osv_raw(), semgrep_raw()] {
        let normalized = normalize_raw_finding(&raw, &snapshot(), "1.0.0").unwrap();
        assert_eq!(normalized.scanner, raw.scanner);
        assert_eq!(normalized.provenance.rule_id, raw.rule_id);
        assert_eq!(normalized.evidence.file_path, raw.file);
        assert_eq!(normalized.evidence.line_number, raw.line);
        assert_eq!(normalized.evidence.snippet, raw.snippet);
        assert_eq!(normalized.id, canonical_finding_id(&raw));
    }
}

#[test]
fn normalization_rejects_invalid_raw_findings() {
    let mut missing_file = gitleaks_raw();
    missing_file.file = String::new();
    assert!(normalize_raw_finding(&missing_file, &snapshot(), "1.0.0").is_err());

    let mut absolute = gitleaks_raw();
    absolute.file = "/etc/passwd".to_string();
    assert!(normalize_raw_finding(&absolute, &snapshot(), "1.0.0").is_err());

    let mut traversal = gitleaks_raw();
    traversal.file = "../secret".to_string();
    assert!(normalize_raw_finding(&traversal, &snapshot(), "1.0.0").is_err());

    let mut bad_line = gitleaks_raw();
    bad_line.line = 0;
    assert!(normalize_raw_finding(&bad_line, &snapshot(), "1.0.0").is_err());

    let mut no_snippet = gitleaks_raw();
    no_snippet.snippet = "   ".to_string();
    assert!(normalize_raw_finding(&no_snippet, &snapshot(), "1.0.0").is_err());

    let mut no_rule = gitleaks_raw();
    no_rule.rule_id = String::new();
    assert!(normalize_raw_finding(&no_rule, &snapshot(), "1.0.0").is_err());
}

#[test]
fn deduplication_keeps_first_scanner_identity() {
    let first = redacted_finding(&gitleaks_raw(), "v8.18.4");
    let mut second = first.clone();
    second.evidence.snippet = "AWS_ACCESS_KEY_ID=[REDACTED] again".to_string();
    let other_scanner = redacted_finding(&osv_raw(), "1.2.3");

    let deduped = dedupe_canonical_findings(vec![first.clone(), second, other_scanner.clone()]);
    assert_eq!(deduped.len(), 2);
    assert_eq!(deduped[0].evidence.snippet, first.evidence.snippet);
    assert_eq!(deduped[1].id, other_scanner.id);
}

#[test]
fn every_finding_must_have_provenance() {
    let mut finding = redacted_finding(&gitleaks_raw(), "v8.18.4");
    finding.provenance.rule_id.clear();
    assert_eq!(
        validate_canonical_finding(&finding),
        Err(ContractError::MissingProvenance)
    );

    let mut finding = redacted_finding(&gitleaks_raw(), "v8.18.4");
    finding.provenance.snapshot.clear();
    assert_eq!(
        validate_canonical_finding(&finding),
        Err(ContractError::MissingProvenance)
    );
}

#[test]
fn every_finding_must_have_redacted_evidence() {
    let unredacted = normalize_raw_finding(&gitleaks_raw(), &snapshot(), "v8.18.4").unwrap();
    assert_eq!(
        validate_canonical_finding(&unredacted),
        Err(ContractError::UnredactedEvidence)
    );
    assert_eq!(
        require_redacted_evidence(&unredacted.evidence),
        Err(ContractError::UnredactedEvidence)
    );

    let mut no_location = redacted_finding(&gitleaks_raw(), "v8.18.4");
    no_location.evidence.file_path.clear();
    assert_eq!(
        validate_canonical_finding(&no_location),
        Err(ContractError::MissingEvidence)
    );

    let redacted = redacted_finding(&gitleaks_raw(), "v8.18.4");
    validate_canonical_finding(&redacted).unwrap();
    require_redacted_evidence(&redacted.evidence).unwrap();
}

#[test]
fn scanner_failure_is_never_zero_vulnerabilities() {
    let failed = scan_result(
        PipelineState::Failed,
        vec![failed_run(ScannerKind::Gitleaks)],
        Some("gitleaks: scanner exited non-zero".to_string()),
    );
    validate_scan_result(&failed).unwrap();
    assert!(!failed.findings.is_empty() || failed.error.is_some());

    let completed_with_failure = scan_result(
        PipelineState::Completed,
        vec![failed_run(ScannerKind::Gitleaks)],
        Some("gitleaks failed".to_string()),
    );
    assert!(validate_scan_result(&completed_with_failure).is_err());

    let ok_but_empty_runs = scan_result(PipelineState::Completed, vec![], None);
    assert!(validate_scan_result(&ok_but_empty_runs).is_err());
}

#[test]
fn partial_scan_must_be_explicitly_represented() {
    let partial = scan_result(
        PipelineState::Partial,
        vec![ok_run(ScannerKind::Gitleaks), failed_run(ScannerKind::Osv)],
        Some("osv: registry unreachable".to_string()),
    );
    validate_scan_result(&partial).unwrap();

    let unnamed = scan_result(
        PipelineState::Partial,
        vec![ok_run(ScannerKind::Gitleaks), failed_run(ScannerKind::Osv)],
        Some("a scanner failed".to_string()),
    );
    assert_eq!(
        validate_scan_result(&unnamed),
        Err(ContractError::PartialWithoutCause)
    );

    let no_failure = scan_result(
        PipelineState::Partial,
        vec![ok_run(ScannerKind::Gitleaks)],
        Some("gitleaks failed".to_string()),
    );
    assert!(validate_scan_result(&no_failure).is_err());

    let no_success = scan_result(
        PipelineState::Partial,
        vec![failed_run(ScannerKind::Gitleaks)],
        Some("gitleaks failed".to_string()),
    );
    assert!(validate_scan_result(&no_success).is_err());
}

#[test]
fn completed_scan_requires_every_scanner_to_succeed() {
    let completed = scan_result(
        PipelineState::Completed,
        vec![ok_run(ScannerKind::Gitleaks), ok_run(ScannerKind::Osv)],
        None,
    );
    validate_scan_result(&completed).unwrap();

    let skipped = ScanResult {
        scanner_runs: vec![
            ok_run(ScannerKind::Gitleaks),
            ScannerRun {
                scanner: ScannerKind::Semgrep,
                status: ScannerStatus::Skipped,
                detail: serde_json::json!({}),
                raw_finding_count: 0,
            },
        ],
        ..scan_result(PipelineState::Completed, vec![], None)
    };
    assert!(validate_scan_result(&skipped).is_err());
}

#[test]
fn ai_cannot_create_findings() {
    let findings = vec![redacted_finding(&gitleaks_raw(), "v8.18.4")];
    let invented = vec![
        ReportFinding {
            finding_id: findings[0].id.clone(),
            summary: "Leaked AWS key".to_string(),
            priority: 1,
        },
        ReportFinding {
            finding_id: "ai|invented|nowhere|0".to_string(),
            summary: "An issue the scanner never reported".to_string(),
            priority: 1,
        },
    ];
    assert!(matches!(
        validate_report_input(&findings, &invented),
        Err(ContractError::InvalidReportInput { .. })
    ));
}

#[test]
fn ai_cannot_drop_or_duplicate_findings() {
    let two = vec![
        redacted_finding(&gitleaks_raw(), "v8.18.4"),
        redacted_finding(&osv_raw(), "1.2.3"),
    ];
    let only_first = vec![ReportFinding {
        finding_id: two[0].id.clone(),
        summary: "Leaked AWS key".to_string(),
        priority: 1,
    }];
    assert!(validate_report_input(&two, &only_first).is_err());

    let duplicated = vec![
        ReportFinding {
            finding_id: two[0].id.clone(),
            summary: "First".to_string(),
            priority: 1,
        },
        ReportFinding {
            finding_id: two[0].id.clone(),
            summary: "First again".to_string(),
            priority: 2,
        },
    ];
    assert!(validate_report_input(&two, &duplicated).is_err());
}

#[test]
fn ai_cannot_modify_severity_or_invent_evidence() {
    assert_eq!(
        check_report_severity_unchanged("high", "critical"),
        Err(ContractError::SeverityChanged {
            from: "high".to_string(),
            to: "critical".to_string()
        })
    );
    check_report_severity_unchanged("high", "high").unwrap();

    let mut unredacted = redacted_finding(&gitleaks_raw(), "v8.18.4");
    unredacted.evidence.snippet = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".to_string();
    unredacted.evidence.redacted = false;
    let report = vec![ReportFinding {
        finding_id: unredacted.id.clone(),
        summary: "Leaked AWS key".to_string(),
        priority: 1,
    }];
    assert!(validate_report_input(&[unredacted], &report).is_err());
}

#[test]
fn report_requires_existing_redacted_findings() {
    assert!(matches!(
        validate_report_input(&[], &[]),
        Err(ContractError::InvalidReportInput { .. })
    ));

    let findings = vec![redacted_finding(&gitleaks_raw(), "v8.18.4")];
    let report = vec![ReportFinding {
        finding_id: findings[0].id.clone(),
        summary: " ".to_string(),
        priority: 1,
    }];
    assert!(validate_report_input(&findings, &report).is_err());
}

#[test]
fn pipeline_states_and_versions_round_trip() {
    for state in [
        PipelineState::Queued,
        PipelineState::Fetching,
        PipelineState::Scanning,
        PipelineState::Normalizing,
        PipelineState::Scoring,
        PipelineState::Reporting,
        PipelineState::Delivering,
        PipelineState::Completed,
        PipelineState::Partial,
        PipelineState::Failed,
        PipelineState::Cancelled,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, format!("\"{}\"", state.as_str()));
        assert_eq!(serde_json::from_str::<PipelineState>(&json).unwrap(), state);
    }
    assert!(PipelineState::Completed.is_terminal());
    assert!(PipelineState::Partial.is_terminal());
    assert!(PipelineState::Failed.is_terminal());
    assert!(PipelineState::Cancelled.is_terminal());
    assert!(!PipelineState::Queued.is_terminal());
    assert!(!PipelineState::Scanning.is_terminal());

    let mut versioned = scan_result(
        PipelineState::Completed,
        vec![ok_run(ScannerKind::Gitleaks)],
        None,
    );
    versioned.contract_version = CONTRACT_VERSION + 1;
    assert_eq!(
        validate_scan_result(&versioned),
        Err(ContractError::UnsupportedVersion(CONTRACT_VERSION + 1))
    );
}

#[test]
fn unknown_scanners_stay_distinguishable() {
    let raw: RawFinding = serde_json::from_value(serde_json::json!({
        "scanner": "brand-new-scanner",
        "rule_id": "R1",
        "file": "src/main.rs",
        "line": 4,
        "snippet": "suspicious()"
    }))
    .unwrap();
    assert_eq!(raw.scanner, ScannerKind::Other);
    assert_eq!(raw.scanner.as_str(), "other");
}

#[test]
fn every_named_contract_schema_exists() {
    // RepositoryTarget, RepositorySnapshot, Scanner, ScannerRun, RawFinding,
    // Finding, Evidence, Dependency, ScanResult, Report, ReportFinding, Rules.
    let _target = parse_repository_target("https://github.com/acme/widget", "main").unwrap();
    let _snapshot = snapshot();
    let scanner = Scanner::gitleaks();
    assert_eq!(scanner.kind, ScannerKind::Gitleaks);
    assert_eq!(scanner.name, "gitleaks");
    let _run = ok_run(ScannerKind::Gitleaks);
    let _raw = gitleaks_raw();
    let finding = redacted_finding(&gitleaks_raw(), "8.18.4");
    let _provenance = finding.provenance.clone();
    let _evidence = finding.evidence.clone();
    let _dep = Dependency {
        name: "lodash".to_string(),
        version: "4.17.20".to_string(),
        ecosystem: "npm".to_string(),
    };
    let _result = scan_result(
        PipelineState::Completed,
        vec![ok_run(ScannerKind::Gitleaks)],
        None,
    );
    let _report = Report {
        scan_id: "scan-1".to_string(),
        score: Some(9.0),
        findings: vec![ReportFinding {
            finding_id: finding.id.clone(),
            summary: "Leaked AWS key".to_string(),
            priority: 1,
        }],
        markdown: "# report".to_string(),
        html: "<h1>report</h1>".to_string(),
    };
    assert_eq!(RULES.len(), 8);
}

#[test]
fn every_contract_rule_is_listed_and_unique() {
    let ids: Vec<&str> = RULES.iter().map(|rule| rule.id).collect();
    assert_eq!(ids.len(), 8, "all eight rules must remain canonical");
    let mut unique = std::collections::BTreeSet::new();
    for id in ids {
        assert!(unique.insert(id), "duplicate rule id {id}");
    }
    let required = [
        "scanner_is_authoritative",
        "ai_cannot_create",
        "ai_cannot_change_severity",
        "ai_cannot_invent_evidence",
        "failure_is_not_zero",
        "partial_is_explicit",
        "every_finding_has_provenance",
        "secrets_redacted_first",
    ];
    for id in required {
        assert!(
            unique.contains(id),
            "rule {id} must never be removed from the contract"
        );
    }
}

#[test]
fn gitleaks_scanner_descriptor_matches_the_pinned_image() {
    let scanner = Scanner::gitleaks();
    assert_eq!(scanner.image, "ghcr.io/gitleaks/gitleaks:v8.18.4");
    assert!(!scanner.version.is_empty());
    assert_eq!(scanner.mode, "secret");
}
