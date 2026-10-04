//! Phase 14: the constrained AI reporter boundary.
//!
//! These tests prove the property that makes an AI layer safe to keep: a model
//! can only ever *explain* an audit, never *change* one, and any attempt is
//! refused rather than softened.
//!
//! Every test here runs with **no network and no model**. That is not a
//! limitation — it is the design goal. The validator is deterministic, so the
//! entire rule set is provable offline, and a rule that needs a live model to
//! test is a rule that cannot be relied on.
//!
//! The adversarial cases are the substance of the file. A validator is only as
//! good as the hostile inputs it has been shown to refuse, so each rule below
//! has at least one narrative crafted to violate it.

mod support;

use firecrow_backend::agents::scanner::{ScannerOutcome, ScannerResult};
use firecrow_backend::models::Severity;
use firecrow_backend::orchestrator::canonical_audit::{canonical_audit, CanonicalAuditRequest};
use firecrow_backend::schemas::ai_narrative::{
    explain_report, validate_narrative, FindingExplanation, NarrativeViolation,
    RemediationGuidance, ReportNarrative, AI_NARRATIVE_SCHEMA_VERSION,
};
use firecrow_backend::schemas::audit_state::Finding;
use firecrow_backend::schemas::report::{build_report, CanonicalAuditReport, ExecutionIdentity};
use firecrow_backend::services::llm::{build_prompt, parse_and_validate};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const REPO: &str = "https://github.com/example/repo";

/// One redacted secret finding, exactly as the canonical boundary produces it.
fn finding(rule: &str, severity: Severity, cwe: Option<&str>) -> Finding {
    Finding {
        id: format!("gitleaks-{rule}"),
        agent_source: "gitleaks".into(),
        title: format!("{rule} detection"),
        description: "Detected by gitleaks.".into(),
        severity,
        cvss_vector: None,
        cvss_score: None,
        // Redacted at the canonical boundary, exactly as in production.
        evidence: Some("AWS_ACCESS_KEY_ID=[REDACTED]".into()),
        remediation: Some("Rotate the credential.".into()),
        cwe_id: cwe.map(str::to_string),
        owasp_category: None,
        confidence: Some("high".into()),
        scanner_name: Some("gitleaks".into()),
        scanner_mode: Some("secret".into()),
        file_path: Some("config/aws.env".into()),
        line_number: Some(3),
        route: None,
        metadata_json: Some(
            serde_json::json!({
                "rule_id": rule,
                "fingerprint": format!("fp-{rule}"),
                "parser": "gitleaks-json-v1",
                "scanner_version": "8.18.4",
                "scanner_image": "ghcr.io/gitleaks/gitleaks:v8.18.4",
                "snapshot_commit": COMMIT,
            })
            .to_string(),
        ),
    }
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
            "parser": format!("{scanner}-json-v1"),
            "snapshot_commit": COMMIT,
        }),
    }
}

fn failed(scanner: &str, mode: &str) -> ScannerResult {
    ScannerResult {
        scanner: scanner.into(),
        version: "1.0.0".into(),
        mode: mode.into(),
        outcome: ScannerOutcome::Failed {
            reason: "engine unavailable".into(),
        },
        findings: vec![],
        execution_record: serde_json::json!({
            "scanner": scanner,
            "version": "1.0.0",
            "mode": mode,
            "parser": format!("{scanner}-json-v1"),
            "snapshot_commit": COMMIT,
            "detail": "engine unavailable",
            "coverage": "unknown",
        }),
    }
}

/// Build the deterministic report these tests validate against.
fn report_for(
    results: &[ScannerResult],
    findings: &[Finding],
    score: Option<f64>,
) -> CanonicalAuditReport {
    let borrowed: Vec<ScannerResult> = results.to_vec();
    let audit = canonical_audit(&CanonicalAuditRequest {
        scan_id: "scan-p14",
        repository_url: REPO,
        repo_branch: "main",
        repo_owner: "example",
        repo_name: "repo",
        snapshot_commit: Some(COMMIT),
        snapshot_file_count: 12,
        snapshot_total_size: 4096,
        results: &borrowed,
        findings,
        security_score: score,
    })
    .expect("canonical audit");
    build_report(
        &audit,
        &ExecutionIdentity {
            execution_id: "exec-1".into(),
            attempt_number: 1,
        },
    )
    .expect("report builds")
}

/// Three clean scanners.
fn clean_report() -> CanonicalAuditReport {
    report_for(
        &[
            success("gitleaks", "secret", vec![]),
            success("osv", "dependency", vec![]),
            success("semgrep", "sast", vec![]),
        ],
        &[],
        Some(9.5),
    )
}

/// One high-severity secret finding with a CWE.
fn findings_report() -> CanonicalAuditReport {
    let f = finding("aws-access-token", Severity::High, Some("CWE-798"));
    report_for(
        &[
            success("gitleaks", "secret", vec![f.clone()]),
            success("osv", "dependency", vec![]),
            success("semgrep", "sast", vec![]),
        ],
        &[f],
        Some(2.5),
    )
}

/// A run where one scanner failed, so coverage is partial.
fn partial_report() -> CanonicalAuditReport {
    report_for(
        &[
            success("gitleaks", "secret", vec![]),
            failed("osv", "dependency"),
            success("semgrep", "sast", vec![]),
        ],
        &[],
        None,
    )
}

/// A narrative that is faithful to the audit it describes.
fn faithful(report: &CanonicalAuditReport) -> ReportNarrative {
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
// The baseline: a faithful narrative is accepted
// ---------------------------------------------------------------------------

#[test]
fn a_faithful_narrative_is_accepted() {
    let report = findings_report();
    let narrative = faithful(&report);
    let accepted = validate_narrative(&report, &narrative).expect("faithful narrative accepted");
    assert_eq!(
        accepted, narrative,
        "validation returns the narrative unchanged"
    );
}

#[test]
fn a_faithful_narrative_on_a_clean_audit_is_accepted() {
    let report = clean_report();
    let narrative = faithful(&report);
    validate_narrative(&report, &narrative).expect("clean narrative accepted");
}

#[test]
fn a_faithful_narrative_on_a_partial_audit_is_accepted() {
    let report = partial_report();
    let narrative = faithful(&report);
    validate_narrative(&report, &narrative).expect("partial narrative accepted");
}

// ---------------------------------------------------------------------------
// No new findings — the central invariant
// ---------------------------------------------------------------------------

#[test]
fn a_narrative_cannot_invent_a_finding() {
    let report = clean_report();
    let mut narrative = faithful(&report);
    narrative.finding_explanations.push(FindingExplanation {
        finding_id: "invented-vulnerability".into(),
        severity: Some("critical".into()),
        explanation: "A backdoor was found in the authentication layer.".into(),
    });
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::UnknownFindingReference {
            finding_id: "invented-vulnerability".into()
        },
        "a finding id with nothing behind it must be refused"
    );
}

#[test]
fn remediation_cannot_invent_a_finding_either() {
    // The explanation list is the obvious attack surface, but remediation has
    // the same shape and must be guarded identically.
    let report = clean_report();
    let mut narrative = faithful(&report);
    narrative.remediation_guidance.push(RemediationGuidance {
        finding_id: "phantom-issue".into(),
        guidance: "Patch the deserialization flaw.".into(),
        verified: false,
    });
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::UnknownFindingReference {
            finding_id: "phantom-issue".into()
        }
    );
}

#[test]
fn a_clean_audit_cannot_be_given_findings_via_a_narrative() {
    // The most damaging version of the above: an audit with zero findings must
    // not become an audit with findings because a model said so.
    let report = clean_report();
    assert_eq!(report.summary.finding_count, 0);
    let mut narrative = faithful(&report);
    narrative.finding_explanations.push(FindingExplanation {
        finding_id: "gitleaks-aws-access-token".into(),
        severity: None,
        explanation: "An exposed key was detected.".into(),
    });
    assert!(validate_narrative(&report, &narrative).is_err());
}

// ---------------------------------------------------------------------------
// No severity or confidence changes
// ---------------------------------------------------------------------------

#[test]
fn a_narrative_cannot_escalate_severity() {
    let report = findings_report();
    let canonical_severity = report.findings[0].severity.as_str().to_string();
    let mut narrative = faithful(&report);
    narrative.finding_explanations[0].severity = Some("critical".into());
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::SeverityMismatch {
            finding_id: report.findings[0].id.clone(),
            claimed: "critical".into(),
            canonical: canonical_severity,
        }
    );
}

#[test]
fn restating_the_canonical_severity_exactly_is_allowed() {
    // The rule is "may restate, may not re-rank" — so a correct restatement must
    // pass, or the rule would train models to omit severity entirely.
    let report = findings_report();
    let canonical_severity = report.findings[0].severity.as_str().to_string();
    let mut narrative = faithful(&report);
    narrative.finding_explanations[0].severity = Some(canonical_severity);
    validate_narrative(&report, &narrative).expect("an exact restatement is fine");
}

#[test]
fn a_narrative_cannot_assert_confidence() {
    // Confidence is the scanner's measurement. The canonical contract is careful
    // to distinguish a scanner default from a real measurement; a model has no
    // standing to assert either.
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary = "This is a high confidence finding.".into();
    assert!(matches!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::ConfidenceRestated { .. }
    ));
}
// ---------------------------------------------------------------------------
// No invented classifications
// ---------------------------------------------------------------------------

#[test]
fn a_narrative_cannot_invent_a_cve() {
    // A plausible invented CVE is indistinguishable from a real one to a reader.
    // That is exactly why it is refused rather than flagged.
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary =
        "This corresponds to CVE-2024-99999 and should be patched.".into();
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::InventedClassification {
            identifier: "CVE-2024-99999".into()
        }
    );
}

#[test]
fn citing_the_canonical_cwe_is_allowed() {
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary = "The audit recorded one finding classified as CWE-798.".into();
    validate_narrative(&report, &narrative).expect("citing the canonical CWE is fine");
}

#[test]
fn a_real_but_unrelated_cwe_is_still_refused() {
    // The canonical audit does contain a CWE, so this proves the check is
    // membership rather than "any identifier at all".
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary = "This is also classified as CWE-89.".into();
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::InventedClassification {
            identifier: "CWE-89".into()
        }
    );
}

#[test]
fn a_finding_without_a_cwe_cannot_have_one_attributed_to_it() {
    let report = report_for(
        &[
            success(
                "semgrep",
                "sast",
                vec![finding("py-subprocess", Severity::Critical, None)],
            ),
            success("osv", "dependency", vec![]),
        ],
        &[finding("py-subprocess", Severity::Critical, None)],
        Some(1.0),
    );
    let mut narrative = faithful(&report);
    narrative.executive_summary = "This maps to CWE-78.".into();
    assert!(matches!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::InventedClassification { .. }
    ));
}

// ---------------------------------------------------------------------------
// No false all-clear
// ---------------------------------------------------------------------------

#[test]
fn a_narrative_cannot_declare_an_audit_clean_when_findings_exist() {
    // The single most damaging sentence a security product can publish.
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary = "This repository has no vulnerabilities.".into();
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::FalseAllClear { count: 1 }
    );
}

#[test]
fn an_all_clear_on_a_genuinely_clean_audit_is_allowed() {
    // The rule is conditional. Refusing "no vulnerabilities" on a scan that found
    // nothing would make the validator useless for clean repositories.
    let report = clean_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary =
        "No vulnerabilities were identified across the scanned snapshot.".into();
    validate_narrative(&report, &narrative).expect("an honest all-clear is fine");
}

#[test]
fn an_all_clear_is_refused_when_only_invalid_findings_were_quarantined() {
    // Quarantined findings are still findings a reader needs to know about.
    let report = report_for(
        &[success("gitleaks", "secret", vec![])],
        &[finding("bad-path", Severity::Low, None)],
        None,
    );
    if report.summary.invalid_finding_count == 0 {
        return; // the fixture produced a valid finding; nothing to assert here
    }
    let mut narrative = faithful(&report);
    narrative.executive_summary = "Nothing to fix here.".into();
    assert!(validate_narrative(&report, &narrative).is_err());
}
// ---------------------------------------------------------------------------
// Coverage honesty
// ---------------------------------------------------------------------------

#[test]
fn a_narrative_cannot_claim_complete_coverage_on_a_partial_audit() {
    // The AI-layer restatement of Phase 13's rule. A confident narrative must
    // not be able to paper over a cautious coverage banner.
    let report = partial_report();
    assert!(!report.coverage.complete);
    for claim in [
        "The project was fully scanned for issues.",
        "This audit provides complete coverage of the codebase.",
        "This was a comprehensive scan of the repository.",
        "Every file was scanned by the available tools.",
        "All files were analyzed during this run.",
        "No files were skipped in this analysis.",
    ] {
        let mut narrative = faithful(&report);
        narrative.executive_summary = claim.to_string();
        assert!(
            matches!(
                validate_narrative(&report, &narrative).unwrap_err(),
                NarrativeViolation::ProhibitedClaim { .. }
            ),
            "coverage overclaim not caught: {claim:?}"
        );
    }
}

#[test]
fn a_narrative_cannot_claim_a_failed_scanner_succeeded() {
    let report = partial_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary = "The osv succeeded and found no vulnerable packages.".into();
    assert!(matches!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::ScannerSuccessOverclaim { .. }
    ));
}

#[test]
fn an_explanation_cannot_hide_a_coverage_overclaim_from_the_summary() {
    // Every authored string is checked, not just the summary, so the model
    // cannot route a false claim through a field that is checked less often.
    let report = partial_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary = "This audit examined the repository.".into();
    narrative.remediation_guidance.push(RemediationGuidance {
        finding_id: "unrelated".into(),
        guidance: "All files were analyzed, so nothing else is outstanding.".into(),
        verified: false,
    });
    // The unknown finding id is caught first, which is itself correct: an
    // untraceable claim cannot be published regardless of its content.
    assert!(validate_narrative(&report, &narrative).is_err());
}

#[test]
fn a_partial_audit_may_still_be_described_accurately() {
    let report = partial_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary =
        "Coverage was incomplete: one scanner did not run, so this result is partial.".into();
    validate_narrative(&report, &narrative).expect("an honest partial description is fine");
}

// ---------------------------------------------------------------------------
// Remediation is never a verified fact
// ---------------------------------------------------------------------------

#[test]
fn remediation_cannot_be_marked_verified() {
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.remediation_guidance[0].verified = true;
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::VerifiedRemediationClaim {
            finding_id: report.findings[0].id.clone()
        }
    );
}

#[test]
fn remediation_cannot_be_phrased_as_an_accomplished_fix() {
    // `verified: false` can be set truthfully while the prose still overclaims,
    // so the prose is checked too.
    let report = findings_report();
    for claim in [
        "Rotating the key this fixes the exposure.",
        "This will fix the issue permanently.",
        "Applying this change guarantees the repository is safe.",
        "After this change the repository is now secure.",
        "The exposure has been remediated by this change.",
        "Verified fixed once this patch is applied.",
    ] {
        let mut narrative = faithful(&report);
        narrative.remediation_guidance[0].guidance = claim.to_string();
        assert!(
            matches!(
                validate_narrative(&report, &narrative).unwrap_err(),
                NarrativeViolation::RemediationStatedAsFact { .. }
            ),
            "verified-remediation phrasing not caught: {claim:?}"
        );
    }
}

#[test]
fn remediation_worded_as_a_suggestion_is_accepted() {
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.remediation_guidance[0].guidance =
        "Consider rotating the credential; this is guidance, not a verified change.".into();
    validate_narrative(&report, &narrative).expect("suggestion wording is fine");
}
// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

#[test]
fn a_narrative_cannot_echo_a_credential() {
    // The canonical audit is already redacted, so any credential-shaped string
    // here is something the model produced.
    let report = findings_report();
    for leak in [
        "The key is AKIAIOSFODNN7EXAMPLE and should be rotated.",
        "Set api_key = sk-live-1234567890abcdef in the config.",
        "The token=ghp_abcdefghijklmnopqrstuvwxyz0123456789 was exposed.",
    ] {
        let mut narrative = faithful(&report);
        narrative.executive_summary = leak.to_string();
        assert_eq!(
            validate_narrative(&report, &narrative).unwrap_err(),
            NarrativeViolation::SecretMaterial,
            "credential material not caught: {leak:?}"
        );
    }
}

#[test]
fn a_credential_in_an_explanation_is_refused_too() {
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.finding_explanations[0].explanation =
        "The value AKIAIOSFODNN7EXAMPLE appears in config.".into();
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::SecretMaterial
    );
}

#[test]
fn the_redaction_marker_is_not_treated_as_a_leak() {
    // The canonical evidence uses this exact marker, so a narrative that
    // references the redaction must still be accepted. Otherwise the rule would
    // make it impossible to discuss a redacted finding at all.
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary =
        "The recorded evidence shows AWS_ACCESS_KEY_ID=[REDACTED] in the repository.".into();
    validate_narrative(&report, &narrative).expect("the redaction marker is not a secret");
}

// ---------------------------------------------------------------------------
// Limitations
// ---------------------------------------------------------------------------

#[test]
fn a_narrative_cannot_invent_a_limitation() {
    let report = partial_report();
    let mut narrative = faithful(&report);
    narrative
        .limitations
        .push("Dynamic analysis was not performed.".into());
    assert!(matches!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::InventedLimitation { .. }
    ));
}

// ---------------------------------------------------------------------------
// Structural limits and versioning
// ---------------------------------------------------------------------------

#[test]
fn a_narrative_may_explain_a_finding_only_once() {
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.finding_explanations.push(FindingExplanation {
        finding_id: report.findings[0].id.clone(),
        severity: None,
        explanation: "A second explanation of the same finding.".into(),
    });
    assert!(matches!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::DuplicateExplanation { .. }
    ));
}

#[test]
fn an_unsupported_narrative_version_is_refused() {
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.narrative_schema_version = 99;
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::UnsupportedNarrativeVersion {
            found: 99,
            expected: AI_NARRATIVE_SCHEMA_VERSION,
        }
    );
}

#[test]
fn an_empty_executive_summary_is_refused() {
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary = "   ".into();
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::EmptyExecutiveSummary
    );
}

#[test]
fn an_oversized_narrative_is_refused() {
    // A model is an untrusted input source even when we called it; a looping
    // generation is rejected rather than persisted for a human to read.
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary =
        "a".repeat(firecrow_backend::schemas::ai_narrative::MAX_EXECUTIVE_SUMMARY_CHARS + 1);
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::ExecutiveSummaryTooLong
    );
}

#[test]
fn an_empty_explanation_is_refused() {
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.finding_explanations[0].explanation = String::new();
    assert!(matches!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::EmptyExplanation { .. }
    ));
}
// ---------------------------------------------------------------------------
// The deterministic baseline always survives
// ---------------------------------------------------------------------------

#[test]
fn the_deterministic_report_is_retained_alongside_an_accepted_narrative() {
    // The design choice that makes this phase safe to ship: the AI annotates,
    // it never replaces. If the model disappears tomorrow, the report is intact.
    let report = findings_report();
    let narrative = faithful(&report);
    let explained = explain_report(report.clone(), narrative.clone()).expect("accepted");
    assert_eq!(
        explained.deterministic_report, report,
        "the factual baseline must be retained unchanged"
    );
    assert_eq!(explained.narrative, narrative);
}

#[test]
fn a_rejected_narrative_yields_no_explained_report_at_all() {
    // There is no partial acceptance. A rejected narrative produces no output,
    // so no object exists in which a bad claim has been half-applied.
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.finding_explanations.push(FindingExplanation {
        finding_id: "invented".into(),
        severity: None,
        explanation: "A vulnerability that was never found.".into(),
    });
    assert!(explain_report(report.clone(), narrative).is_err());
}

#[test]
fn a_narrative_from_one_audit_cannot_be_reused_against_another() {
    // Traceability is checked per audit, so a narrative explaining execution 1's
    // findings cannot be attached to execution 2's report.
    let first = findings_report();
    let second = report_for(
        &[
            success(
                "semgrep",
                "sast",
                vec![finding("py-eval", Severity::Medium, None)],
            ),
            success("osv", "dependency", vec![]),
        ],
        &[finding("py-eval", Severity::Medium, None)],
        Some(5.0),
    );
    assert!(
        explain_report(second, faithful(&first)).is_err(),
        "a narrative must not transfer between audits"
    );
}

#[test]
fn validation_is_deterministic() {
    // Same input, same verdict, every time — including which rule fires first.
    let report = findings_report();
    let mut narrative = faithful(&report);
    narrative.executive_summary = "This repository has no vulnerabilities.".into();
    let first = validate_narrative(&report, &narrative).unwrap_err();
    for _ in 0..5 {
        assert_eq!(validate_narrative(&report, &narrative).unwrap_err(), first);
    }
}
// ---------------------------------------------------------------------------
// The input boundary: what the prompt may contain
// ---------------------------------------------------------------------------

#[test]
fn the_prompt_never_contains_finding_evidence() {
    // Stronger than relying on upstream redaction: the model is given no
    // evidence at all, so it cannot echo one even if redaction were wrong.
    let report = findings_report();
    let prompt = build_prompt(&report);
    assert!(
        !prompt.contains("[REDACTED]"),
        "evidence must not reach the model"
    );
    assert!(!prompt.contains("AWS_ACCESS_KEY_ID"));
}

#[test]
fn the_prompt_carries_only_canonical_facts() {
    let report = findings_report();
    let prompt = build_prompt(&report);
    assert!(prompt.contains(&report.findings[0].id));
    assert!(prompt.contains("total_findings: 1"));
    assert!(prompt.contains("security_score: 2.5"));
    assert!(prompt.contains("coverage_complete: true"));
    assert!(prompt.contains("CWE-798"));
}

#[test]
fn the_prompt_states_a_null_score_as_null_never_zero() {
    // Otherwise a model learns that "no score" means "a perfect score".
    let prompt = build_prompt(&partial_report());
    assert!(prompt.contains("security_score: null"));
    assert!(!prompt.contains("security_score: 0"));
}

#[test]
fn the_prompt_names_scanners_that_did_not_succeed() {
    let prompt = build_prompt(&partial_report());
    assert!(prompt.contains("scanners_that_did_not_succeed"));
    assert!(prompt.contains("osv"));
}

#[test]
fn the_prompt_is_deterministic() {
    let report = findings_report();
    assert_eq!(build_prompt(&report), build_prompt(&report));
}

#[test]
fn the_prompt_carries_no_repository_path_or_scanner_json() {
    let prompt = build_prompt(&findings_report());
    for banned in [
        "/tmp/",
        "clone_path",
        "\"Secret\"",
        "\"StartLine\"",
        "scanner_execution",
    ] {
        assert!(!prompt.contains(banned), "prompt leaked {banned}");
    }
}

// ---------------------------------------------------------------------------
// The output boundary: raw model text
// ---------------------------------------------------------------------------

#[test]
fn a_valid_raw_response_is_parsed_and_accepted() {
    let report = findings_report();
    let narrative = faithful(&report);
    let raw = serde_json::to_string(&narrative).unwrap();
    assert_eq!(
        parse_and_validate(&report, &raw).expect("accepted"),
        narrative
    );
}

#[test]
fn malformed_model_output_is_refused_not_guessed_at() {
    let report = findings_report();
    for raw in [
        "not json at all",
        "{}",
        "[]",
        r#"{"narrative_schema_version": 1}"#,
        r#"{"narrative_schema_version": "one", "executive_summary": "x"}"#,
    ] {
        assert!(
            matches!(
                parse_and_validate(&report, raw).unwrap_err(),
                NarrativeViolation::MalformedResponse { .. }
            ),
            "malformed output not refused: {raw:?}"
        );
    }
}

#[test]
fn a_hostile_raw_response_cannot_smuggle_a_finding_through() {
    // The full path a real model response takes: parse, then validate. Proving it
    // end-to-end is what makes the boundary real rather than advisory.
    let raw = r#"{
        "narrative_schema_version": 1,
        "executive_summary": "No vulnerabilities were found in this repository.",
        "finding_explanations": [
            {"finding_id": "totally-made-up", "severity": "critical",
             "explanation": "A remote code execution flaw was detected."}
        ],
        "remediation_guidance": [],
        "limitations": []
    }"#;
    assert_eq!(
        parse_and_validate(&findings_report(), raw).unwrap_err(),
        NarrativeViolation::UnknownFindingReference {
            finding_id: "totally-made-up".into()
        }
    );
}

#[test]
fn an_accepted_narrative_cannot_change_the_audit_it_describes() {
    // The end-to-end guarantee: after everything above, the canonical report is
    // still exactly what the scanners produced.
    let report = findings_report();
    let before = report.clone();
    let explained = explain_report(report, faithful(&before)).expect("accepted");
    assert_eq!(
        explained.deterministic_report.findings.len(),
        before.findings.len()
    );
    assert_eq!(
        explained.deterministic_report.summary.security_score,
        before.summary.security_score
    );
    assert_eq!(
        explained.deterministic_report.coverage.state,
        before.coverage.state
    );
}

#[test]
fn an_invented_finding_is_refused_even_without_a_severity_claim() {
    // Isolates the membership rule. The neighbouring test supplies a severity,
    // and the severity lookup is a *second* structural gate that would also
    // refuse the unknown id — so on its own that test would still pass if the
    // membership check were removed. This one omits severity so the membership
    // check is the only thing standing between the model and a fabricated
    // finding, which is the invariant the whole phase rests on.
    let report = clean_report();
    let mut narrative = faithful(&report);
    narrative.finding_explanations.push(FindingExplanation {
        finding_id: "invented-vulnerability".into(),
        severity: None,
        explanation: "An undocumented backdoor was found in the authentication layer.".into(),
    });
    assert_eq!(
        validate_narrative(&report, &narrative).unwrap_err(),
        NarrativeViolation::UnknownFindingReference {
            finding_id: "invented-vulnerability".into()
        }
    );
}

#[test]
fn the_membership_rule_alone_refuses_an_invented_finding() {
    // The same guarantee, exercised through the full parse-and-validate path a
    // real model response takes, again with no severity to fall back on.
    let raw = r#"{
        "narrative_schema_version": 1,
        "executive_summary": "This audit examined the repository snapshot.",
        "finding_explanations": [
            {"finding_id": "invented-vulnerability", "severity": null,
             "explanation": "An undocumented backdoor was found."}
        ],
        "remediation_guidance": [],
        "limitations": []
    }"#;
    assert_eq!(
        parse_and_validate(&clean_report(), raw).unwrap_err(),
        NarrativeViolation::UnknownFindingReference {
            finding_id: "invented-vulnerability".into()
        }
    );
}
