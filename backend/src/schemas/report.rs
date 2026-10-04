//! Phase 13: the deterministic, versioned audit *report* contract.
//!
//! A report is a **presentation** of a Canonical Audit v1 plus the execution
//! identity that produced it. It is derived by a pure transformation:
//! [`build_report`] takes a validated [`CanonicalAudit`] and a
//! [`ExecutionIdentity`] and returns a [`CanonicalAuditReport`]. Nothing in this
//! module reads a scanner, a repository, the filesystem, the network, the
//! database, or an AI service — so rendering the same audit always yields the
//! same bytes.
//!
//! The report never invents a value. A missing scanner field stays missing, an
//! `unknown` severity stays `unknown`, and a `null` score stays `null`.

use crate::models::Severity;
use crate::schemas::canonical_audit::{
    CanonicalAudit, CanonicalAuditFinding, CanonicalScannerRun, CanonicalScannerStatus,
    CoverageStatus, FindingCorrelation, InvalidFinding, CANONICAL_AUDIT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version tag for every report document. A reader must refuse a document whose
/// version it does not understand, exactly as it does for a canonical audit.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// Overall execution state as presented by the report.
///
/// This is the single terminal-coverage verdict, derived deterministically from
/// the canonical scanner runs. It is deliberately *not* a re-derivation of
/// scanner output: every variant maps one-to-one onto a
/// [`CanonicalScannerStatus`] or onto a complete-coverage result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageState {
    /// Every scanner completed and none reported a finding.
    SuccessClean,
    /// Every scanner completed and at least one reported a finding.
    SuccessFindings,
    /// At least one scanner failed, and the failure was not a timeout, a
    /// cancellation, or "no files analyzed".
    Failed,
    /// At least one scanner hit its time limit.
    Timeout,
    /// The run was cancelled before a result could be established.
    Cancelled,
    /// The scanner looked at no files, so its coverage is unknown, not clean.
    NoFilesAnalyzed,
}

impl CoverageState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SuccessClean => "SUCCESS_CLEAN",
            Self::SuccessFindings => "SUCCESS_FINDINGS",
            Self::Failed => "FAILED",
            Self::Timeout => "TIMEOUT",
            Self::Cancelled => "CANCELLED",
            Self::NoFilesAnalyzed => "NO_FILES_ANALYZED",
        }
    }

    /// Whether the run established coverage over the snapshot.
    pub fn coverage_known(self) -> bool {
        matches!(self, Self::SuccessClean | Self::SuccessFindings)
    }
}

/// The immutable identity of the audit and the attempt that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportIdentity {
    /// The audit identity (the canonical audit's `scan_id`).
    pub audit_id: String,
    /// The execution/attempt that produced this audit.
    pub execution_id: String,
    pub attempt_number: i32,
    pub repository_url: String,
    pub repo_branch: String,
    pub repo_owner: String,
    pub repo_name: String,
    pub snapshot_commit: Option<String>,
    pub snapshot_file_count: usize,
    pub snapshot_total_size: u64,
    /// The canonical contract version the presented audit was written under.
    pub canonical_schema_version: u32,
    /// The report contract version these bytes are written under.
    pub report_schema_version: u32,
}

/// The execution identity supplied by the caller alongside the canonical audit.
///
/// `CanonicalAudit` carries the audit identity but not the attempt identity, so
/// that one fact is passed in explicitly. It is just an identity, never scanner
/// output: the generator has no way to accept raw findings or orchestrator
/// state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionIdentity {
    pub execution_id: String,
    pub attempt_number: i32,
}

/// Coverage as presented in the report.
///
/// Every field is copied from the canonical audit's coverage, except `state`,
/// which is derived deterministically by [`derive_coverage_state`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportCoverage {
    pub state: CoverageState,
    pub status: CoverageStatus,
    pub complete: bool,
    /// One canonical scanner run per scanner, sorted by scanner name.
    pub scanner_runs: Vec<CanonicalScannerRun>,
    pub successful_scanners: Vec<String>,
    pub unsuccessful_scanners: BTreeMap<String, String>,
    pub limitations: Vec<String>,
}

/// Facts-only summary of the audit. No editorialising, no inferred risk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportSummary {
    /// A single factual sentence describing the result.
    pub headline: String,
    pub finding_count: usize,
    /// Counts keyed by severity name, including `unknown` when present.
    pub findings_by_severity: BTreeMap<String, usize>,
    /// Counts keyed by scanner name.
    pub findings_by_scanner: BTreeMap<String, usize>,
    pub invalid_finding_count: usize,
    pub duplicate_group_count: usize,
    /// Copied verbatim. `None` stays `None`; it is never substituted with `0`.
    pub security_score: Option<f64>,
}

/// The complete, self-contained report document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalAuditReport {
    pub report_schema_version: u32,
    pub identity: ReportIdentity,
    pub coverage: ReportCoverage,
    pub summary: ReportSummary,
    /// Canonical findings, sorted by (severity, canonical id) for stable output.
    pub findings: Vec<CanonicalAuditFinding>,
    /// Correlations present in the canonical audit, sorted by correlation id.
    pub correlations: Vec<FindingCorrelation>,
    /// Findings the canonical audit quarantined. Never re-validated here.
    pub invalid_findings: Vec<InvalidFinding>,
    pub limitations: Vec<String>,
    /// Fixed, auditable statements about what the report is and is not.
    pub disclaimers: Vec<String>,
}

/// Reasons a report cannot be built at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    #[error("canonical audit schema version {found} is not supported (expected {expected})")]
    UnsupportedCanonicalVersion { found: u32, expected: u32 },
}

impl CanonicalAuditReport {
    /// The report schema version this document was produced under.
    pub fn schema_version(&self) -> u32 {
        self.report_schema_version
    }
}

/// Sort rank for a severity: higher severity first, `unknown` last.
///
/// `unknown` must never outrank a known signal, so it sorts after `info`.
fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
        Severity::Unknown => 5,
    }
}

/// Derive the single aggregate coverage state from the canonical scanner runs.
///
/// The precedence is fixed and total: cancellation wins over every other
/// signal, a timeout wins over an ordinary failure, and only a fully
/// `SuccessClean`/`SuccessFindings` audit is reported as successful.
pub fn derive_coverage_state(audit: &CanonicalAudit) -> CoverageState {
    if audit
        .scanner_runs
        .iter()
        .any(|run| matches!(run.status, CanonicalScannerStatus::Cancelled))
    {
        return CoverageState::Cancelled;
    }
    if audit
        .scanner_runs
        .iter()
        .any(|run| matches!(run.status, CanonicalScannerStatus::Timeout { .. }))
    {
        return CoverageState::Timeout;
    }
    if audit.coverage.complete {
        return if audit.summary.finding_count == 0 {
            CoverageState::SuccessClean
        } else {
            CoverageState::SuccessFindings
        };
    }
    let unsuccessful: Vec<&CanonicalScannerStatus> = audit
        .scanner_runs
        .iter()
        .filter(|run| !run.coverage_known)
        .map(|run| &run.status)
        .collect();
    if !unsuccessful.is_empty()
        && unsuccessful
            .iter()
            .all(|status| matches!(status, CanonicalScannerStatus::NoFilesAnalyzed { .. }))
    {
        return CoverageState::NoFilesAnalyzed;
    }
    CoverageState::Failed
}

/// Build the deterministic, facts-only headline for a summary.
fn headline(audit: &CanonicalAudit, state: CoverageState) -> String {
    match state {
        CoverageState::SuccessClean => format!(
            "All {} scanner(s) completed and reported no findings.",
            audit.coverage.successful_scanners.len()
        ),
        CoverageState::SuccessFindings => format!(
            "{} finding(s) reported across {} scanner(s).",
            audit.summary.finding_count,
            audit.coverage.successful_scanners.len()
        ),
        CoverageState::Cancelled => {
            "The audit was cancelled before coverage could be established.".to_string()
        }
        CoverageState::Timeout => "At least one scanner exceeded its time limit.".to_string(),
        CoverageState::NoFilesAnalyzed => {
            "No files were analyzed, so coverage is unknown rather than clean.".to_string()
        }
        CoverageState::Failed => {
            let names: Vec<String> = audit
                .coverage
                .unsuccessful_scanners
                .iter()
                .map(|(scanner, status)| format!("{scanner} ({status})"))
                .collect();
            if names.is_empty() {
                "Coverage is incomplete; the result cannot be treated as clean.".to_string()
            } else {
                format!("Coverage is incomplete: {}.", names.join(", "))
            }
        }
    }
}

/// The fixed statements attached to every report.
fn disclaimers() -> Vec<String> {
    vec![
        "This report presents a frozen canonical audit. Generating it ran no scanners, \
         accessed no repository, and called no AI service."
            .to_string(),
        "A missing or \"unknown\" value means the scanner did not report it; it is never \
         inferred or defaulted here."
            .to_string(),
        "Remediation text is guidance suggested by the scanner or platform; it is not a \
         verified fact about the repository."
            .to_string(),
    ]
}

/// Build a report from a canonical audit and a caller-supplied execution identity.
///
/// The only accepted source is a [`CanonicalAudit`]; there is no overload that
/// accepts raw findings, scanner JSON, a repository path, or orchestrator state.
pub fn build_report(
    audit: &CanonicalAudit,
    execution: &ExecutionIdentity,
) -> Result<CanonicalAuditReport, ReportError> {
    if audit.schema_version != CANONICAL_AUDIT_VERSION {
        return Err(ReportError::UnsupportedCanonicalVersion {
            found: audit.schema_version,
            expected: CANONICAL_AUDIT_VERSION,
        });
    }

    let state = derive_coverage_state(audit);
    let identity = ReportIdentity {
        audit_id: audit.scan_id.clone(),
        execution_id: execution.execution_id.clone(),
        attempt_number: execution.attempt_number,
        repository_url: audit.repository_url.clone(),
        repo_branch: audit.repo_branch.clone(),
        repo_owner: audit.repo_owner.clone(),
        repo_name: audit.repo_name.clone(),
        snapshot_commit: audit.snapshot_commit.clone(),
        snapshot_file_count: audit.snapshot_file_count,
        snapshot_total_size: audit.snapshot_total_size,
        canonical_schema_version: audit.schema_version,
        report_schema_version: REPORT_SCHEMA_VERSION,
    };

    let mut scanner_runs = audit.scanner_runs.clone();
    scanner_runs.sort_by(|a, b| a.scanner.cmp(&b.scanner));

    let coverage = ReportCoverage {
        state,
        status: audit.coverage.status,
        complete: audit.coverage.complete,
        scanner_runs,
        successful_scanners: audit.coverage.successful_scanners.clone(),
        unsuccessful_scanners: audit.coverage.unsuccessful_scanners.clone(),
        limitations: audit.coverage.limitations.clone(),
    };

    let summary = ReportSummary {
        headline: headline(audit, state),
        finding_count: audit.summary.finding_count,
        findings_by_severity: audit.summary.findings_by_severity.clone(),
        findings_by_scanner: audit.summary.findings_by_scanner.clone(),
        invalid_finding_count: audit.summary.invalid_finding_count,
        duplicate_group_count: audit.summary.duplicate_group_count,
        security_score: audit.summary.security_score,
    };

    // Explicit, total ordering: severity rank first, then canonical id. The
    // canonical audit already carries a deterministic id, so this is stable
    // regardless of scanner result order.
    let mut findings = audit.findings.clone();
    findings.sort_by(|a, b| {
        severity_rank(a.severity)
            .cmp(&severity_rank(b.severity))
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut correlations = audit.correlations.clone();
    correlations.sort_by(|a, b| a.correlation_id.cmp(&b.correlation_id));

    let mut invalid_findings: Vec<InvalidFinding> = audit.invalid_findings.clone();
    // A quarantined finding's path is precisely the field that failed validation.
    // Re-validating it here keeps an unvalidated scanner-controlled string (for
    // example `../../etc/passwd`) out of the published report. The canonical
    // reason is preserved either way, so nothing is silently discarded.
    for invalid in &mut invalid_findings {
        if let Some(file) = invalid.file.as_deref() {
            if crate::schemas::canonical_audit::validate_repo_path(file).is_err() {
                invalid.file = None;
            }
        }
    }
    invalid_findings.sort_by(|a, b| a.id.cmp(&b.id));

    let mut limitations = audit.limitations.clone();
    limitations.sort();
    limitations.dedup();

    Ok(CanonicalAuditReport {
        report_schema_version: REPORT_SCHEMA_VERSION,
        identity,
        coverage,
        summary,
        findings,
        correlations,
        invalid_findings,
        limitations,
        disclaimers: disclaimers(),
    })
}
