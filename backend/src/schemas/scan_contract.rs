//! Canonical Phase 0 product contract for the scan pipeline.
//!
//! These types are the authority for every handoff in the diagram: repository
//! intake, secure fetch, repository snapshot, scanner execution, raw results,
//! normalization, deduplication, evidence validation, canonical findings,
//! result JSON, AI reporting, rendered output, and email.
//!
//! Scanners are the only origin of detections. The AI reporter may explain or
//! prioritize an existing canonical finding, but cannot create findings, change
//! severity, or invent evidence. A scanner failure is represented explicitly
//! and is never the same as zero vulnerabilities.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Version tag for every contract document emitted by this module. Consumers
/// must reject documents whose version they do not understand.
pub const CONTRACT_VERSION: u32 = 1;

/// Supported scanner kinds. Unknown scanners deserialize to `Other` so a new
/// producer cannot crash a consumer, while its output remains distinguishable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerKind {
    Gitleaks,
    Osv,
    Semgrep,
    #[serde(other)]
    Other,
}

impl ScannerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gitleaks => "gitleaks",
            Self::Osv => "osv",
            Self::Semgrep => "semgrep",
            Self::Other => "other",
        }
    }
}

/// Every scanner must report one of these outcomes. `Failed` and `TimedOut`
/// mean "unknown coverage", never "zero vulnerabilities".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerStatus {
    Ok,
    Failed,
    TimedOut,
    Skipped,
}

/// Identity of one scanner participating in the pipeline. Fixed at registration
/// time; the version is pinned so a finding's provenance stays reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scanner {
    pub kind: ScannerKind,
    pub name: String,
    pub version: String,
    pub mode: String,
    pub image: String,
}

impl Scanner {
    /// The gitleaks scanner this build actually runs.
    pub fn gitleaks() -> Self {
        Self {
            kind: ScannerKind::Gitleaks,
            name: "gitleaks".to_string(),
            version: "8.18.4".to_string(),
            mode: "secret".to_string(),
            image: "ghcr.io/gitleaks/gitleaks:v8.18.4".to_string(),
        }
    }
}

/// One violation that must always be rejected, identified by id and stated in
/// prose. The constant [`RULES`] is the canonical list; tests assert it stays
/// complete, so a rule cannot be quietly dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: &'static str,
    pub statement: &'static str,
}

/// The product's inviolable rules, in canonical order.
pub const RULES: [Rule; 8] = [
    Rule {
        id: "scanner_is_authoritative",
        statement: "Scanner output is authoritative for detection.",
    },
    Rule {
        id: "ai_cannot_create",
        statement: "AI cannot create findings.",
    },
    Rule {
        id: "ai_cannot_change_severity",
        statement: "AI cannot modify severity.",
    },
    Rule {
        id: "ai_cannot_invent_evidence",
        statement: "AI cannot invent evidence.",
    },
    Rule {
        id: "failure_is_not_zero",
        statement: "Scanner failure != zero vulnerabilities.",
    },
    Rule {
        id: "partial_is_explicit",
        statement: "Partial scan must be explicitly represented.",
    },
    Rule {
        id: "every_finding_has_provenance",
        statement: "Every finding must have provenance.",
    },
    Rule {
        id: "secrets_redacted_first",
        statement: "Secrets must be redacted before persistence/reporting/AI.",
    },
];

/// Every scanner run in `ScanResult.scanner_runs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerRun {
    pub scanner: ScannerKind,
    pub status: ScannerStatus,
    /// Scanner-specific execution record, JSON-serializable.
    pub detail: serde_json::Value,
    pub raw_finding_count: usize,
}

/// Raw scanner output before normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawFinding {
    pub scanner: ScannerKind,
    pub rule_id: String,
    pub file: String,
    pub line: i64,
    pub snippet: String,
}

/// Provenance for a canonical finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub scanner: ScannerKind,
    pub scanner_version: String,
    pub snapshot: String,
    pub rule_id: String,
}

/// Redacted evidence attached to a canonical finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub file_path: String,
    pub line_number: i64,
    pub snippet: String,
    pub redacted: bool,
}

/// Canonical scanner-owned finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalFinding {
    pub id: String,
    pub scanner: ScannerKind,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub provenance: Provenance,
    pub evidence: Evidence,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub cvss_score: Option<f64>,
}

/// A report-ready view of an existing canonical finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportFinding {
    pub finding_id: String,
    pub summary: String,
    pub priority: u32,
}

/// Dependency/package inventory entry for a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
}

/// Frozen acquisition of a repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositorySnapshot {
    pub repository_url: String,
    pub branch: String,
    pub archive_sha256: String,
    pub tree_sha256: String,
    pub file_count: usize,
    pub total_bytes: u64,
}

/// Intake target before acquisition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryTarget {
    pub repository_url: String,
    pub branch: String,
}

/// Structured report derived only from existing canonical findings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub scan_id: String,
    pub score: Option<f64>,
    pub findings: Vec<ReportFinding>,
    pub markdown: String,
    pub html: String,
}

/// Machine-readable scan result JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    pub contract_version: u32,
    pub scan_id: String,
    pub repository: RepositoryTarget,
    pub snapshot: RepositorySnapshot,
    pub pipeline_state: PipelineState,
    pub scanner_runs: Vec<ScannerRun>,
    pub findings: Vec<CanonicalFinding>,
    pub dependencies: Vec<Dependency>,
    pub error: Option<String>,
}

/// All valid pipeline states.
///
/// `Partial` means some scanner failed or timed out while at least one scanner
/// succeeded. It must carry the failed scanner name(s) in `ScanResult.error`
/// or in a failed `ScannerRun`; omitting that information is invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineState {
    Queued,
    Fetching,
    Scanning,
    Normalizing,
    Scoring,
    Reporting,
    Delivering,
    Completed,
    Partial,
    Failed,
    Cancelled,
}

impl PipelineState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Fetching => "fetching",
            Self::Scanning => "scanning",
            Self::Normalizing => "normalizing",
            Self::Scoring => "scoring",
            Self::Reporting => "reporting",
            Self::Delivering => "delivering",
            Self::Completed => "completed",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Partial | Self::Failed | Self::Cancelled
        )
    }
}

/// Errors that reject invalid contract documents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    #[error("unsupported contract version: {0}")]
    UnsupportedVersion(u32),
    #[error("repository URL must be an https://github.com/OWNER/REPO URL")]
    InvalidRepositoryUrl,
    #[error("snapshot digest must be lowercase hex")]
    InvalidSnapshotDigest,
    #[error("raw finding from {scanner}: {reason}")]
    InvalidRawFinding { scanner: String, reason: String },
    #[error("canonical finding is missing provenance")]
    MissingProvenance,
    #[error("canonical finding is missing file, line, or evidence")]
    MissingEvidence,
    #[error("canonical finding evidence is not marked redacted")]
    UnredactedEvidence,
    #[error("scan result and pipeline state disagree: {reason}")]
    InconsistentResult { reason: String },
    #[error("partial scan must name the failed scanner(s)")]
    PartialWithoutCause,
    #[error("report input is invalid: {reason}")]
    InvalidReportInput { reason: String },
    #[error("severity change from {from} to {to} is not permitted")]
    SeverityChanged { from: String, to: String },
}

pub type ContractResult<T> = Result<T, ContractError>;

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn is_lower_hex_digest(value: &str) -> bool {
    // Written with `%` rather than `is_multiple_of` to stay within the README's
    // stated Rust 1.75 MSRV.
    !value.is_empty()
        && value.len() % 2 == 0
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Parse and validate a repository intake URL.
pub fn parse_repository_target(
    repository_url: &str,
    branch: &str,
) -> ContractResult<RepositoryTarget> {
    let normalized = normalize_repository_url(repository_url)?;
    let branch = branch.trim();
    if branch.is_empty() || branch.contains(char::is_whitespace) || branch.contains('/') {
        return Err(ContractError::InvalidRepositoryUrl);
    }
    Ok(RepositoryTarget {
        repository_url: normalized,
        branch: branch.to_string(),
    })
}

/// Normalize `https://github.com/{owner}/{repo}[.git][/]` to canonical form.
pub fn normalize_repository_url(url: &str) -> ContractResult<String> {
    let rest = url
        .trim()
        .strip_prefix("https://github.com/")
        .ok_or(ContractError::InvalidRepositoryUrl)?
        .trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let mut parts = rest.split('/');
    let owner = parts.next().unwrap_or_default();
    let repo = parts.next().unwrap_or_default();
    if parts.next().is_some() || !valid_segment(owner) || !valid_segment(repo) {
        return Err(ContractError::InvalidRepositoryUrl);
    }
    Ok(format!("https://github.com/{owner}/{repo}"))
}

/// Validate a snapshot's digests and counters.
pub fn validate_snapshot(snapshot: &RepositorySnapshot) -> ContractResult<()> {
    normalize_repository_url(&snapshot.repository_url)?;
    if snapshot.branch.trim().is_empty() {
        return Err(ContractError::InvalidRepositoryUrl);
    }
    if !is_lower_hex_digest(&snapshot.archive_sha256) || !is_lower_hex_digest(&snapshot.tree_sha256)
    {
        return Err(ContractError::InvalidSnapshotDigest);
    }
    Ok(())
}

fn raw_location_valid(raw: &RawFinding) -> ContractResult<()> {
    let file = raw.file.trim();
    if file.is_empty() || file.starts_with('/') || file.contains("..") {
        return Err(ContractError::InvalidRawFinding {
            scanner: raw.scanner.as_str().to_string(),
            reason: "file must be a repository-relative path".to_string(),
        });
    }
    if raw.line <= 0 {
        return Err(ContractError::InvalidRawFinding {
            scanner: raw.scanner.as_str().to_string(),
            reason: "line must be positive".to_string(),
        });
    }
    if raw.snippet.trim().is_empty() {
        return Err(ContractError::InvalidRawFinding {
            scanner: raw.scanner.as_str().to_string(),
            reason: "snippet must be non-empty".to_string(),
        });
    }
    Ok(())
}

/// Normalize one raw scanner result into a canonical finding.
///
/// Scanner output remains authoritative for detection and location. This step
/// validates shape only; it never invents a finding and never changes a
/// scanner-supplied severity.
pub fn normalize_raw_finding(
    raw: &RawFinding,
    snapshot: &RepositorySnapshot,
    scanner_version: &str,
) -> ContractResult<CanonicalFinding> {
    raw_location_valid(raw)?;
    validate_snapshot(snapshot)?;
    if raw.rule_id.trim().is_empty() {
        return Err(ContractError::InvalidRawFinding {
            scanner: raw.scanner.as_str().to_string(),
            reason: "rule_id must be non-empty".to_string(),
        });
    }
    if scanner_version.trim().is_empty() {
        return Err(ContractError::InvalidRawFinding {
            scanner: raw.scanner.as_str().to_string(),
            reason: "scanner_version must be non-empty".to_string(),
        });
    }

    Ok(CanonicalFinding {
        id: canonical_finding_id(raw),
        scanner: raw.scanner.clone(),
        severity: scanner_severity(&raw.scanner, &raw.rule_id),
        title: scanner_title(&raw.scanner, &raw.rule_id),
        description: scanner_description(&raw.scanner, &raw.rule_id),
        provenance: Provenance {
            scanner: raw.scanner.clone(),
            scanner_version: scanner_version.to_string(),
            snapshot: snapshot.tree_sha256.clone(),
            rule_id: raw.rule_id.clone(),
        },
        evidence: Evidence {
            file_path: raw.file.clone(),
            line_number: raw.line,
            snippet: raw.snippet.clone(),
            redacted: false,
        },
        cwe_id: scanner_cwe(&raw.scanner, &raw.rule_id),
        owasp_category: scanner_owasp(&raw.scanner, &raw.rule_id),
        cvss_score: None,
    })
}

/// Stable identity for one raw detection: scanner, rule, file, and line.
pub fn canonical_finding_id(raw: &RawFinding) -> String {
    format!(
        "{}|{}|{}|{}",
        raw.scanner.as_str(),
        raw.rule_id,
        raw.file,
        raw.line
    )
}

/// Deduplicate canonical findings by stable scanner identity.
pub fn dedupe_canonical_findings(findings: Vec<CanonicalFinding>) -> Vec<CanonicalFinding> {
    let mut seen = BTreeSet::new();
    findings
        .into_iter()
        .filter(|finding| {
            seen.insert(format!(
                "{}|{}|{}|{}",
                finding.scanner.as_str(),
                finding.provenance.rule_id,
                finding.evidence.file_path,
                finding.evidence.line_number
            ))
        })
        .collect()
}

/// Validate a canonical finding's required provenance and evidence fields.
pub fn validate_canonical_finding(finding: &CanonicalFinding) -> ContractResult<()> {
    if finding.id.trim().is_empty()
        || finding.title.trim().is_empty()
        || finding.description.trim().is_empty()
        || finding.severity.trim().is_empty()
    {
        return Err(ContractError::MissingEvidence);
    }
    if finding.provenance.rule_id.trim().is_empty()
        || finding.provenance.snapshot.trim().is_empty()
        || finding.provenance.scanner_version.trim().is_empty()
    {
        return Err(ContractError::MissingProvenance);
    }
    if finding.evidence.file_path.trim().is_empty()
        || finding.evidence.line_number <= 0
        || finding.evidence.snippet.trim().is_empty()
    {
        return Err(ContractError::MissingEvidence);
    }
    if !finding.evidence.redacted {
        return Err(ContractError::UnredactedEvidence);
    }
    Ok(())
}

/// Scanner-owned severity table. The reporter must preserve these values.
fn scanner_severity(scanner: &ScannerKind, rule_id: &str) -> String {
    match (scanner, rule_id) {
        (ScannerKind::Gitleaks, _) => "high".to_string(),
        (ScannerKind::Semgrep, rule) if rule.contains("critical") => "critical".to_string(),
        (ScannerKind::Semgrep, _) => "medium".to_string(),
        (ScannerKind::Osv, _) => "high".to_string(),
        (ScannerKind::Other, _) => "medium".to_string(),
    }
}

fn scanner_title(scanner: &ScannerKind, rule_id: &str) -> String {
    match scanner {
        ScannerKind::Gitleaks => format!("Exposed secret: {rule_id}"),
        ScannerKind::Osv => format!("Vulnerable dependency: {rule_id}"),
        ScannerKind::Semgrep => format!("Static analysis finding: {rule_id}"),
        ScannerKind::Other => format!("Scanner finding: {rule_id}"),
    }
}

fn scanner_description(scanner: &ScannerKind, rule_id: &str) -> String {
    match scanner {
        ScannerKind::Gitleaks => format!("gitleaks rule {rule_id}"),
        ScannerKind::Osv => format!("osv package {rule_id}"),
        ScannerKind::Semgrep => format!("semgrep rule {rule_id}"),
        ScannerKind::Other => format!("scanner rule {rule_id}"),
    }
}

fn scanner_cwe(scanner: &ScannerKind, rule_id: &str) -> Option<String> {
    match scanner {
        ScannerKind::Gitleaks => Some("CWE-798".to_string()),
        ScannerKind::Osv => Some("CWE-1104".to_string()),
        ScannerKind::Semgrep => {
            let normalized = format!("CWE-{rule_id}").replace("CWE-CWE-", "CWE-");
            Some(normalized)
        }
        ScannerKind::Other => None,
    }
}

fn scanner_owasp(scanner: &ScannerKind, _rule_id: &str) -> Option<String> {
    match scanner {
        ScannerKind::Gitleaks => Some("A07:2021".to_string()),
        ScannerKind::Osv => Some("A06:2021".to_string()),
        ScannerKind::Semgrep => Some("A03:2021".to_string()),
        ScannerKind::Other => None,
    }
}

/// Require already-redacted evidence before persistence, reporting, or AI input.
pub fn require_redacted_evidence(evidence: &Evidence) -> ContractResult<()> {
    if evidence.snippet.trim().is_empty() {
        return Err(ContractError::MissingEvidence);
    }
    if !evidence.redacted {
        return Err(ContractError::UnredactedEvidence);
    }
    Ok(())
}

/// Validate a completed or partial `ScanResult`.
///
/// A completed result must have every scanner run successful. A partial result
/// must include at least one failed/timed-out scanner and name it in `error`.
pub fn validate_scan_result(result: &ScanResult) -> ContractResult<()> {
    if result.contract_version != CONTRACT_VERSION {
        return Err(ContractError::UnsupportedVersion(result.contract_version));
    }
    normalize_repository_url(&result.repository.repository_url)?;
    validate_snapshot(&result.snapshot)?;
    if result.repository.repository_url != result.snapshot.repository_url
        || result.repository.branch != result.snapshot.branch
    {
        return Err(ContractError::InconsistentResult {
            reason: "repository target and snapshot disagree".to_string(),
        });
    }

    let failed_scanners: Vec<String> = result
        .scanner_runs
        .iter()
        .filter(|run| matches!(run.status, ScannerStatus::Failed | ScannerStatus::TimedOut))
        .map(|run| run.scanner.as_str().to_string())
        .collect();
    let any_success = result
        .scanner_runs
        .iter()
        .any(|run| run.status == ScannerStatus::Ok);

    match result.pipeline_state {
        PipelineState::Completed => {
            if !failed_scanners.is_empty() {
                return Err(ContractError::InconsistentResult {
                    reason: "completed scan must not contain failed scanners".to_string(),
                });
            }
            if result.scanner_runs.is_empty() {
                return Err(ContractError::InconsistentResult {
                    reason: "completed scan requires at least one successful scanner run"
                        .to_string(),
                });
            }
            if result
                .scanner_runs
                .iter()
                .any(|run| run.status != ScannerStatus::Ok)
            {
                return Err(ContractError::InconsistentResult {
                    reason: "completed scan requires every scanner run to succeed".to_string(),
                });
            }
        }
        PipelineState::Partial => {
            if failed_scanners.is_empty() || !any_success {
                return Err(ContractError::InconsistentResult {
                    reason: "partial scan requires one success and one scanner failure".to_string(),
                });
            }
            let error = result.error.as_deref().unwrap_or_default();
            if !failed_scanners.iter().all(|name| error.contains(name)) {
                return Err(ContractError::PartialWithoutCause);
            }
        }
        PipelineState::Failed => {
            if result
                .error
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                return Err(ContractError::InconsistentResult {
                    reason: "failed scan must carry an error".to_string(),
                });
            }
        }
        _ => {}
    }

    for finding in &result.findings {
        validate_canonical_finding(finding)?;
    }
    Ok(())
}

/// Validate an AI/report input before any report text is produced.
///
/// Reports may only explain or prioritize findings that already exist. The id
/// set must match exactly: no invented findings, no dropped findings.
pub fn validate_report_input(
    findings: &[CanonicalFinding],
    report_findings: &[ReportFinding],
) -> ContractResult<()> {
    if findings.is_empty() {
        return Err(ContractError::InvalidReportInput {
            reason: "report requires at least one canonical finding".to_string(),
        });
    }
    let mut expected: BTreeMap<&str, &CanonicalFinding> = BTreeMap::new();
    for finding in findings {
        validate_canonical_finding(finding)?;
        if expected.insert(finding.id.as_str(), finding).is_some() {
            return Err(ContractError::InvalidReportInput {
                reason: format!("duplicate finding id {}", finding.id),
            });
        }
    }
    if report_findings.len() != findings.len() {
        return Err(ContractError::InvalidReportInput {
            reason: "report must cover every canonical finding exactly once".to_string(),
        });
    }
    let mut seen = BTreeSet::new();
    for report_finding in report_findings {
        if report_finding.summary.trim().is_empty() {
            return Err(ContractError::InvalidReportInput {
                reason: format!("empty summary for {}", report_finding.finding_id),
            });
        }
        if !seen.insert(report_finding.finding_id.as_str()) {
            return Err(ContractError::InvalidReportInput {
                reason: format!("duplicate report finding {}", report_finding.finding_id),
            });
        }
        if !expected.contains_key(report_finding.finding_id.as_str()) {
            return Err(ContractError::InvalidReportInput {
                reason: format!("unknown finding {}", report_finding.finding_id),
            });
        }
    }
    Ok(())
}

/// Guard a reporter attempting to change scanner-owned severity.
pub fn check_report_severity_unchanged(from: &str, to: &str) -> ContractResult<()> {
    if from.trim().is_empty() || to.trim().is_empty() {
        return Err(ContractError::InvalidReportInput {
            reason: "severity must be non-empty".to_string(),
        });
    }
    if from != to {
        return Err(ContractError::SeverityChanged {
            from: from.to_string(),
            to: to.to_string(),
        });
    }
    Ok(())
}
