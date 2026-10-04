//! Versioned canonical audit contract for multi-scanner results.
//!
//! This is the runtime normalization contract used after all scanner phases.
//! It is intentionally separate from the frozen Phase 0 `scan_contract` test
//! model: Phase 0 pins historical product rules, while this module describes
//! what the current adapters actually emit and what the pipeline guarantees.
//!
//! A canonical audit never invents scanner metadata. It preserves provenance,
//! validates evidence, assigns deterministic identities, keeps successful
//! scanners' findings when another scanner fails, and leaves the security
//! score unavailable unless every scanner reported successfully.

use crate::models::Severity;
use crate::schemas::audit_state::Finding;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Version tag for every canonical audit document. Consumers must reject
/// documents whose version they do not understand.
pub const CANONICAL_AUDIT_VERSION: u32 = 1;

/// Maximum evidence characters accepted at the canonical boundary.
///
/// Adapters already truncate evidence to about 400 characters. The canonical
/// bound is deliberately a little larger so truncation markers survive, but far
/// below any size that could turn one finding into a payload problem.
pub const MAX_CANONICAL_EVIDENCE_CHARS: usize = 512;

/// Maximum serialized bytes accepted for one finding's curated metadata.
///
/// Scanner metadata is already selected by the adapters, but an advisory or
/// rule can in principle carry many references or ranges. Anything larger is
/// rejected and recorded instead of being silently carried forward.
pub const MAX_CANONICAL_METADATA_BYTES: usize = 8192;

/// Maximum references accepted from one finding.
pub const MAX_CANONICAL_REFERENCES: usize = 64;

/// Maximum characters accepted for one reference URL.
pub const MAX_CANONICAL_REFERENCE_URL_CHARS: usize = 2048;

/// Maximum characters accepted for a title, description, or remediation.
///
/// Adapters bound the longest scanner-controlled fields well below this. The
/// canonical bound is a backstop for programmatically constructed findings,
/// not a license to accept unbounded scanner prose.
pub const MAX_CANONICAL_TEXT_CHARS: usize = 4096;

/// Execution status after unifying all scanner outcomes.
///
/// `SuccessClean` and `SuccessFindings` are distinguished explicitly because a
/// clean result and a result with findings have different meanings downstream.
/// `NoFilesAnalyzed` is its own status because “the scanner looked at nothing”
// is unknown coverage, never clean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalScannerStatus {
    SuccessClean,
    SuccessFindings { finding_count: usize },
    Failed { reason: String },
    Timeout { limit_secs: u64 },
    Cancelled,
    NoFilesAnalyzed { reason: String },
}

impl CanonicalScannerStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SuccessClean => "success_clean",
            Self::SuccessFindings { .. } => "success_findings",
            Self::Failed { .. } => "failed",
            Self::Timeout { .. } => "timeout",
            Self::Cancelled => "cancelled",
            Self::NoFilesAnalyzed { .. } => "no_files_analyzed",
        }
    }

    pub fn coverage_known(&self) -> bool {
        matches!(self, Self::SuccessClean | Self::SuccessFindings { .. })
    }

    pub fn finding_count(&self) -> Option<usize> {
        match self {
            Self::SuccessClean => Some(0),
            Self::SuccessFindings { finding_count } => Some(*finding_count),
            _ => None,
        }
    }
}

/// Aggregate scanner coverage for one audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Complete,
    Partial,
    Absent,
}

impl CoverageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Absent => "absent",
        }
    }
}

/// Provenance retained for every canonical finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalProvenance {
    pub scanner: String,
    pub scanner_version: String,
    pub parser: String,
    pub scanner_image: String,
    pub rule_id: String,
    pub native_fingerprint: String,
    pub snapshot_commit: Option<String>,
}

/// Normalized finding location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalLocation {
    pub file: String,
    pub line: i32,
    pub start_column: Option<i64>,
    pub end_line: Option<i64>,
    pub end_column: Option<i64>,
}

/// Curated reference preserved from scanner metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalReference {
    #[serde(rename = "type")]
    pub reference_type: String,
    pub url: String,
}

/// One validated canonical finding.
///
/// `id` is deterministic and independent of scanner result ordering. The
/// database/storage row identifier is preserved separately because storage
/// needs a stable primary key across reruns while canonical identity needs a
/// deterministic content identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalAuditFinding {
    pub id: String,
    pub agent_source: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Option<String>,
    pub confidence_source: ConfidenceSource,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub remediation: Option<String>,
    pub provenance: CanonicalProvenance,
    pub native_id: String,
    pub location: CanonicalLocation,
    pub evidence: String,
    pub evidence_kind: EvidenceKind,
    pub evidence_truncated: bool,
    pub references: Vec<CanonicalReference>,
    pub scanner_metadata: BTreeMap<String, serde_json::Value>,
}

/// Where the confidence value came from.
///
/// Gitleaks always reports `"high"` as an adapter convention, not as a
/// detector measurement. Calling that `Scanner` would overstate the evidence,
// so the canonical contract distinguishes adapter defaults from scanner
// measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceSource {
    Scanner,
    ScannerDefault,
    Absent,
}

/// Evidence category, used only to select validation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Secret,
    Dependency,
    Source,
    Unknown,
}

/// One group of findings that share an exact canonical identity.
///
/// Duplicates are correlated, not silently discarded: the representative
/// finding is stored once, while every occurrence stays in the group with its
/// own storage identifier and provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingCorrelation {
    pub correlation_id: String,
    pub canonical_id: String,
    pub basis: CorrelationBasis,
    pub occurrences: usize,
    pub provenance: Vec<CanonicalProvenance>,
}

/// The only automatic correlation basis currently implemented.
///
/// No cross-scanner inference is performed. Two findings from different
/// scanners therefore never share a canonical identity and are never merged.
// The schema can represent explicit future bases without changing this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationBasis {
    ExactCanonicalIdentity,
}

/// A finding excluded from canonical output, with a safe failure record.
///
/// The original evidence and metadata are deliberately not repeated here: an
/// invalid finding must not leak through its own validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidFinding {
    pub id: String,
    pub scanner: Option<String>,
    pub file: Option<String>,
    pub reason: String,
    pub evidence_chars: Option<usize>,
}

/// One scanner's canonical execution status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalScannerRun {
    pub scanner: String,
    pub version: String,
    pub parser: String,
    pub mode: String,
    pub image: String,
    pub status: CanonicalScannerStatus,
    pub finding_count: Option<usize>,
    pub coverage_known: bool,
    pub detail: Option<String>,
    pub limitations: Vec<String>,
}

/// Aggregate coverage derived from scanner runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalCoverage {
    pub status: CoverageStatus,
    pub complete: bool,
    pub successful_scanners: Vec<String>,
    pub unsuccessful_scanners: BTreeMap<String, String>,
    pub limitations: Vec<String>,
}

/// Aggregate finding counts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalSummary {
    pub finding_count: usize,
    pub valid_finding_count: usize,
    pub invalid_finding_count: usize,
    pub duplicate_group_count: usize,
    pub findings_by_scanner: BTreeMap<String, usize>,
    pub findings_by_severity: BTreeMap<String, usize>,
    pub security_score: Option<f64>,
}

/// The versioned canonical audit document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CanonicalAudit {
    pub schema_version: u32,
    pub scan_id: String,
    pub repository_url: String,
    pub repo_branch: String,
    pub repo_owner: String,
    pub repo_name: String,
    pub snapshot_commit: Option<String>,
    pub snapshot_file_count: usize,
    pub snapshot_total_size: u64,
    pub scanner_runs: Vec<CanonicalScannerRun>,
    pub coverage: CanonicalCoverage,
    pub findings: Vec<CanonicalAuditFinding>,
    pub correlations: Vec<FindingCorrelation>,
    pub invalid_findings: Vec<InvalidFinding>,
    pub limitations: Vec<String>,
    pub summary: CanonicalSummary,
}

/// Errors that prevent building a canonical audit at all.
///
/// Invalid individual findings do not produce this error; they are excluded
// from `findings` and represented in `invalid_findings`.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CanonicalAuditError {
    #[error("canonical audit requires a scan id")]
    MissingScanId,
    #[error("canonical audit requires a repository URL")]
    MissingRepository,
    #[error("canonical audit requires at least one scanner run")]
    MissingScannerRuns,
    #[error("security score {0:?} is inconsistent with {1} coverage")]
    InconsistentScore(Option<f64>, &'static str),
    #[error("canonical audit requires a snapshot commit")]
    MissingSnapshot,
}

/// Parse curated finding metadata.
///
/// Metadata must be a JSON object. Anything else is invalid: canonical code
// must not guess at unstructured scanner output.
pub fn parse_metadata(finding: &Finding) -> Result<BTreeMap<String, serde_json::Value>, String> {
    let raw = finding.metadata_json.as_deref().unwrap_or("{}");
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| "metadata is not valid JSON".to_string())?;
    match value {
        serde_json::Value::Object(map) => Ok(map.into_iter().collect()),
        _ => Err("metadata is not a JSON object".to_string()),
    }
}

/// Canonical rule identity for a finding.
///
/// Scanner adapters already normalize the primary identifier to `rule_id`;
// `check_id` and `advisory` aliases are accepted for compatibility, but a
// finding without any rule identity is invalid rather than guessable.
pub fn native_rule_id(metadata: &BTreeMap<String, serde_json::Value>) -> Result<String, String> {
    for key in ["rule_id", "check_id", "advisory"] {
        if let Some(rule) = metadata.get(key).and_then(|value| value.as_str()) {
            if !rule.trim().is_empty() {
                return Ok(rule.to_string());
            }
        }
    }
    Err("finding has no rule identity".to_string())
}

/// Scanner-native fingerprint when present.
pub fn native_fingerprint(
    metadata: &BTreeMap<String, serde_json::Value>,
) -> Result<String, String> {
    match metadata.get("fingerprint").and_then(|value| value.as_str()) {
        Some(fingerprint) if !fingerprint.trim().is_empty() => Ok(fingerprint.to_string()),
        _ => Err("finding has no native fingerprint".to_string()),
    }
}

/// Recursively sort JSON object keys so canonical output does not depend on
/// parser or construction order.
pub fn sort_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> = map
                .into_iter()
                .map(|(key, value)| (key, sort_json(value)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sort_json).collect())
        }
        scalar => scalar,
    }
}

/// Collect every distinct string in a JSON value, for secret-safety scans.
///
/// Only scalar strings are collected. Object keys are scanner-controlled field
// names, not evidence, and are validated separately by shape.
pub fn metadata_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => out.push(text.clone()),
        serde_json::Value::Array(values) => {
            for value in values {
                metadata_strings(value, out);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values() {
                metadata_strings(value, out);
            }
        }
        _ => {}
    }
}

/// Validate that a repository-relative path cannot escape the snapshot.
pub fn validate_repo_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("file path is empty".to_string());
    }
    if trimmed.len() > 1024 {
        return Err("file path is too long".to_string());
    }
    if trimmed.starts_with('/') || trimmed.contains('\\') || trimmed.contains('\0') {
        return Err("file path is not repository-relative".to_string());
    }
    if trimmed.split('/').any(|part| part == "..") {
        return Err("file path escapes the repository".to_string());
    }
    if trimmed.chars().any(char::is_control) {
        return Err("file path contains control characters".to_string());
    }
    Ok(trimmed.to_string())
}

/// Validate that a snapshot commit is either absent or a 40-character
/// lowercase hex digest.
pub fn validate_snapshot_commit(commit: Option<&str>) -> Result<Option<String>, String> {
    match commit {
        None => Ok(None),
        Some(value) if value.trim().is_empty() => Ok(None),
        Some(value) => {
            let valid = value.len() == 40
                && value
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
            if valid {
                Ok(Some(value.to_string()))
            } else {
                Err("snapshot commit is not a 40-character lowercase hex digest".to_string())
            }
        }
    }
}

/// Stable severity name for summary keys.
pub fn severity_name(severity: &Severity) -> &'static str {
    severity.as_str()
}

/// Collect distinct scanner names in sorted order.
pub fn sorted_scanners<'a, I>(scanners: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut names: BTreeSet<String> = BTreeSet::new();
    for scanner in scanners {
        if !scanner.trim().is_empty() {
            names.insert(scanner.to_string());
        }
    }
    names.into_iter().collect()
}
