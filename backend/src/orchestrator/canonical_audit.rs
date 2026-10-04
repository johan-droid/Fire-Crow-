//! Canonical multi-scanner normalization.
//!
//! The scanner adapters stay authoritative about detection. This module is
//! authoritative about integration: it turns usable scanner results into one
//! deterministic, provenance-preserving audit without inventing metadata,
//! merging distinct findings, or converting failure into clean.

use crate::agents::scanner::{ScannerOutcome, ScannerResult};
use crate::schemas::audit_state::Finding;
use crate::schemas::canonical_audit::{
    metadata_strings, native_fingerprint, native_rule_id, parse_metadata, sort_json,
    validate_repo_path, validate_snapshot_commit, CanonicalAudit, CanonicalAuditError,
    CanonicalAuditFinding, CanonicalCoverage, CanonicalLocation, CanonicalProvenance,
    CanonicalReference, CanonicalScannerRun, CanonicalScannerStatus, CanonicalSummary,
    ConfidenceSource, CorrelationBasis, CoverageStatus, EvidenceKind, FindingCorrelation,
    InvalidFinding, CANONICAL_AUDIT_VERSION, MAX_CANONICAL_EVIDENCE_CHARS,
    MAX_CANONICAL_METADATA_BYTES, MAX_CANONICAL_REFERENCES, MAX_CANONICAL_REFERENCE_URL_CHARS,
    MAX_CANONICAL_TEXT_CHARS,
};
use crate::services::redaction::contains_known_credential_assignment;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Scanner identity expected by canonical normalization.
const KNOWN_SCANNERS: [(&str, &str); 3] = [
    ("gitleaks", "secret"),
    ("osv", "dependency"),
    ("semgrep", "sast"),
];

/// Input for one canonical audit.
pub struct CanonicalAuditRequest<'a> {
    pub scan_id: &'a str,
    pub repository_url: &'a str,
    pub repo_branch: &'a str,
    pub repo_owner: &'a str,
    pub repo_name: &'a str,
    pub snapshot_commit: Option<&'a str>,
    pub snapshot_file_count: usize,
    pub snapshot_total_size: u64,
    pub results: &'a [ScannerResult],
    pub findings: &'a [Finding],
    pub security_score: Option<f64>,
}

struct NormalizedFinding {
    finding: Finding,
    metadata: BTreeMap<String, serde_json::Value>,
    canonical_id: String,
    native_id: String,
    provenance: CanonicalProvenance,
    location: CanonicalLocation,
    evidence_kind: EvidenceKind,
    evidence_text: String,
    evidence_truncated: bool,
}

struct NormalizedFindings {
    valid: Vec<NormalizedFinding>,
    invalid: Vec<InvalidFinding>,
    correlations: usize,
    valid_count_by_scanner: BTreeMap<String, usize>,
    valid_count_by_severity: BTreeMap<String, usize>,
}

/// Build the versioned canonical audit.
pub fn canonical_audit(
    request: &CanonicalAuditRequest,
) -> Result<CanonicalAudit, CanonicalAuditError> {
    if request.scan_id.trim().is_empty() {
        return Err(CanonicalAuditError::MissingScanId);
    }
    if request.repository_url.trim().is_empty() {
        return Err(CanonicalAuditError::MissingRepository);
    }
    if request.results.is_empty() {
        return Err(CanonicalAuditError::MissingScannerRuns);
    }

    let snapshot_commit = validate_snapshot_commit(request.snapshot_commit)
        .map_err(|_| CanonicalAuditError::MissingSnapshot)?;
    let borrowed: Vec<&ScannerResult> = request.results.iter().collect();
    let runs = canonical_scanner_runs(&borrowed);
    let coverage = canonical_coverage(&runs);
    if coverage.status != CoverageStatus::Complete && request.security_score.is_some() {
        return Err(CanonicalAuditError::InconsistentScore(
            request.security_score,
            coverage.status.as_str(),
        ));
    }

    let normalized = normalize_findings(request.findings, snapshot_commit.as_deref());
    let invalid_count = normalized.invalid.len();
    let findings: Vec<CanonicalAuditFinding> = normalized
        .valid
        .into_iter()
        .map(canonical_finding)
        .collect();
    let correlations = correlate_findings(&findings);

    Ok(CanonicalAudit {
        schema_version: CANONICAL_AUDIT_VERSION,
        scan_id: request.scan_id.to_string(),
        repository_url: request.repository_url.to_string(),
        repo_branch: request.repo_branch.to_string(),
        repo_owner: request.repo_owner.to_string(),
        repo_name: request.repo_name.to_string(),
        snapshot_commit,
        snapshot_file_count: request.snapshot_file_count,
        snapshot_total_size: request.snapshot_total_size,
        scanner_runs: runs,
        coverage: coverage.clone(),
        findings,
        correlations,
        invalid_findings: normalized.invalid.clone(),
        limitations: coverage.limitations.clone(),
        summary: canonical_summary(
            &coverage,
            &normalized.valid_count_by_scanner,
            &normalized.valid_count_by_severity,
            invalid_count,
            normalized.correlations,
            request.security_score,
        ),
    })
}

/// Map one scanner execution onto the unified canonical status.
fn canonical_status(result: &ScannerResult) -> CanonicalScannerStatus {
    match &result.outcome {
        ScannerOutcome::Success { finding_count } => {
            if *finding_count == 0 {
                CanonicalScannerStatus::SuccessClean
            } else {
                CanonicalScannerStatus::SuccessFindings {
                    finding_count: *finding_count,
                }
            }
        }
        ScannerOutcome::Failed { reason } => {
            let detail = result
                .execution_record
                .get("detail")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            if detail == "no_files_analyzed" {
                CanonicalScannerStatus::NoFilesAnalyzed {
                    reason: reason.clone(),
                }
            } else {
                CanonicalScannerStatus::Failed {
                    reason: reason.clone(),
                }
            }
        }
        ScannerOutcome::Timeout { limit_secs } => CanonicalScannerStatus::Timeout {
            limit_secs: *limit_secs,
        },
        ScannerOutcome::Cancelled => CanonicalScannerStatus::Cancelled,
    }
}

/// Build sorted canonical scanner runs.
fn canonical_scanner_runs(results: &[&ScannerResult]) -> Vec<CanonicalScannerRun> {
    let mut runs = results
        .iter()
        .map(|result| {
            let status = canonical_status(result);
            let text = |key: &str| {
                result
                    .execution_record
                    .get(key)
                    .and_then(|value| value.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let mut limitations = Vec::new();
            if !status.coverage_known() {
                limitations.push(format!(
                    "scanner {} did not analyze the repository ({})",
                    result.scanner,
                    status.as_str()
                ));
            }
            if result.scanner == "semgrep" {
                if let Some(rejected) = result
                    .execution_record
                    .get("rejected_count")
                    .and_then(|value| value.as_u64())
                {
                    if rejected > 0 {
                        limitations.push(format!(
                            "scanner semgrep excluded {rejected} detections with invalid locations"
                        ));
                    }
                }
            }
            CanonicalScannerRun {
                scanner: result.scanner.clone(),
                version: result.version.clone(),
                parser: text("parser"),
                mode: text("mode"),
                image: text("image"),
                status: status.clone(),
                finding_count: status.finding_count(),
                coverage_known: status.coverage_known(),
                detail: match &status {
                    CanonicalScannerStatus::Failed { reason }
                    | CanonicalScannerStatus::NoFilesAnalyzed { reason } => Some(reason.clone()),
                    CanonicalScannerStatus::Timeout { limit_secs } => {
                        Some(format!("timeout after {limit_secs}s"))
                    }
                    CanonicalScannerStatus::Cancelled => Some("cancelled".to_string()),
                    _ => None,
                },
                limitations,
            }
        })
        .collect::<Vec<_>>();
    runs.sort_by(|a, b| a.scanner.cmp(&b.scanner));
    runs
}

/// Derive aggregate coverage from canonical scanner runs.
fn canonical_coverage(runs: &[CanonicalScannerRun]) -> CanonicalCoverage {
    let mut successful = Vec::new();
    let mut unsuccessful = BTreeMap::new();
    let mut limitations = BTreeSet::new();
    for run in runs {
        if run.coverage_known {
            successful.push(run.scanner.clone());
        } else {
            unsuccessful.insert(run.scanner.clone(), run.status.as_str().to_string());
        }
        for limitation in &run.limitations {
            limitations.insert(limitation.clone());
        }
    }
    successful.sort();
    let status = if successful.len() == runs.len() {
        CoverageStatus::Complete
    } else if successful.is_empty() {
        CoverageStatus::Absent
    } else {
        CoverageStatus::Partial
    };
    CanonicalCoverage {
        status,
        complete: status == CoverageStatus::Complete,
        successful_scanners: successful,
        unsuccessful_scanners: unsuccessful,
        limitations: limitations.into_iter().collect(),
    }
}

/// Validate, identify, sort, and group findings without merging distinct rows.
fn normalize_findings(findings: &[Finding], snapshot_commit: Option<&str>) -> NormalizedFindings {
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    let mut valid_count_by_scanner = BTreeMap::new();
    let mut valid_count_by_severity = BTreeMap::new();
    for finding in findings {
        match normalize_finding(finding, snapshot_commit) {
            Ok(normalized) => valid.push(normalized),
            Err(reason) => invalid.push(InvalidFinding {
                id: String::new(),
                scanner: finding.scanner_name.clone(),
                file: finding.file_path.clone(),
                reason,
                evidence_chars: finding
                    .evidence
                    .as_ref()
                    .map(|evidence| evidence.chars().count()),
            }),
        }
    }

    valid.sort_by(|a, b| a.canonical_id.cmp(&b.canonical_id));
    let mut grouped: BTreeMap<String, Vec<NormalizedFinding>> = BTreeMap::new();
    for finding in valid {
        grouped
            .entry(finding.canonical_id.clone())
            .or_default()
            .push(finding);
    }
    let mut deduplicated = Vec::new();
    let mut correlations = 0usize;
    for group in grouped.into_values() {
        let occurrences = group.len();
        if occurrences > 1 {
            correlations += 1;
        }
        let mut ordered = group;
        // Smallest storage identifier wins so the retained representative is
        // deterministic for a given input set.
        ordered.sort_by(|a, b| a.finding.id.cmp(&b.finding.id));
        if let Some(mut representative) = ordered.into_iter().next() {
            // Record the merge on the retained row without changing its
            // canonical identity: `duplicate_occurrences` is provenance
            // bookkeeping, never an identity input.
            if occurrences > 1 {
                if let Some(raw) = representative.finding.metadata_json.as_deref() {
                    if let Ok(serde_json::Value::Object(mut metadata)) = serde_json::from_str(raw) {
                        metadata.insert(
                            "duplicate_occurrences".to_string(),
                            serde_json::json!(occurrences),
                        );
                        representative.finding.metadata_json =
                            Some(serde_json::Value::Object(metadata).to_string());
                    }
                }
            }
            deduplicated.push(representative);
        }
    }
    deduplicated.sort_by(|a, b| a.canonical_id.cmp(&b.canonical_id));
    // Counts are taken from the deduplicated canonical set. Counting before
    // deduplication made `summary.finding_count` disagree with
    // `findings.len()` for the same audit, which is exactly the kind of
    // silent disagreement a canonical contract must never contain.
    for finding in &deduplicated {
        *valid_count_by_scanner
            .entry(finding.provenance.scanner.clone())
            .or_insert(0) += 1;
        *valid_count_by_severity
            .entry(finding.finding.severity.as_str().to_string())
            .or_insert(0) += 1;
    }

    // Deterministic invalid identifiers without storage UUIDs: sort by stable
    // fields first, then number identical descriptors in order.
    invalid.sort_by(|a, b| {
        (
            a.scanner.clone().unwrap_or_default(),
            a.file.clone().unwrap_or_default(),
            &a.reason,
            a.evidence_chars.unwrap_or(0),
        )
            .cmp(&(
                b.scanner.clone().unwrap_or_default(),
                b.file.clone().unwrap_or_default(),
                &b.reason,
                b.evidence_chars.unwrap_or(0),
            ))
    });
    let mut last_key: Option<(String, String, String, usize)> = None;
    let mut occurrence = 0usize;
    for item in &mut invalid {
        let key = (
            item.scanner.clone().unwrap_or_default(),
            item.file.clone().unwrap_or_default(),
            item.reason.clone(),
            item.evidence_chars.unwrap_or(0),
        );
        if last_key.as_ref() == Some(&key) {
            occurrence += 1;
        } else {
            occurrence = 0;
        }
        last_key = Some(key.clone());
        item.id = format!(
            "invalid-v1:{}",
            sha256_hex(&format!(
                "{}|{}|{}|{}|{occurrence}",
                key.0, key.1, key.2, key.3
            ))
        );
    }

    NormalizedFindings {
        valid: deduplicated,
        invalid,
        correlations,
        valid_count_by_scanner,
        valid_count_by_severity,
    }
}

/// Validate one finding and derive its canonical identity.
fn normalize_finding(
    finding: &Finding,
    snapshot_commit: Option<&str>,
) -> Result<NormalizedFinding, String> {
    let (scanner, mode) = match (&finding.scanner_name, &finding.scanner_mode) {
        (Some(scanner), Some(mode)) => (scanner.as_str(), mode.as_str()),
        _ => return Err("finding has no scanner identity".to_string()),
    };
    if !KNOWN_SCANNERS
        .iter()
        .any(|(name, scanner_mode)| *name == scanner && *scanner_mode == mode)
    {
        return Err("finding has an unknown scanner identity".to_string());
    }
    if finding.agent_source != scanner {
        return Err("finding scanner identity mismatch".to_string());
    }
    if finding.title.trim().is_empty() {
        return Err("finding title is empty".to_string());
    }
    if finding.description.trim().is_empty() {
        return Err("finding description is empty".to_string());
    }
    check_text("title", &finding.title)?;
    check_text("description", &finding.description)?;
    if let Some(remediation) = finding.remediation.as_deref() {
        check_text("remediation", remediation)?;
    }

    let metadata = parse_metadata(finding)?;
    check_metadata_size(&metadata)?;
    let rule_id = native_rule_id(&metadata)?;
    let native_fp = native_fingerprint(&metadata)?;
    let provenance = finding_provenance(finding, &metadata, snapshot_commit)?;
    let location = finding_location(finding, &metadata)?;
    let evidence_kind = match scanner {
        "gitleaks" => EvidenceKind::Secret,
        "osv" => EvidenceKind::Dependency,
        "semgrep" => EvidenceKind::Source,
        _ => EvidenceKind::Unknown,
    };
    let evidence_text = finding
        .evidence
        .as_deref()
        .map(str::trim)
        .filter(|evidence| !evidence.is_empty())
        .ok_or_else(|| "finding evidence is empty".to_string())?;
    check_evidence(evidence_kind, evidence_text)?;
    let evidence_truncated = evidence_text.contains("... [truncated]");
    let canonical_id =
        canonical_finding_id(scanner, &rule_id, &native_fp, &location, &metadata, finding)?;
    Ok(NormalizedFinding {
        finding: finding.clone(),
        metadata,
        canonical_id: canonical_id.clone(),
        native_id: format!("{scanner}:{native_fp}"),
        provenance,
        location,
        evidence_kind,
        evidence_text: evidence_text.to_string(),
        evidence_truncated,
    })
}

/// Provenance retained for every canonical finding.
fn finding_provenance(
    finding: &Finding,
    metadata: &BTreeMap<String, serde_json::Value>,
    snapshot_commit: Option<&str>,
) -> Result<CanonicalProvenance, String> {
    let scanner = finding.scanner_name.clone().unwrap_or_default();
    let string = |key: &str| {
        metadata
            .get(key)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| format!("finding metadata has no {key}"))
    };
    Ok(CanonicalProvenance {
        scanner,
        scanner_version: string("scanner_version")?,
        parser: string("parser")?,
        scanner_image: string("scanner_image")?,
        rule_id: native_rule_id(metadata)?,
        native_fingerprint: native_fingerprint(metadata)?,
        snapshot_commit: validate_snapshot_commit(
            metadata
                .get("snapshot_commit")
                .and_then(|value| value.as_str())
                .or(snapshot_commit),
        )
        .map_err(|_| "finding snapshot commit is invalid".to_string())?,
    })
}

/// Normalized finding location.
fn finding_location(
    finding: &Finding,
    metadata: &BTreeMap<String, serde_json::Value>,
) -> Result<CanonicalLocation, String> {
    let file = finding
        .file_path
        .as_deref()
        .ok_or_else(|| "finding file is missing".to_string())?;
    let file = validate_repo_path(file).map_err(|_| "finding file is invalid".to_string())?;
    let line = finding
        .line_number
        .filter(|line| *line > 0)
        .ok_or_else(|| "finding line is invalid".to_string())?;
    let number = |key: &str| match metadata.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| format!("finding metadata {key} is not an integer")),
    };
    let start_column = number("start_column")?;
    let end_line = number("end_line")?;
    let end_column = number("end_column")?;
    if start_column.is_some_and(|column| column < 0) {
        return Err("finding start column is invalid".to_string());
    }
    if end_column.is_some_and(|column| column < 0) {
        return Err("finding end column is invalid".to_string());
    }
    if let Some(end) = end_line {
        if end < i64::from(line) {
            return Err("finding end line precedes start line".to_string());
        }
        if end == i64::from(line) {
            if let (Some(start), Some(end)) = (start_column, end_column) {
                if end != 0 && start != 0 && end < start {
                    return Err("finding end column precedes start column".to_string());
                }
            }
        }
    }
    Ok(CanonicalLocation {
        file,
        line,
        start_column,
        end_line,
        end_column,
    })
}

/// Type-specific evidence checks.
fn check_evidence(kind: EvidenceKind, evidence: &str) -> Result<(), String> {
    if evidence.chars().count() > MAX_CANONICAL_EVIDENCE_CHARS {
        return Err("finding evidence exceeds the canonical bound".to_string());
    }
    match kind {
        EvidenceKind::Secret => {
            if !(evidence.contains("[REDACTED]") || evidence.contains("[BASE64_REDACTED]")) {
                return Err("secret evidence has no redaction marker".to_string());
            }
        }
        EvidenceKind::Dependency | EvidenceKind::Source | EvidenceKind::Unknown => {
            if contains_known_credential_assignment(evidence) {
                return Err("evidence contains an unredacted credential shape".to_string());
            }
        }
    }
    Ok(())
}

/// Generic text bound shared by titles, descriptions, and remediation.
fn check_text(field: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("finding {field} is empty"));
    }
    if value.chars().count() > MAX_CANONICAL_TEXT_CHARS {
        return Err(format!("finding {field} exceeds the canonical bound"));
    }
    Ok(())
}

/// Validate curated metadata size and secret safety.
fn check_metadata_size(metadata: &BTreeMap<String, serde_json::Value>) -> Result<(), String> {
    let sorted = sort_json(serde_json::Value::Object(
        metadata.clone().into_iter().collect(),
    ));
    let serialized = serde_json::to_string(&sorted)
        .map_err(|_| "finding metadata cannot be serialized".to_string())?;
    if serialized.len() > MAX_CANONICAL_METADATA_BYTES {
        return Err("finding metadata exceeds the canonical bound".to_string());
    }
    let mut strings = Vec::new();
    metadata_strings(&sorted, &mut strings);
    if strings
        .iter()
        .any(|text| contains_known_credential_assignment(text))
    {
        return Err("finding metadata contains an unredacted credential shape".to_string());
    }
    Ok(())
}

/// Canonical references preserved from scanner metadata.
fn canonical_references(
    metadata: &BTreeMap<String, serde_json::Value>,
) -> Result<Vec<CanonicalReference>, String> {
    let Some(references) = metadata.get("references") else {
        return Ok(Vec::new());
    };
    let references = references
        .as_array()
        .ok_or_else(|| "finding references are invalid".to_string())?;
    if references.len() > MAX_CANONICAL_REFERENCES {
        return Err("finding has too many references".to_string());
    }
    let mut parsed = Vec::new();
    for reference in references {
        let reference_type = reference
            .get("type")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "finding reference type is invalid".to_string())?;
        if reference_type.chars().count() > 32 {
            return Err("finding reference type is too long".to_string());
        }
        let url = reference
            .get("url")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "finding reference URL is invalid".to_string())?;
        if url.chars().count() > MAX_CANONICAL_REFERENCE_URL_CHARS {
            return Err("finding reference URL is too long".to_string());
        }
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err("finding reference URL is invalid".to_string());
        }
        parsed.push(CanonicalReference {
            reference_type: reference_type.to_string(),
            url: url.to_string(),
        });
    }
    parsed.sort_by(|a, b| (&a.url, &a.reference_type).cmp(&(&b.url, &b.reference_type)));
    parsed.dedup_by(|a, b| a.url == b.url && a.reference_type == b.reference_type);
    Ok(parsed)
}

/// Deterministic canonical identity.
///
/// The payload includes scanner, rule, native fingerprint, normalized
/// location/target, and a digest of the evidence. Assessments (severity,
/// confidence) are excluded: rescoring a finding must not re-identify it.
/// Scanner result ordering, database row UUIDs, and JSON key order cannot
/// change it.
///
/// Run-level provenance (scanner version, parser, image, snapshot) is
/// deliberately **not** an identity input. Those fields are attached when a
/// scan is executed, so making them part of identity would give the same
/// detection two different identities depending on whether it was read back
/// from an adapter or from a persisted run. Provenance still travels with
/// every finding; it just does not decide what the finding *is*.
fn canonical_finding_id(
    scanner: &str,
    rule_id: &str,
    native_fingerprint: &str,
    location: &CanonicalLocation,
    metadata: &BTreeMap<String, serde_json::Value>,
    finding: &Finding,
) -> Result<String, String> {
    let mut payload = BTreeMap::new();
    payload.insert("v".to_string(), serde_json::json!(CANONICAL_AUDIT_VERSION));
    payload.insert(
        "scanner".to_string(),
        serde_json::Value::String(scanner.to_string()),
    );
    payload.insert(
        "rule_id".to_string(),
        serde_json::Value::String(rule_id.to_string()),
    );
    payload.insert(
        "native_fingerprint".to_string(),
        serde_json::Value::String(native_fingerprint.to_string()),
    );
    payload.insert(
        "file".to_string(),
        serde_json::Value::String(location.file.clone()),
    );
    payload.insert("line".to_string(), serde_json::json!(location.line));
    payload.insert(
        "start_column".to_string(),
        location
            .start_column
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::Value::Null),
    );
    payload.insert(
        "end_line".to_string(),
        location
            .end_line
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::Value::Null),
    );
    payload.insert(
        "end_column".to_string(),
        location
            .end_column
            .map(|v| serde_json::json!(v))
            .unwrap_or(serde_json::Value::Null),
    );
    for key in [
        "package",
        "installed_version",
        "ecosystem",
        "manifest",
        "advisory",
        "direct",
    ] {
        payload.insert(
            key.to_string(),
            metadata
                .get(key)
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        );
    }
    payload.insert(
        "evidence_sha256".to_string(),
        serde_json::Value::String(sha256_hex(finding.evidence.as_deref().unwrap_or_default())),
    );
    let serialized = serde_json::to_string(&payload)
        .map_err(|_| "finding identity cannot be serialized".to_string())?;
    Ok(format!("canonical-v1:{}", sha256_hex(&serialized)))
}

fn sha256_hex(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

/// Build one canonical finding view from validated input.
fn canonical_finding(normalized: NormalizedFinding) -> CanonicalAuditFinding {
    let finding = normalized.finding;
    let metadata = parse_metadata(&finding).unwrap_or_default();
    let references = canonical_references(&metadata).unwrap_or_default();
    let confidence_source = match finding.scanner_name.as_deref() {
        // Gitleaks has no confidence concept; its adapter records "high" as a
        // fixed convention, so calling that a scanner measurement would
        // overstate the evidence.
        Some("gitleaks") => ConfidenceSource::ScannerDefault,
        Some(_) if finding.confidence.is_some() => ConfidenceSource::Scanner,
        // No scanner-supplied confidence: reported as absent, never defaulted.
        _ => ConfidenceSource::Absent,
    };
    let mut scanner_metadata = BTreeMap::new();
    for (key, value) in metadata {
        scanner_metadata.insert(key, sort_json(value));
    }
    CanonicalAuditFinding {
        id: normalized.canonical_id,
        agent_source: finding.agent_source,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        confidence: finding.confidence,
        confidence_source,
        cwe_id: finding.cwe_id,
        owasp_category: finding.owasp_category,
        remediation: finding.remediation,
        provenance: normalized.provenance,
        native_id: normalized.native_id,
        location: CanonicalLocation {
            file: normalized.location.file,
            line: normalized.location.line,
            start_column: normalized.location.start_column,
            end_line: normalized.location.end_line,
            end_column: normalized.location.end_column,
        },
        evidence: normalized.evidence_text,
        evidence_kind: normalized.evidence_kind,
        evidence_truncated: normalized.evidence_truncated,
        references,
        scanner_metadata,
    }
}

/// Correlate exact canonical duplicates without merging distinct findings.
fn correlate_findings(findings: &[CanonicalAuditFinding]) -> Vec<FindingCorrelation> {
    let mut groups: BTreeMap<String, Vec<&CanonicalAuditFinding>> = BTreeMap::new();
    for finding in findings {
        groups.entry(finding.id.clone()).or_default().push(finding);
    }
    let mut correlations = Vec::new();
    for (canonical_id, group) in groups {
        // A persisted representative carries its merge count in metadata, so
        // duplicate attestations survive persistence even though only one row
        // was stored.
        let persisted_occurrences = group
            .first()
            .and_then(|finding| {
                finding
                    .scanner_metadata
                    .get("duplicate_occurrences")
                    .and_then(|value| value.as_u64())
            })
            .unwrap_or(0) as usize;
        let occurrences = group.len().max(persisted_occurrences).max(1);
        if occurrences > 1 || group.len() > 1 {
            let mut provenance = BTreeSet::new();
            for finding in &group {
                provenance.insert(serde_json::to_string(&finding.provenance).unwrap_or_default());
            }
            correlations.push(FindingCorrelation {
                correlation_id: canonical_id.clone(),
                canonical_id,
                basis: CorrelationBasis::ExactCanonicalIdentity,
                occurrences,
                provenance: provenance
                    .into_iter()
                    .filter_map(|item| serde_json::from_str(&item).ok())
                    .collect(),
            });
        }
    }
    correlations
}

/// Aggregate finding counts.
fn canonical_summary(
    coverage: &CanonicalCoverage,
    valid_count_by_scanner: &BTreeMap<String, usize>,
    valid_count_by_severity: &BTreeMap<String, usize>,
    invalid_count: usize,
    duplicate_groups: usize,
    security_score: Option<f64>,
) -> CanonicalSummary {
    let mut finding_count = 0usize;
    let mut findings_by_scanner = BTreeMap::new();
    for (scanner, count) in valid_count_by_scanner {
        findings_by_scanner.insert(scanner.clone(), *count);
        finding_count += count;
    }
    CanonicalSummary {
        finding_count,
        valid_finding_count: finding_count,
        invalid_finding_count: invalid_count,
        duplicate_group_count: duplicate_groups,
        findings_by_scanner,
        findings_by_severity: valid_count_by_severity.clone(),
        security_score: if coverage.complete {
            security_score
        } else {
            None
        },
    }
}

/// Coverage helper shared by the pipeline: usable findings are retained even
/// when another scanner fails, and the score stays unavailable.
pub fn aggregate_scan_results(
    results: &[&ScannerResult],
) -> (Vec<Finding>, CanonicalCoverage, Option<String>) {
    let runs = canonical_scanner_runs(results);
    let coverage = canonical_coverage(&runs);
    let mut findings = Vec::new();
    for result in results {
        if result.usable() {
            findings.extend(result.findings.iter().cloned());
        }
    }
    let detail = if coverage.complete || coverage.status == CoverageStatus::Absent {
        None
    } else {
        Some(format!(
            "partial coverage: {}",
            coverage
                .unsuccessful_scanners
                .iter()
                .map(|(scanner, status)| format!("{scanner} ({status})"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    };
    (findings, coverage, detail)
}

/// Stable identity for one finding, shared by pipeline deduplication.
pub fn canonical_identity(finding: &Finding) -> Result<String, String> {
    let metadata = parse_metadata(finding)?;
    let rule_id = native_rule_id(&metadata)?;
    let native_fp = native_fingerprint(&metadata)?;
    let scanner = finding
        .scanner_name
        .as_deref()
        .filter(|scanner| !scanner.trim().is_empty())
        .ok_or_else(|| "finding has no scanner identity".to_string())?;
    let location = finding_location(finding, &metadata)?;
    // Identity is computed from detection facts only. Run provenance
    // (scanner version, parser, image, snapshot) is validated separately by
    // `normalize_finding`, so a finding read straight from an adapter keeps
    // the identity it will have after it is persisted with its run record.
    canonical_finding_id(scanner, &rule_id, &native_fp, &location, &metadata, finding)
}

/// Normalize findings for persistence: sort, validate, dedupe, quarantine.
///
/// Exact canonical duplicates collapse to one representative row; anything
/// invalid is excluded and recorded. Ordering is by canonical identity, so
/// scanner result order can never change the outcome.
pub fn normalize_findings_for_persist(findings: Vec<Finding>) -> NormalizedPersisted {
    let mut valid: Vec<(String, Finding)> = Vec::new();
    let mut invalid = Vec::new();
    for finding in &findings {
        match normalize_finding(finding, None) {
            Ok(normalized) => valid.push((normalized.canonical_id, finding.clone())),
            Err(reason) => invalid.push(InvalidFinding {
                id: String::new(),
                scanner: finding.scanner_name.clone(),
                file: finding.file_path.clone(),
                reason,
                evidence_chars: finding
                    .evidence
                    .as_ref()
                    .map(|evidence| evidence.chars().count()),
            }),
        }
    }
    valid.sort_by(|a, b| a.0.cmp(&b.0));
    let mut grouped: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for (identity, finding) in valid {
        grouped.entry(identity).or_default().push(finding);
    }
    let mut deduplicated = Vec::new();
    let mut duplicate_groups = 0usize;
    for group in grouped.into_values() {
        let occurrences = group.len();
        if occurrences > 1 {
            duplicate_groups += 1;
        }
        let mut ordered = group;
        // Smallest storage identifier wins so the retained row is
        // deterministic for a given input set.
        ordered.sort_by(|a, b| a.id.cmp(&b.id));
        if let Some(mut representative) = ordered.into_iter().next() {
            // Record the merge on the retained row without changing its
            // canonical identity: `duplicate_occurrences` is provenance
            // bookkeeping, never an identity input.
            if occurrences > 1 {
                if let Some(raw) = representative.metadata_json.as_deref() {
                    if let Ok(serde_json::Value::Object(mut metadata)) = serde_json::from_str(raw) {
                        metadata.insert(
                            "duplicate_occurrences".to_string(),
                            serde_json::json!(occurrences),
                        );
                        representative.metadata_json =
                            Some(serde_json::Value::Object(metadata).to_string());
                    }
                }
            }
            deduplicated.push(representative);
        }
    }

    invalid.sort_by(|a, b| {
        (
            a.scanner.clone().unwrap_or_default(),
            a.file.clone().unwrap_or_default(),
            &a.reason,
            a.evidence_chars.unwrap_or(0),
        )
            .cmp(&(
                b.scanner.clone().unwrap_or_default(),
                b.file.clone().unwrap_or_default(),
                &b.reason,
                b.evidence_chars.unwrap_or(0),
            ))
    });
    let mut last_key: Option<(String, String, String, usize)> = None;
    let mut occurrence = 0usize;
    for item in &mut invalid {
        let key = (
            item.scanner.clone().unwrap_or_default(),
            item.file.clone().unwrap_or_default(),
            item.reason.clone(),
            item.evidence_chars.unwrap_or(0),
        );
        if last_key.as_ref() == Some(&key) {
            occurrence += 1;
        } else {
            occurrence = 0;
        }
        last_key = Some(key.clone());
        item.id = format!(
            "invalid-v1:{}",
            sha256_hex(&format!(
                "{}|{}|{}|{}|{occurrence}",
                key.0, key.1, key.2, key.3
            ))
        );
    }

    let dropped_count = findings.len().saturating_sub(deduplicated.len());
    NormalizedPersisted {
        raw_count: findings.len(),
        dropped_count,
        valid: deduplicated,
        invalid,
        duplicate_groups,
    }
}

/// Pipeline normalization output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NormalizedPersisted {
    pub raw_count: usize,
    pub dropped_count: usize,
    pub valid: Vec<Finding>,
    pub invalid: Vec<InvalidFinding>,
    pub duplicate_groups: usize,
}
