//! Secret scanning — the `scan` phase. gitleaks only.
//!
//! The repository is mounted **read-only** into a hardened container and the
//! scanner writes its JSON report to stdout. The report is parsed into
//! [`Finding`]s that always carry a file, a line, and an evidence snippet, and
//! the secret value is redacted before it is stored.
//!
//! A non-zero scanner exit or an unparseable report is recorded in the scanner
//! execution map and marks the phase failed; the caller must not then report a
//! score.

use crate::error::Result;
use crate::models::Severity;
use crate::schemas::audit_state::Finding;
use crate::services::redaction::redact_text;
use crate::services::sandbox::{SandboxManager, SandboxMount};
use serde::Deserialize;
use std::path::Path;

/// The pinned gitleaks image.
pub const GITLEAKS_IMAGE: &str = "ghcr.io/gitleaks/gitleaks:v8.18.4";
/// Container path the repository is mounted at (read-only).
pub const SOURCE_MOUNT: &str = "/src";
/// Wall-clock ceiling for a scan.
pub const SCAN_TIMEOUT_SECS: u64 = 300;
/// Scanner name recorded on every finding.
pub const SCANNER_NAME: &str = "gitleaks";
/// Scanner mode recorded on every finding.
pub const SCANNER_MODE: &str = "secret";
/// Maximum characters retained from an evidence snippet.
pub const SNIPPET_MAX_CHARS: usize = 400;

/// One entry of gitleaks' JSON report. Field names mirror gitleaks exactly.
#[derive(Debug, Clone, Deserialize)]
pub struct GitleaksFinding {
    #[serde(rename = "RuleID", default)]
    pub rule_id: String,
    #[serde(rename = "Description", default)]
    pub description: String,
    #[serde(rename = "File", default)]
    pub file: String,
    #[serde(rename = "StartLine", default)]
    pub start_line: i64,
    #[serde(rename = "Secret", default)]
    pub secret: String,
    #[serde(rename = "Match", default)]
    pub match_text: String,
}

/// Outcome of a scan phase.
pub struct ScanOutcome {
    pub findings: Vec<Finding>,
    /// Persisted verbatim into `AuditState::scanner_execution`.
    pub scanner_execution: serde_json::Value,
    /// True when the scanner could not be trusted to produce a result.
    pub failed: bool,
}

/// Run gitleaks over `source_dir` and return findings plus an execution record.
pub async fn run_secret_scan(source_dir: &Path, sandbox: &SandboxManager) -> ScanOutcome {
    let mounts = vec![SandboxMount {
        host_path: source_dir.to_string_lossy().to_string(),
        container_path: SOURCE_MOUNT.to_string(),
        read_only: true,
    }];

    // `--exit-code=0` makes a *finding* exit 0; a non-zero exit then means the
    // scanner itself failed, which is the distinction that matters here.
    let source_arg = format!("--source={SOURCE_MOUNT}");
    let command = [
        "detect",
        "--no-git",
        source_arg.as_str(),
        "--report-format=json",
        "--report-path=/dev/stdout",
        "--exit-code=0",
        "--log-level=error",
    ];

    match sandbox
        .run(GITLEAKS_IMAGE, &command, &mounts, SCAN_TIMEOUT_SECS)
        .await
    {
        Ok(out) if out.success => match parse_gitleaks_report(&out.stdout) {
            Ok(raw) => {
                let findings: Vec<Finding> = raw.iter().map(finding_from_gitleaks).collect();
                ScanOutcome {
                    scanner_execution: serde_json::json!({
                        "scanner": SCANNER_NAME,
                        "status": "ok",
                        "finding_count": findings.len(),
                    }),
                    findings,
                    failed: false,
                }
            }
            Err(e) => ScanOutcome {
                scanner_execution: serde_json::json!({
                    "scanner": SCANNER_NAME,
                    "status": "parse_error",
                    "error": e.to_string(),
                }),
                findings: Vec::new(),
                failed: true,
            },
        },
        Ok(out) => ScanOutcome {
            scanner_execution: serde_json::json!({
                "scanner": SCANNER_NAME,
                "status": "error",
                "detail": "scanner exited non-zero",
                "stderr": redact_text(&out.stderr, 1000),
            }),
            findings: Vec::new(),
            failed: true,
        },
        Err(e) => ScanOutcome {
            scanner_execution: serde_json::json!({
                "scanner": SCANNER_NAME,
                "status": "error",
                "error": e.to_string(),
            }),
            findings: Vec::new(),
            failed: true,
        },
    }
}

/// Parse gitleaks' JSON report.
///
/// Accepts an empty body or `null` as "no findings" (gitleaks does this on some
/// versions), a bare array, or an array preceded by log noise on stdout.
pub fn parse_gitleaks_report(stdout: &str) -> Result<Vec<GitleaksFinding>> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(Vec::new());
    }

    if let Ok(v) = serde_json::from_str::<Vec<GitleaksFinding>>(trimmed) {
        return Ok(v);
    }

    // Recover the array if other lines were interleaved.
    if let (Some(start), Some(end)) = (trimmed.find('['), trimmed.rfind(']')) {
        if start < end {
            if let Ok(v) = serde_json::from_str::<Vec<GitleaksFinding>>(&trimmed[start..=end]) {
                return Ok(v);
            }
        }
    }

    Err(crate::error::AppError::Internal(
        "gitleaks report was not valid JSON".into(),
    ))
}

/// Convert one gitleaks entry into a `Finding`.
///
/// The `Finding` always carries `file_path`, `line_number`, and an evidence
/// snippet; the snippet is the scanner's own match text with the secret value
/// replaced by `[REDACTED]` and then passed through the shared redactor.
pub fn finding_from_gitleaks(g: &GitleaksFinding) -> Finding {
    let title = if g.description.trim().is_empty() {
        format!("Exposed secret: {}", g.rule_id)
    } else {
        g.description.clone()
    };

    let raw_snippet = if !g.match_text.trim().is_empty() {
        g.match_text.clone()
    } else {
        format!("{} = {}", g.rule_id, g.secret)
    };

    // Replace the exact secret value first, then run the generic redactor for
    // anything else that looks like a credential.
    let without_secret = if g.secret.is_empty() {
        raw_snippet
    } else {
        raw_snippet.replace(&g.secret, "[REDACTED]")
    };
    let evidence = redact_text(&without_secret, SNIPPET_MAX_CHARS);

    Finding {
        id: uuid::Uuid::new_v4().to_string(),
        agent_source: SCANNER_NAME.to_string(),
        title,
        description: format!("gitleaks rule {}: {}", g.rule_id, g.description),
        severity: Severity::High,
        cvss_vector: None,
        cvss_score: None,
        evidence: Some(evidence),
        remediation: Some(
            "Revoke the exposed credential, remove it from the repository history, and load it from a secret manager at runtime.".to_string(),
        ),
        cwe_id: Some("CWE-798".to_string()),
        owasp_category: Some("A07:2021".to_string()),
        // Scanner's own confidence, not a computed heuristic.
        confidence: Some("high".to_string()),
        scanner_name: Some(SCANNER_NAME.to_string()),
        scanner_mode: Some(SCANNER_MODE.to_string()),
        file_path: Some(normalize_repo_path(&g.file)),
        line_number: Some(g.start_line as i32),
        route: None,
        metadata_json: Some(serde_json::json!({ "rule_id": g.rule_id }).to_string()),
    }
}

/// Strip the container mount prefix so the stored path is repository-relative.
///
/// gitleaks reports the path it saw (`/src/aws.env`); the product should record
/// `aws.env`, not an internal container path.
fn normalize_repo_path(path: &str) -> String {
    let with_slash = format!("{SOURCE_MOUNT}/");
    path.strip_prefix(with_slash.as_str())
        .unwrap_or(path)
        .trim_start_matches('/')
        .to_string()
}
