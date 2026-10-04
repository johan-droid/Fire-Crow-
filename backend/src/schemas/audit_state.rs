use crate::models::{JobStatus, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseHistoryEntry {
    pub phase: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub duration_sec: f64,
    pub outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub agent_source: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub confidence: Option<String>,
    pub scanner_name: Option<String>,
    pub scanner_mode: Option<String>,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub route: Option<String>,
    pub metadata_json: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditState {
    // Identity
    pub job_id: String,
    pub user_id: String,
    // Repository
    pub repo_url: String,
    pub repo_branch: String,
    pub repo_owner: String,
    pub repo_name: String,
    // Lifecycle
    pub created_at: DateTime<Utc>,
    pub current_phase: String,
    pub status: JobStatus,
    // Fetch
    pub clone_path: String,
    /// Head commit the scan was pinned to, resolved during the fetch phase.
    #[serde(default)]
    pub commit_sha: Option<String>,
    /// `"public"` or `"private"`, as reported by GitHub during intake.
    #[serde(default)]
    pub repo_visibility: Option<String>,
    // Scan results
    pub findings: Vec<Finding>,
    pub security_score: Option<f64>,
    pub scanner_execution: HashMap<String, serde_json::Value>,
    pub analysis_performed: bool,
    /// Whether every scanner reported successfully. Partial coverage retains
    /// usable findings but never receives a score.
    #[serde(default)]
    pub coverage_complete: bool,
    /// Machine-readable reason when coverage is incomplete.
    #[serde(default)]
    pub coverage_detail: Option<String>,
    /// Sorted limitations carried forward from scanner execution records.
    #[serde(default)]
    pub coverage_limitations: Vec<String>,
    /// Markdown report produced by the `report` phase.
    ///
    /// Held in state rather than written during the phase, because the report
    /// row and the findings and the terminal status must be committed *together*
    /// at finalization — writing it here would be the commit boundary the
    /// atomicity invariant forbids.
    #[serde(default)]
    pub report_markdown: Option<String>,
    /// The canonical audit document built for this attempt (Phase 13). Held in
    /// state so the report is derived from it and so it is persisted with the
    /// terminal status.
    #[serde(default)]
    pub canonical_json: Option<serde_json::Value>,
    /// The deterministic report model, serialized (Phase 13).
    #[serde(default)]
    pub report_json: Option<serde_json::Value>,
    /// The HTML presentation derived from `report_json` (Phase 13).
    #[serde(default)]
    pub report_html: Option<String>,
    pub errors: Vec<serde_json::Value>,
    pub risk_summary: serde_json::Value,
}
