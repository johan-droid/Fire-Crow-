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
    // Scan results
    pub findings: Vec<Finding>,
    pub security_score: Option<f64>,
    pub scanner_execution: HashMap<String, serde_json::Value>,
    pub analysis_performed: bool,
    pub errors: Vec<serde_json::Value>,
    pub risk_summary: serde_json::Value,
}
