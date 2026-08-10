//! Audit job, finding, artifact, agent log, phase ledger, and report models.

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use crate::models::{JobStatus, Severity};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditJob {
    pub id: String,
    pub user_id: String,
    pub tenant_id: Option<String>,
    pub repo_url: String,
    pub repo_branch: String,
    pub status: JobStatus,
    pub created_at: NaiveDateTime,
    pub finished_at: Option<NaiveDateTime>,
    pub cancel_requested: bool,
    pub cancel_requested_at: Option<NaiveDateTime>,
    pub report_pdf_url: Option<String>,
    pub report_id: Option<String>,
    pub error_message: Option<String>,
    pub security_score: Option<f64>,
    pub legal_hold: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditReport {
    pub id: String,
    pub job_id: String,
    pub html_content: Option<String>,
    pub markdown_content: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct FindingModel {
    pub id: String,
    pub job_id: String,
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
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AgentLog {
    pub id: i64,
    pub job_id: String,
    pub agent_name: String,
    pub log_level: String,
    pub message: String,
    pub timestamp: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditArtifact {
    pub id: String,
    pub job_id: String,
    pub artifact_type: String,
    pub name: String,
    pub data_json: Option<String>,
    pub data_text: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PhaseLedgerModel {
    pub id: String,
    pub job_id: String,
    pub phase_name: String,
    pub status: String,
    pub mode: String,
    pub duration_sec: Option<f64>,
    pub error_message: Option<String>,
    pub started_at: NaiveDateTime,
    pub ended_at: Option<NaiveDateTime>,
}
