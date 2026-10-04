//! Audit job, finding, artifact, agent log, phase ledger, and report models.

use crate::models::{JobStatus, Severity};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditJob {
    pub id: String,
    pub user_id: String,
    #[sqlx(default)]
    pub tenant_id: Option<String>,
    pub repo_url: String,
    pub repo_branch: String,
    pub status: JobStatus,
    pub created_at: NaiveDateTime,
    #[sqlx(default)]
    pub finished_at: Option<NaiveDateTime>,
    #[sqlx(default)]
    pub cancel_requested: bool,
    #[sqlx(default)]
    pub cancel_requested_at: Option<NaiveDateTime>,
    #[sqlx(default)]
    pub report_pdf_url: Option<String>,
    #[sqlx(default)]
    pub report_id: Option<String>,
    #[sqlx(default)]
    pub error_message: Option<String>,
    #[sqlx(default)]
    pub security_score: Option<f64>,
    #[sqlx(default)]
    pub legal_hold: bool,
    /// The repository snapshot this audit judged, pinned during the fetch
    /// phase.
    ///
    /// An audit is a record of one immutable snapshot. Persisting the snapshot
    /// on the job (not only inside each finding's metadata) is what makes that
    /// claim checkable: every finding can be proven to belong to the snapshot
    /// the job claims, and a later repository change cannot relabel history.
    #[sqlx(default)]
    pub commit_sha: Option<String>,
    /// What the caller asked to scan: `None` means "the branch head, resolved
    /// at fetch time"; `Some(sha)` means that exact snapshot, used verbatim.
    /// A branch is only ever an input used to resolve a SHA — the execution
    /// always pins an immutable commit.
    #[sqlx(default)]
    pub requested_commit_sha: Option<String>,
    /// GitHub delivery ID that created this job, if any. UNIQUE: one delivery
    /// produces at most one job, so a redelivered webhook finds this row
    /// instead of queueing a duplicate audit. `None` for user submissions.
    #[sqlx(default)]
    pub webhook_delivery_id: Option<String>,
    /// Installation that authorized a webhook-created job. Attribution for
    /// reporting back (Check Runs); live authorization is always re-resolved.
    #[sqlx(default)]
    pub github_installation_id: Option<i64>,
    #[sqlx(default)]
    pub started_at: Option<NaiveDateTime>,
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
    #[sqlx(default)]
    pub execution_id: Option<String>,
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
    /// `JSONB` in the schema, so it is decoded as JSON and rendered to a string
    /// by the caller. Typing this `Option<String>` makes every read of a row
    /// with metadata fail on a type mismatch.
    pub metadata_json: Option<serde_json::Value>,
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
    #[sqlx(default)]
    pub execution_id: Option<String>,
    pub phase_name: String,
    pub status: String,
    pub mode: String,
    pub duration_sec: Option<f64>,
    pub error_message: Option<String>,
    pub started_at: NaiveDateTime,
    pub ended_at: Option<NaiveDateTime>,
}
