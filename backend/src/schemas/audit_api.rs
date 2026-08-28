use crate::models::{FindingModel, JobStatus, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct SubmitJobRequest {
    pub repo_url: String,
    #[serde(default = "default_branch")]
    pub repo_branch: Option<String>,
    #[serde(default)]
    pub attestation_accepted: bool,
    #[serde(default = "default_auth_scope")]
    pub authorization_scope: Option<String>,
    pub custom_email: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailReportRequest {
    pub email: Option<String>,
}

fn default_branch() -> Option<String> { Some("main".into()) }
fn default_auth_scope() -> Option<String> { Some("authorized_representative".into()) }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResponse {
    pub id: String,
    pub user_id: String,
    pub repo_url: String,
    pub repo_branch: String,
    pub status: JobStatus,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub cancel_requested: bool,
    pub cancel_requested_at: Option<DateTime<Utc>>,
    pub report_pdf_url: Option<String>,
    pub error_message: Option<String>,
    pub security_score: Option<f64>,
    pub email_delivered: bool,
    pub github_issues_raised: bool,
    pub github_pr_created: bool,
}

impl From<crate::models::AuditJob> for JobResponse {
    fn from(job: crate::models::AuditJob) -> Self {
        Self {
            id: job.id, user_id: job.user_id, repo_url: job.repo_url, repo_branch: job.repo_branch,
            status: job.status,
            created_at: job.created_at.and_utc(),
            finished_at: job.finished_at.map(|dt| dt.and_utc()),
            cancel_requested: job.cancel_requested,
            cancel_requested_at: job.cancel_requested_at.map(|dt| dt.and_utc()),
            report_pdf_url: job.report_pdf_url, error_message: job.error_message,
            security_score: job.security_score, email_delivered: false,
            github_issues_raised: false, github_pr_created: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingResponse {
    pub id: String,
    pub agent_source: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
}

impl From<FindingModel> for FindingResponse {
    fn from(f: FindingModel) -> Self {
        Self {
            id: f.id, agent_source: f.agent_source, title: f.title, description: f.description,
            severity: f.severity, cvss_score: f.cvss_score, cvss_vector: f.cvss_vector,
            evidence: f.evidence, remediation: f.remediation,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JobDetailResponse {
    pub job: JobResponse,
    pub findings: Vec<FindingResponse>,
}
