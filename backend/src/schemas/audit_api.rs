use crate::models::{FindingModel, JobStatus, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct SubmitJobRequest {
    pub repo_url: String,
    #[serde(default = "default_branch")]
    pub repo_branch: Option<String>,
    /// Optional pinned snapshot. When present it must be a 40-character
    /// lowercase hex digest and the fetch phase scans exactly that commit
    /// instead of resolving the branch head. A branch is only ever an input
    /// used to resolve a SHA; the execution always pins an immutable commit.
    #[serde(default)]
    pub commit_sha: Option<String>,
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

/// Query string for a report download.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportQuery {
    /// One of `markdown` (default), `json`, or `html`.
    #[serde(default)]
    pub format: Option<String>,
}

fn default_branch() -> Option<String> {
    Some("main".into())
}
fn default_auth_scope() -> Option<String> {
    Some("authorized_representative".into())
}

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
    /// What the caller asked to scan: `None` means the branch head. The
    /// execution always pins an immutable commit; see `commit_sha`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_commit_sha: Option<String>,
    /// The snapshot the audit judged, pinned by the fetch phase.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
}

impl From<crate::models::AuditJob> for JobResponse {
    fn from(job: crate::models::AuditJob) -> Self {
        Self {
            id: job.id,
            user_id: job.user_id,
            repo_url: job.repo_url,
            repo_branch: job.repo_branch,
            status: job.status,
            created_at: job.created_at.and_utc(),
            finished_at: job.finished_at.map(|dt| dt.and_utc()),
            cancel_requested: job.cancel_requested,
            cancel_requested_at: job.cancel_requested_at.map(|dt| dt.and_utc()),
            report_pdf_url: job.report_pdf_url,
            error_message: job.error_message,
            security_score: job.security_score,
            email_delivered: false,
            github_issues_raised: false,
            github_pr_created: false,
            requested_commit_sha: job.requested_commit_sha,
            commit_sha: job.commit_sha,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingResponse {
    pub id: String,
    /// Deterministic canonical identity, independent of scanner result order.
    /// The storage `id` above stays random; this is the stable export identity.
    pub canonical_id: String,
    pub agent_source: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub scanner_name: Option<String>,
    pub scanner_mode: Option<String>,
    pub scanner_version: Option<String>,
    pub parser: Option<String>,
    pub rule_id: Option<String>,
    pub native_fingerprint: Option<String>,
    pub snapshot_commit: Option<String>,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub confidence: Option<String>,
    pub references: Vec<super::canonical_audit::CanonicalReference>,
}

impl From<FindingModel> for FindingResponse {
    fn from(f: FindingModel) -> Self {
        let metadata: Option<serde_json::Value> = f
            .metadata_json
            .as_ref()
            .and_then(|value| serde_json::to_value(value).ok());
        let string = |key: &str| {
            metadata
                .as_ref()
                .and_then(|value| value.get(key))
                .and_then(|value| value.as_str())
                .map(str::to_string)
        };
        let references = metadata
            .as_ref()
            .and_then(|value| value.get("references"))
            .and_then(|value| value.as_array())
            .map(|references| {
                references
                    .iter()
                    .filter_map(|reference| {
                        let url = reference.get("url")?.as_str()?.to_string();
                        let reference_type = reference
                            .get("type")
                            .and_then(|value| value.as_str())
                            .unwrap_or("WEB")
                            .to_string();
                        (url.starts_with("http://") || url.starts_with("https://")).then_some(
                            super::canonical_audit::CanonicalReference {
                                reference_type,
                                url,
                            },
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Canonical identity when the row carries curated metadata; otherwise
        // the storage id, so legacy rows never fail serialization.
        let canonical_id = metadata
            .as_ref()
            .and_then(|_| {
                let finding = crate::schemas::audit_state::Finding {
                    id: f.id.clone(),
                    agent_source: f.agent_source.clone(),
                    title: f.title.clone(),
                    description: f.description.clone(),
                    severity: f.severity,
                    cvss_vector: f.cvss_vector.clone(),
                    cvss_score: f.cvss_score,
                    evidence: f.evidence.clone(),
                    remediation: f.remediation.clone(),
                    cwe_id: f.cwe_id.clone(),
                    owasp_category: f.owasp_category.clone(),
                    confidence: f.confidence.clone(),
                    scanner_name: f.scanner_name.clone(),
                    scanner_mode: f.scanner_mode.clone(),
                    file_path: f.file_path.clone(),
                    line_number: f.line_number,
                    route: f.route.clone(),
                    metadata_json: f.metadata_json.as_ref().map(|value| value.to_string()),
                };
                crate::orchestrator::canonical_audit::canonical_identity(&finding).ok()
            })
            .unwrap_or_else(|| f.id.clone());
        Self {
            canonical_id,
            id: f.id,
            agent_source: f.agent_source,
            title: f.title,
            description: f.description,
            severity: f.severity,
            cvss_score: f.cvss_score,
            cvss_vector: f.cvss_vector,
            evidence: f.evidence,
            remediation: f.remediation,
            scanner_name: f.scanner_name,
            scanner_mode: f.scanner_mode,
            scanner_version: string("scanner_version"),
            parser: string("parser"),
            rule_id: string("rule_id")
                .or_else(|| string("check_id"))
                .or_else(|| string("advisory")),
            native_fingerprint: string("fingerprint"),
            snapshot_commit: string("snapshot_commit"),
            file_path: f.file_path,
            line_number: f.line_number,
            cwe_id: f.cwe_id,
            owasp_category: f.owasp_category,
            confidence: f.confidence,
            references,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JobDetailResponse {
    pub job: JobResponse,
    pub findings: Vec<FindingResponse>,
    /// Latest execution that produced this audit. `None` for jobs that predate
    /// execution identity; the findings list then carries the legacy rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<String>,
    /// Attempt number of the reconstructed audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_number: Option<i32>,
    /// Canonical audit document committed with the terminal status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_json: Option<serde_json::Value>,
}
