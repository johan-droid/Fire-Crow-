use crate::error::Result;
use crate::models::AuditJob;
use crate::schemas::audit_state::Finding;
use crate::utils::sanitize_html_entities;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn generate_markdown(
        job: &AuditJob,
        findings: &[Finding],
        summary: &crate::schemas::audit_state::AuditState,
    ) -> Result<String> {
        let mut md = String::new();

        // Enforce HTML entity sanitization on all dynamic fields to prevent SSTI/XSS in report viewers
        let safe_repo = sanitize_html_entities(&job.repo_url);
        let safe_branch = sanitize_html_entities(&job.repo_branch);

        md.push_str(&format!(
            "# Security Audit Report\n\n**Repository:** {}\n**Branch:** {}\n**Status:** {:?}\n**Date:** {}\n\n",
            safe_repo, safe_branch, job.status, job.created_at
        ));

        if let Some(score) = job.security_score {
            md.push_str(&format!("## Security Score: {}/10\n\n", score));
        }

        md.push_str("## Findings\n\n");
        for (i, finding) in findings.iter().enumerate() {
            let safe_title = sanitize_html_entities(&finding.title);
            let safe_desc = sanitize_html_entities(&finding.description);
            md.push_str(&format!(
                "### {}. {} [{}]\n\n{}\n\n",
                i + 1,
                safe_title,
                finding.severity.as_str(),
                safe_desc
            ));

            if let Some(ref evidence) = finding.evidence {
                let safe_ev = sanitize_html_entities(evidence);
                md.push_str(&format!("**Evidence:**\n```\n{}\n```\n\n", safe_ev));
            }
            if let Some(ref remediation) = finding.remediation {
                let safe_rem = sanitize_html_entities(remediation);
                md.push_str(&format!("**Remediation:** {}\n\n", safe_rem));
            }
        }

        md.push_str("## Remediation Plan\n\n");
        if !summary.remediation_tasks.is_empty() {
            for task in &summary.remediation_tasks {
                let task_str = serde_json::to_string(task).unwrap_or_default();
                let safe_task = sanitize_html_entities(&task_str);
                md.push_str(&format!("- {}\n", safe_task));
            }
        } else {
            md.push_str("No specific remediation tasks generated.\n");
        }

        Ok(md)
    }

    pub fn get_clean_repo_name(repo_url: &str) -> String {
        repo_url
            .trim_end_matches('/')
            .split('/')
            .next_back()
            .unwrap_or("repo")
            .replace('.', "_")
    }

    pub fn is_r2_auth_error(msg: &str) -> bool {
        msg.contains("AccessDenied") || msg.contains("InvalidAccessKeyId")
    }
}
