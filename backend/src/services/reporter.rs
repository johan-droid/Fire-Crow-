use crate::error::Result;
use crate::models::AuditJob;
use crate::schemas::audit_state::Finding;

/// Escape for surrounding prose (headings, labels, remediation text).
///
/// This is deliberately **not** applied to evidence inside a code fence: a
/// scanner snippet must be reproduced verbatim, so that `/`, `<`, `>`, `&` and
/// quotes appear exactly as the scanner emitted them. Escaping them inside a
/// fence merely corrupts the evidence.
fn sanitize_html_entities(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Break any triple-backtick run so pasted evidence cannot terminate the code
/// fence and inject content into the rest of the document.
///
/// A zero-width space is inserted between the last two backticks. The rendered
/// characters are unchanged to the eye; the fence delimiter is destroyed. This
/// is the code-fence equivalent of escaping the delimiter, and it is applied to
/// the evidence only.
fn neutralize_code_fence(input: &str) -> String {
    input.replace("```", "``\u{200b}`")
}

pub struct ReportGenerator;

impl ReportGenerator {
    /// Generate the markdown report for a finished job.
    ///
    /// `score` is the persisted `security_score`; it is `None` whenever no
    /// analysis ran or a scanner failed, and the report says `n/a` rather than
    /// implying a clean result.
    pub fn generate_markdown(
        job: &AuditJob,
        findings: &[Finding],
        score: Option<f64>,
    ) -> Result<String> {
        let mut md = String::new();

        let safe_repo = sanitize_html_entities(&job.repo_url);
        let safe_branch = sanitize_html_entities(&job.repo_branch);

        md.push_str(&format!(
            "# Security Audit Report\n\n**Repository:** {}\n**Branch:** {}\n**Status:** {:?}\n**Date:** {}\n\n",
            safe_repo, safe_branch, job.status, job.created_at
        ));

        match score {
            Some(value) => md.push_str(&format!("## Security Score: {:.1}/10\n\n", value)),
            None => md.push_str("## Security Score: n/a\n\n"),
        }

        md.push_str("## Findings\n\n");
        if findings.is_empty() {
            md.push_str("No findings were produced.\n\n");
        }

        for (i, finding) in findings.iter().enumerate() {
            // Title and description are prose: escape them for the viewer.
            let safe_title = sanitize_html_entities(&finding.title);
            let safe_desc = sanitize_html_entities(&finding.description);
            md.push_str(&format!(
                "### {}. {} [{}]\n\n{}\n\n",
                i + 1,
                safe_title,
                finding.severity.as_str(),
                safe_desc
            ));

            // A finding must always carry its location; render it when present.
            if let Some(ref path) = finding.file_path {
                let location = match finding.line_number {
                    Some(line) => format!("{}:{}", path, line),
                    None => path.clone(),
                };
                md.push_str(&format!("**Location:** `{}`\n\n", location.replace('`', "")));
            }

            if let Some(ref evidence) = finding.evidence {
                // Verbatim, with the fence delimiter neutralized.
                let safe_ev = neutralize_code_fence(evidence);
                md.push_str(&format!("**Evidence:**\n```\n{}\n```\n\n", safe_ev));
            }
            if let Some(ref remediation) = finding.remediation {
                let safe_rem = sanitize_html_entities(remediation);
                md.push_str(&format!("**Remediation:** {}\n\n", safe_rem));
            }
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
