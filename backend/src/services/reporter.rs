//! Deterministic report rendering (Phase 13).
//!
//! The renderer is a pure function of a [`CanonicalAuditReport`]. It performs no
//! I/O — no scanner, no repository, no filesystem, no network, no database, no
//! LLM — so the same report model always renders to the same bytes. Markdown,
//! JSON, and HTML are all derived from the *same* model; none of them reads the
//! database or the findings independently.

use crate::error::{AppError, Result};
use crate::schemas::canonical_audit::{ConfidenceSource, CorrelationBasis, EvidenceKind};
use crate::schemas::report::CanonicalAuditReport;

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

/// Neutralize a code fence in evidence.
///
/// Break any triple-backtick run so pasted evidence cannot terminate the code
/// fence and inject content into the rest of the document. A zero-width space is
/// inserted between the last two backticks; the rendered characters are
/// unchanged to the eye, but the fence delimiter is destroyed.
fn neutralize_code_fence(input: &str) -> String {
    input.replace("```", "``\u{200b}`")
}

/// Stable lowercase name for a confidence source. Presentation-only; the
/// canonical contract is not modified.
fn confidence_source_str(source: ConfidenceSource) -> &'static str {
    match source {
        ConfidenceSource::Scanner => "scanner",
        ConfidenceSource::ScannerDefault => "scanner_default",
        ConfidenceSource::Absent => "absent",
    }
}

/// Stable lowercase name for an evidence kind.
fn evidence_kind_str(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Secret => "secret",
        EvidenceKind::Dependency => "dependency",
        EvidenceKind::Source => "source",
        EvidenceKind::Unknown => "unknown",
    }
}

/// Stable lowercase name for a correlation basis.
fn correlation_basis_str(basis: CorrelationBasis) -> &'static str {
    match basis {
        CorrelationBasis::ExactCanonicalIdentity => "exact_canonical_identity",
    }
}

/// A report is only ever rendered from a model; a serialization failure is a
/// programming error, not user input, so it maps to an internal error.
fn serialization_error(error: serde_json::Error) -> AppError {
    AppError::Internal(format!("report serialization failed: {error}"))
}

pub struct ReportGenerator;

impl ReportGenerator {
    /// Render the deterministic Markdown presentation of a report.
    pub fn render_markdown(report: &CanonicalAuditReport) -> Result<String> {
        let mut md = String::new();
        let id = &report.identity;

        md.push_str("# FireCrow Security Audit Report\n\n");
        md.push_str("## Identity\n\n");
        md.push_str(&format!(
            "- Audit ID: {}\n",
            sanitize_html_entities(&id.audit_id)
        ));
        md.push_str(&format!(
            "- Execution ID: {}\n",
            sanitize_html_entities(&id.execution_id)
        ));
        md.push_str(&format!("- Attempt: {}\n", id.attempt_number));
        md.push_str(&format!(
            "- Repository: {}\n",
            sanitize_html_entities(&id.repository_url)
        ));
        md.push_str(&format!(
            "- Branch: {}\n",
            sanitize_html_entities(&id.repo_branch)
        ));
        md.push_str(&format!(
            "- Snapshot: {}\n",
            id.snapshot_commit.as_deref().unwrap_or("unavailable")
        ));
        md.push_str(&format!("- Files analyzed: {}\n", id.snapshot_file_count));
        md.push_str(&format!(
            "- Snapshot size (bytes): {}\n",
            id.snapshot_total_size
        ));
        md.push_str(&format!(
            "- Coverage state: {}\n",
            report.coverage.state.as_str()
        ));
        md.push_str(&format!(
            "- Canonical schema version: {}\n",
            id.canonical_schema_version
        ));
        md.push_str(&format!(
            "- Report schema version: {}\n",
            id.report_schema_version
        ));
        md.push('\n');

        md.push_str("## Executive Summary\n\n");
        md.push_str(&format!(
            "{}\n\n",
            sanitize_html_entities(&report.summary.headline)
        ));
        md.push_str(&format!("- Findings: {}\n", report.summary.finding_count));
        md.push_str(&format!(
            "- Invalid findings: {}\n",
            report.summary.invalid_finding_count
        ));
        md.push_str(&format!(
            "- Duplicate groups: {}\n",
            report.summary.duplicate_group_count
        ));
        match report.summary.security_score {
            Some(value) => md.push_str(&format!("- Security score: {value:.1}/10\n")),
            None => md.push_str(
                "- Security score: unavailable because scan coverage is incomplete. \
                 A partial scan cannot be scored; the missing value is not zero.\n",
            ),
        }
        md.push('\n');

        md.push_str("### Findings by severity\n\n");
        if report.summary.findings_by_severity.is_empty() {
            md.push_str("- (none)\n");
        } else {
            for (severity, count) in &report.summary.findings_by_severity {
                md.push_str(&format!("- {severity}: {count}\n"));
            }
        }
        md.push('\n');

        md.push_str("### Findings by scanner\n\n");
        if report.summary.findings_by_scanner.is_empty() {
            md.push_str("- (none)\n");
        } else {
            for (scanner, count) in &report.summary.findings_by_scanner {
                md.push_str(&format!("- {}: {count}\n", sanitize_html_entities(scanner)));
            }
        }
        md.push('\n');

        md.push_str("## Coverage\n\n");
        md.push_str(&format!("- Status: {}\n", report.coverage.status.as_str()));
        md.push_str(&format!(
            "- Complete: {}\n",
            if report.coverage.complete {
                "yes"
            } else {
                "no"
            }
        ));
        md.push_str(&format!(
            "- Successful scanners: {}\n",
            if report.coverage.successful_scanners.is_empty() {
                "(none)".to_string()
            } else {
                report.coverage.successful_scanners.join(", ")
            }
        ));
        md.push_str(&format!(
            "- Unsuccessful scanners: {}\n",
            if report.coverage.unsuccessful_scanners.is_empty() {
                "(none)".to_string()
            } else {
                report
                    .coverage
                    .unsuccessful_scanners
                    .iter()
                    .map(|(scanner, status)| format!("{scanner} ({status})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
        md.push('\n');

        md.push_str("### Limitations\n\n");
        if report.limitations.is_empty() {
            md.push_str("- (none)\n");
        } else {
            for limitation in &report.limitations {
                md.push_str(&format!("- {}\n", sanitize_html_entities(limitation)));
            }
        }
        md.push('\n');

        md.push_str(&format!(
            "## Findings ({})\n\n",
            report.summary.finding_count
        ));
        if report.findings.is_empty() {
            md.push_str("No findings were reported.\n\n");
        }
        for (index, finding) in report.findings.iter().enumerate() {
            let safe_title = sanitize_html_entities(&finding.title);
            let safe_desc = sanitize_html_entities(&finding.description);
            md.push_str(&format!(
                "### {}. {} [{}]\n\n{}\n\n",
                index + 1,
                safe_title,
                finding.severity.as_str(),
                safe_desc
            ));
            md.push_str(&format!(
                "**Scanner:** {} ({})\n\n",
                sanitize_html_entities(&finding.provenance.scanner),
                sanitize_html_entities(&finding.provenance.scanner_version)
            ));
            md.push_str(&format!(
                "**Rule:** {}\n\n",
                sanitize_html_entities(&finding.provenance.rule_id)
            ));
            let location = match finding.location.end_line {
                Some(end) if end != i64::from(finding.location.line) => format!(
                    "{}:{}–{}",
                    finding.location.file, finding.location.line, end
                ),
                _ => format!("{}:{}", finding.location.file, finding.location.line),
            };
            md.push_str(&format!(
                "**Location:** `{}`\n\n",
                location.replace('`', "")
            ));
            if let Some(cwe) = finding.cwe_id.as_deref() {
                md.push_str(&format!("**CWE:** {}\n\n", sanitize_html_entities(cwe)));
            }
            if let Some(owasp) = finding.owasp_category.as_deref() {
                md.push_str(&format!("**OWASP:** {}\n\n", sanitize_html_entities(owasp)));
            }
            if let Some(confidence) = finding.confidence.as_deref() {
                md.push_str(&format!(
                    "**Confidence:** {} ({})\n\n",
                    sanitize_html_entities(confidence),
                    confidence_source_str(finding.confidence_source)
                ));
            }
            md.push_str(&format!(
                "**Evidence ({})**{}:\n```\n{}\n```\n\n",
                evidence_kind_str(finding.evidence_kind),
                if finding.evidence_truncated {
                    " [truncated]"
                } else {
                    ""
                },
                neutralize_code_fence(&finding.evidence)
            ));
            if let Some(remediation) = finding.remediation.as_deref() {
                md.push_str(&format!(
                    "**Suggested remediation:** {}\n\n",
                    sanitize_html_entities(remediation)
                ));
            }
            if !finding.references.is_empty() {
                md.push_str("**References:**\n\n");
                for reference in &finding.references {
                    md.push_str(&format!(
                        "- [{}] {}\n",
                        sanitize_html_entities(&reference.reference_type),
                        sanitize_html_entities(&reference.url)
                    ));
                }
                md.push('\n');
            }
        }

        if !report.correlations.is_empty() {
            md.push_str("## Correlations\n\n");
            for correlation in &report.correlations {
                md.push_str(&format!(
                    "- `{}` ({}): {} occurrence(s)\n",
                    correlation.correlation_id,
                    correlation_basis_str(correlation.basis),
                    correlation.occurrences
                ));
            }
            md.push('\n');
        }

        if !report.invalid_findings.is_empty() {
            md.push_str("## Invalid findings\n\n");
            for invalid in &report.invalid_findings {
                md.push_str(&format!(
                    "- `{}`: {} (scanner: {}, file: {})\n",
                    invalid.id,
                    sanitize_html_entities(&invalid.reason),
                    sanitize_html_entities(invalid.scanner.as_deref().unwrap_or("unknown")),
                    sanitize_html_entities(invalid.file.as_deref().unwrap_or("unknown"))
                ));
            }
            md.push('\n');
        }

        md.push_str("## Notices\n\n");
        for disclaimer in &report.disclaimers {
            md.push_str(&format!("- {}\n", sanitize_html_entities(disclaimer)));
        }
        md.push('\n');

        Ok(md)
    }

    /// Render the canonical JSON presentation of a report.
    ///
    /// The same report model is serialized; maps are `BTreeMap`s, so key order is
    /// stable and the output is byte-for-byte reproducible.
    pub fn render_json(report: &CanonicalAuditReport) -> Result<String> {
        let mut json = serde_json::to_string_pretty(report).map_err(serialization_error)?;
        json.push('\n');
        Ok(json)
    }

    /// Render the HTML presentation of a report.
    ///
    /// Derived from the same model as Markdown/JSON. All prose is entity-escaped;
    /// evidence is escaped inside a `<pre>` block, so scanner text cannot inject
    /// markup.
    pub fn render_html(report: &CanonicalAuditReport) -> Result<String> {
        let mut html = String::new();
        let id = &report.identity;
        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"utf-8\">\n");
        html.push_str("<title>FireCrow Security Audit Report</title>\n");
        html.push_str("</head>\n<body>\n");
        html.push_str("<h1>FireCrow Security Audit Report</h1>\n");

        html.push_str("<h2>Identity</h2>\n<ul>\n");
        for (label, value) in [
            ("Audit ID", sanitize_html_entities(&id.audit_id)),
            ("Execution ID", sanitize_html_entities(&id.execution_id)),
            ("Attempt", id.attempt_number.to_string()),
            ("Repository", sanitize_html_entities(&id.repository_url)),
            ("Branch", sanitize_html_entities(&id.repo_branch)),
            (
                "Snapshot",
                id.snapshot_commit
                    .as_deref()
                    .map(sanitize_html_entities)
                    .unwrap_or_else(|| "unavailable".to_string()),
            ),
            ("Files analyzed", id.snapshot_file_count.to_string()),
            ("Snapshot size (bytes)", id.snapshot_total_size.to_string()),
            ("Coverage state", report.coverage.state.as_str().to_string()),
            (
                "Canonical schema version",
                id.canonical_schema_version.to_string(),
            ),
            (
                "Report schema version",
                id.report_schema_version.to_string(),
            ),
        ] {
            html.push_str(&format!("<li><strong>{label}:</strong> {value}</li>\n"));
        }
        html.push_str("</ul>\n");

        html.push_str("<h2>Executive Summary</h2>\n");
        html.push_str(&format!(
            "<p>{}</p>\n",
            sanitize_html_entities(&report.summary.headline)
        ));
        html.push_str("<ul>\n");
        html.push_str(&format!(
            "<li>Findings: {}</li>\n",
            report.summary.finding_count
        ));
        html.push_str(&format!(
            "<li>Invalid findings: {}</li>\n",
            report.summary.invalid_finding_count
        ));
        html.push_str(&format!(
            "<li>Duplicate groups: {}</li>\n",
            report.summary.duplicate_group_count
        ));
        match report.summary.security_score {
            Some(value) => html.push_str(&format!("<li>Security score: {value:.1}/10</li>\n")),
            None => html.push_str(
                "<li>Security score: unavailable because scan coverage is incomplete. \
                 A partial scan cannot be scored; the missing value is not zero.</li>\n",
            ),
        }
        html.push_str("</ul>\n");

        html.push_str("<h2>Coverage</h2>\n<ul>\n");
        html.push_str(&format!(
            "<li>Status: {}</li>\n",
            report.coverage.status.as_str()
        ));
        html.push_str(&format!(
            "<li>Complete: {}</li>\n",
            if report.coverage.complete {
                "yes"
            } else {
                "no"
            }
        ));
        html.push_str(&format!(
            "<li>Successful scanners: {}</li>\n",
            if report.coverage.successful_scanners.is_empty() {
                "(none)".to_string()
            } else {
                sanitize_html_entities(&report.coverage.successful_scanners.join(", "))
            }
        ));
        html.push_str(&format!(
            "<li>Unsuccessful scanners: {}</li>\n",
            if report.coverage.unsuccessful_scanners.is_empty() {
                "(none)".to_string()
            } else {
                sanitize_html_entities(
                    &report
                        .coverage
                        .unsuccessful_scanners
                        .iter()
                        .map(|(scanner, status)| format!("{scanner} ({status})"))
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            }
        ));
        html.push_str("</ul>\n");

        html.push_str("<h2>Limitations</h2>\n<ul>\n");
        if report.limitations.is_empty() {
            html.push_str("<li>(none)</li>\n");
        } else {
            for limitation in &report.limitations {
                html.push_str(&format!(
                    "<li>{}</li>\n",
                    sanitize_html_entities(limitation)
                ));
            }
        }
        html.push_str("</ul>\n");

        html.push_str(&format!(
            "<h2>Findings ({})</h2>\n",
            report.summary.finding_count
        ));
        if report.findings.is_empty() {
            html.push_str("<p>No findings were reported.</p>\n");
        }
        for (index, finding) in report.findings.iter().enumerate() {
            html.push_str(&format!(
                "<h3>{}. {} [{}]</h3>\n",
                index + 1,
                sanitize_html_entities(&finding.title),
                finding.severity.as_str()
            ));
            html.push_str(&format!(
                "<p>{}</p>\n",
                sanitize_html_entities(&finding.description)
            ));
            html.push_str(&format!(
                "<p>Scanner: {}</p>\n",
                sanitize_html_entities(&finding.provenance.scanner)
            ));
            html.push_str(&format!(
                "<p>Rule: {}</p>\n",
                sanitize_html_entities(&finding.provenance.rule_id)
            ));
            html.push_str(&format!(
                "<p>Location: <code>{}:{}</code></p>\n",
                sanitize_html_entities(&finding.location.file),
                finding.location.line
            ));
            html.push_str(&format!(
                "<pre>{}</pre>\n",
                sanitize_html_entities(&finding.evidence)
            ));
            if let Some(remediation) = finding.remediation.as_deref() {
                html.push_str(&format!(
                    "<p><strong>Suggested remediation:</strong> {}</p>\n",
                    sanitize_html_entities(remediation)
                ));
            }
        }

        html.push_str("<h2>Notices</h2>\n<ul>\n");
        for disclaimer in &report.disclaimers {
            html.push_str(&format!(
                "<li>{}</li>\n",
                sanitize_html_entities(disclaimer)
            ));
        }
        html.push_str("</ul>\n");

        html.push_str("</body>\n</html>\n");
        Ok(html)
    }
}
