//! The email delivery artifact (Phase 17).
//!
//! A pure function of exactly two inputs: the finalized
//! [`CanonicalAuditReport`] and an optional validated [`ReportNarrative`]. It
//! reads no files, executes no scanner, queries no database, calls no provider,
//! and knows nothing about SMTP. Two consequences follow, and both are the point:
//!
//! * The same inputs always produce byte-identical output. No clock, no random
//!   id, no request id — so a re-render cannot silently change what an auditor
//!   already read, and a test can assert the whole artifact.
//! * Provider metadata has nowhere to go. It belongs in delivery logs and
//!   delivery state, never inside the security content.
//!
//! The deterministic report is authoritative throughout. The narrative is an
//! explanation appended after it and can add no finding, severity, score,
//! coverage, or scanner status — it was validated against this exact report
//! before it got here, and the renderer reads nothing from it except prose.

use crate::schemas::ai_narrative::ReportNarrative;
use crate::schemas::report::CanonicalAuditReport;

/// One immutable delivery artifact, execution-scoped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailArtifact {
    /// The delivery contract that rendered this artifact.
    pub schema_version: i32,
    pub execution_id: String,
    pub attempt_number: i32,
    /// Deterministic from audit state. Never carries evidence, secrets, or any
    /// model-authored text.
    pub subject: String,
    /// Always produced, so delivery never depends on HTML rendering.
    pub text_body: String,
    pub html_body: String,
}

/// Escape text for safe interpolation into HTML.
///
/// Findings come from repositories, and a repository can contain
/// `<script>alert(1)</script>` in a filename. Every interpolated value passes
/// through here; the renderer has no path that emits raw text into HTML.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(character),
        }
    }
    out
}

/// Human-facing coverage label.
///
/// Taken verbatim from the report's own state. An incomplete or failed scan is
/// never relabelled: `SUCCESS_CLEAN` is only ever produced by an audit that
/// completed every scanner.
pub(crate) fn coverage_label(report: &CanonicalAuditReport) -> &'static str {
    use crate::schemas::report::CoverageState::*;
    match report.coverage.state {
        SuccessClean => "SUCCESS_CLEAN",
        SuccessFindings => "SUCCESS_FINDINGS",
        Failed => "FAILED",
        Timeout => "TIMEOUT",
        Cancelled => "CANCELLED",
        NoFilesAnalyzed => "NO_FILES_ANALYZED",
    }
}

/// The score, or an explicit statement that there is none.
///
/// The renderer never computes, averages, or substitutes a score. `None` stays
/// unknown rather than becoming `0` or `10`.
pub(crate) fn score_text(report: &CanonicalAuditReport) -> String {
    match report.summary.security_score {
        Some(score) => format!("{score}"),
        None => "Not available".to_string(),
    }
}

/// Deterministic subject line.
///
/// Bounded, and built only from audit state and repository identity. No
/// evidence, no secret, and nothing a model wrote may reach a subject line —
/// subjects are routinely logged by mail systems.
fn subject(report: &CanonicalAuditReport) -> String {
    let repository = if report.identity.repository_url.trim().is_empty() {
        "unknown repository"
    } else {
        report.identity.repository_url.trim()
    };
    // Bounded: repository identity is user-controlled, so it is capped.
    let repository: String = repository.chars().take(120).collect();
    format!(
        "Fire Crow — {} — attempt {} — {}",
        coverage_label(report),
        report.identity.attempt_number,
        repository
    )
}

/// Build the artifact for one execution.
pub fn render(report: &CanonicalAuditReport, narrative: Option<&ReportNarrative>) -> EmailArtifact {
    let mut text = String::new();
    let mut html = String::new();

    // ---- Header -----------------------------------------------------------
    text.push_str("Fire Crow security audit\n");
    text.push_str(&format!(
        "Repository: {}\nBranch: {}\nExecution: {} (attempt {})\nScan status: {}\n",
        report.identity.repository_url,
        report.identity.repo_branch,
        report.identity.execution_id,
        report.identity.attempt_number,
        coverage_label(report),
    ));
    html.push_str("<h1>Fire Crow security audit</h1>");
    html.push_str(&format!(
        "<p><strong>Repository:</strong> {}<br>\
         <strong>Branch:</strong> {}<br>\
         <strong>Execution:</strong> {} (attempt {})<br>\
         <strong>Scan status:</strong> {}</p>",
        escape_html(&report.identity.repository_url),
        escape_html(&report.identity.repo_branch),
        escape_html(&report.identity.execution_id),
        report.identity.attempt_number,
        escape_html(coverage_label(report)),
    ));

    // ---- Coverage ---------------------------------------------------------
    // Stated before the findings so a reader cannot reach a "clean" conclusion
    // from the summary alone while a scanner silently failed.
    text.push_str("\nScanner coverage\n");
    for scanner in &report.coverage.successful_scanners {
        text.push_str(&format!("  {scanner}: succeeded\n"));
    }
    for (scanner, status) in &report.coverage.unsuccessful_scanners {
        text.push_str(&format!("  {scanner}: did not succeed ({status})\n"));
    }
    if report.coverage.successful_scanners.is_empty()
        && report.coverage.unsuccessful_scanners.is_empty()
    {
        text.push_str("  no scanner results recorded\n");
    }
    text.push_str(&format!(
        "Coverage complete: {}\n",
        if report.coverage.complete {
            "yes"
        } else {
            "no"
        }
    ));

    html.push_str("<h2>Scanner coverage</h2><ul>");
    if report.coverage.successful_scanners.is_empty()
        && report.coverage.unsuccessful_scanners.is_empty()
    {
        html.push_str("<li>no scanner results recorded</li>");
    }
    for scanner in &report.coverage.successful_scanners {
        html.push_str(&format!("<li>{}: succeeded</li>", escape_html(scanner)));
    }
    for (scanner, status) in &report.coverage.unsuccessful_scanners {
        html.push_str(&format!(
            "<li>{}: did not succeed ({})</li>",
            escape_html(scanner),
            escape_html(status)
        ));
    }
    html.push_str("</ul>");
    html.push_str(&format!(
        "<p>Coverage complete: <strong>{}</strong></p>",
        if report.coverage.complete {
            "yes"
        } else {
            "no"
        }
    ));

    // ---- Security summary -------------------------------------------------
    text.push_str("\nSecurity summary\n");
    text.push_str(&format!("  findings: {}\n", report.summary.finding_count));
    for (severity, count) in &report.summary.findings_by_severity {
        text.push_str(&format!("    {severity}: {count}\n"));
    }
    text.push_str(&format!("  security score: {}\n", score_text(report)));

    html.push_str("<h2>Security summary</h2>");
    html.push_str(&format!(
        "<p>Findings: <strong>{}</strong></p><ul>",
        report.summary.finding_count
    ));
    for (severity, count) in &report.summary.findings_by_severity {
        html.push_str(&format!(
            "<li>{severity}: {count}</li>",
            severity = escape_html(severity)
        ));
    }
    html.push_str("</ul>");
    html.push_str(&format!(
        "<p>Security score: <strong>{}</strong></p>",
        escape_html(&score_text(report))
    ));

    // ---- Findings ---------------------------------------------------------
    text.push_str("\nFindings\n");
    if report.findings.is_empty() {
        // Only reachable when coverage actually completed: the wording must not
        // read as "no problems" when the audit never established coverage.
        text.push_str(if report.coverage.complete {
            "  none: every scanner completed and none reported a finding\n"
        } else {
            "  none reported, but coverage was incomplete; this is not a clean result\n"
        });
        html.push_str(if report.coverage.complete {
            "<p>No findings: every scanner completed and none reported a finding.</p>"
        } else {
            "<p><strong>No findings were reported, but coverage was incomplete. This is not a clean result.</strong></p>"
        });
    }
    for finding in &report.findings {
        let location = if finding.location.file.trim().is_empty() {
            "(no location)".to_string()
        } else if finding.location.line > 0 {
            format!("{}:{}", finding.location.file, finding.location.line)
        } else {
            finding.location.file.clone()
        };
        text.push_str(&format!(
            "\n  [{}] {}\n    id: {}\n    scanner: {} (rule {})\n    location: {}\n",
            finding.severity.as_str(),
            finding.title,
            finding.id,
            finding.provenance.scanner,
            finding.provenance.rule_id,
            location,
        ));
        // Evidence is already redacted upstream; it is copied, never re-derived
        // and never read back from the repository.
        if !finding.evidence.trim().is_empty() {
            text.push_str(&format!("    evidence: {}\n", finding.evidence));
        }
        if let Some(remediation) = &finding.remediation {
            text.push_str(&format!("    remediation: {remediation}\n"));
        }

        html.push_str(&format!(
            "<h3>{} <small>[{}]</small></h3><ul>\
             <li><strong>id:</strong> {}</li>\
             <li><strong>scanner:</strong> {} (rule {})</li>\
             <li><strong>location:</strong> {}</li>",
            escape_html(&finding.title),
            escape_html(finding.severity.as_str()),
            escape_html(&finding.id),
            escape_html(&finding.provenance.scanner),
            escape_html(&finding.provenance.rule_id),
            escape_html(&location),
        ));
        if !finding.evidence.trim().is_empty() {
            html.push_str(&format!(
                "<li><strong>evidence:</strong> {}</li>",
                escape_html(&finding.evidence)
            ));
        }
        if let Some(remediation) = &finding.remediation {
            html.push_str(&format!(
                "<li><strong>remediation:</strong> {}</li>",
                escape_html(remediation)
            ));
        }
        html.push_str("</ul>");
    }

    // ---- AI narrative (optional) -----------------------------------------
    // Present only when a validated narrative exists. Its absence is not an
    // error and produces no placeholder text: the deterministic report above is
    // the deliverable either way.
    if let Some(narrative) = narrative {
        text.push_str("\nAI explanation (non-authoritative)\n");
        text.push_str(&format!("{}\n", narrative.executive_summary));
        for explanation in &narrative.finding_explanations {
            text.push_str(&format!(
                "  {}: {}\n",
                explanation.finding_id, explanation.explanation
            ));
        }
        if !narrative.limitations.is_empty() {
            text.push_str("\n  Limitations carried from the audit:\n");
            for limitation in &narrative.limitations {
                text.push_str(&format!("    - {limitation}\n"));
            }
        }

        html.push_str("<h2>AI explanation <small>(non-authoritative)</small></h2>");
        html.push_str(&format!(
            "<p>{}</p>",
            escape_html(&narrative.executive_summary)
        ));
        if !narrative.finding_explanations.is_empty() {
            html.push_str("<ul>");
            for explanation in &narrative.finding_explanations {
                html.push_str(&format!(
                    "<li><strong>{}</strong>: {}</li>",
                    escape_html(&explanation.finding_id),
                    escape_html(&explanation.explanation)
                ));
            }
            html.push_str("</ul>");
        }
        if !narrative.limitations.is_empty() {
            html.push_str("<p>Limitations carried from the audit:</p><ul>");
            for limitation in &narrative.limitations {
                html.push_str(&format!("<li>{}</li>", escape_html(limitation)));
            }
            html.push_str("</ul>");
        }
    }

    // ---- Limitations ------------------------------------------------------
    if !report.limitations.is_empty() {
        text.push_str("\nAudit limitations\n");
        for limitation in &report.limitations {
            text.push_str(&format!("  - {limitation}\n"));
        }
        html.push_str("<h2>Audit limitations</h2><ul>");
        for limitation in &report.limitations {
            html.push_str(&format!("<li>{}</li>", escape_html(limitation)));
        }
        html.push_str("</ul>");
    }

    EmailArtifact {
        schema_version: crate::orchestrator::delivery::DELIVERY_SCHEMA_VERSION,
        execution_id: report.identity.execution_id.clone(),
        attempt_number: report.identity.attempt_number,
        subject: subject(report),
        text_body: text,
        html_body: html,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escaping_neutralises_inert_payloads() {
        for payload in [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            // A bare scheme with no tag openers is inert text: there is no markup
            // for it to execute through, so the correct property is tag openers,
            // not the word itself.
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "<iframe src=//evil>",
        ] {
            let escaped = escape_html(payload);
            assert!(!escaped.contains('<'), "left a tag open: {escaped}");
            assert!(!escaped.contains('>'), "left a tag close: {escaped}");
            assert!(!escaped.contains('"'), "left a quote: {escaped}");
            assert!(!escaped.contains('\''), "left an apostrophe: {escaped}");
        }
        // Ampersands are escaped too, so no entity confusion.
        assert_eq!(escape_html("a & b"), "a &amp; b");
    }
}
