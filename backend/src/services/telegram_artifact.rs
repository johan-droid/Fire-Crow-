//! The Telegram delivery artifact (Phase 17.4).
//!
//! Decides *what shape* a security report takes in a chat window, and enforces the
//! one rule that matters here: a message must never misrepresent the audit. Either
//! the report is delivered whole, or the message says plainly that it is a summary
//! and states how many findings were omitted. Nothing is ever cut off mid-list and
//! presented as if it were the audit.
//!
//! ```text
//! rendered report <= limit  ->  the whole report, verbatim
//! rendered report >  limit  ->  an explicitly labelled summary + a reference
//! ```
//!
//! There is no third branch and no truncation path, because truncation is the one
//! behaviour that turns a security tool into a misleading one: a message cut off
//! after the first three critical findings reads exactly like an audit that found
//! three critical findings and nothing else.
//!
//! A pure function of the finalized [`CanonicalAuditReport`] and an optional
//! validated [`ReportNarrative`], like every other renderer in Fire Crow. It reads
//! no files, runs no scanner, queries no database, and calls no provider.

use crate::orchestrator::delivery::DELIVERY_SCHEMA_VERSION;
use crate::schemas::ai_narrative::ReportNarrative;
use crate::schemas::report::CanonicalAuditReport;
use crate::services::email_artifact::{coverage_label, render, score_text};

/// Telegram's documented ceiling for a text message, counted in UTF-16 code
/// units.
///
/// A chat window cannot show more than this, so sending more is not "a long
/// message", it is a message the provider rejects — which would surface as a
/// delivery failure for a reason that has nothing to do with the audit.
pub const TELEGRAM_MAX_MESSAGE_CHARS: usize = 4096;

/// Telegram's size unit: UTF-16 code units, not Unicode scalar values.
///
/// An emoji outside the Basic Multilingual Plane costs two units, so counting
/// `.chars()` would pass a message the provider then rejects — a delivery
/// failure whose only cause is a miscount.
pub fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Ceiling on the validated executive summary when it is included in a summary
/// message. The narrative is prose, not a security fact, so bounding it loses
/// nothing; the deterministic facts around it are never bounded.
const SUMMARY_PROSE_CHARS: usize = 600;

/// Ceiling on the repository URL inside a summary message. Matches the cap the
/// email subject uses, for the same reason: repository identity is user-controlled.
const MAX_REPOSITORY_CHARS: usize = 120;

/// One message, ready for [`crate::services::telegram::TelegramTransport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelegramMessage {
    /// The delivery contract that rendered this message.
    pub schema_version: i32,
    pub execution_id: String,
    pub attempt_number: i32,
    /// The message body. Already within the provider's ceiling.
    pub text: String,
    /// Whether this is a summary rather than the full report.
    ///
    /// Recorded so delivery state and tests can tell the two apart. A summary is
    /// a legitimate delivery; what would not be legitimate is delivering one
    /// *silently*.
    pub is_summary: bool,
    /// How many findings this message deliberately leaves out. Zero unless
    /// `is_summary`.
    pub omitted_findings: usize,
}

/// Render the message for one execution.
///
/// `limit` is a parameter rather than a constant so the threshold is explicit at
/// the call site and so a test can drive the boundary exactly, instead of
/// constructing a report that happens to land on the wrong side of it.
pub fn render_message(
    report: &CanonicalAuditReport,
    narrative: Option<&ReportNarrative>,
    limit: usize,
) -> TelegramMessage {
    // One rendering, reused: the email artifact's `text_body` is already the
    // complete plain-text report, so the "small" path cannot drift from what
    // email sends, and there is no second renderer to keep in agreement.
    let full = render(report, narrative).text_body;

    if utf16_len(&full) <= limit {
        return TelegramMessage {
            schema_version: DELIVERY_SCHEMA_VERSION,
            execution_id: report.identity.execution_id.clone(),
            attempt_number: report.identity.attempt_number,
            text: full,
            is_summary: false,
            omitted_findings: 0,
        };
    }

    TelegramMessage {
        schema_version: DELIVERY_SCHEMA_VERSION,
        execution_id: report.identity.execution_id.clone(),
        attempt_number: report.identity.attempt_number,
        text: summary(report, narrative),
        is_summary: true,
        omitted_findings: report.findings.len(),
    }
}

/// The explicitly-labelled summary.
///
/// Carries every *aggregate* fact — identity, coverage, counts, score,
/// limitations — because those are what a reader needs to know whether to open
/// the full report. It carries no individual finding, and it says so, so an omitted
/// finding can never be read as an absent one.
fn summary(report: &CanonicalAuditReport, narrative: Option<&ReportNarrative>) -> String {
    let mut text = String::new();

    // The repository URL is the only unbounded, user-controlled field in a summary
    // (scanner names, statuses, severities, and limitations are all bounded by the
    // scan contract). It is capped so a hostile URL cannot make every delivery fail
    // on the provider's message ceiling.
    let repository: String = report
        .identity
        .repository_url
        .trim()
        .chars()
        .take(MAX_REPOSITORY_CHARS)
        .collect();

    text.push_str("Fire Crow security audit — SUMMARY\n");
    text.push_str(&format!(
        "Repository: {}\nBranch: {}\nExecution: {} (attempt {})\nScan status: {}\n",
        repository,
        report.identity.repo_branch,
        report.identity.execution_id,
        report.identity.attempt_number,
        coverage_label(report),
    ));

    // Coverage before counts, for the same reason the email renderer puts it
    // there: a reader must not reach a "clean" conclusion from the summary while a
    // scanner silently failed.
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

    text.push_str("\nSecurity summary\n");
    text.push_str(&format!("  findings: {}\n", report.summary.finding_count));
    for (severity, count) in &report.summary.findings_by_severity {
        text.push_str(&format!("    {severity}: {count}\n"));
    }
    text.push_str(&format!("  security score: {}\n", score_text(report)));

    // The honest statement of what this message is not. Without it, a chat
    // message showing "findings: 12" and no detail is indistinguishable from one
    // claiming there is nothing to see.
    if report.findings.is_empty() {
        text.push_str(
            "\nNo individual findings: every scanner completed and none reported a finding.\n",
        );
    } else {
        text.push_str(&format!(
            "\n{} individual finding(s) are NOT shown in this message.\n\
             Their details, evidence, and locations are in the full report for this execution.\n\
             Nothing has been assessed as resolved or removed.\n",
            report.findings.len()
        ));
    }

    // The narrative is optional, validated prose. Included because a reader who
    // only ever sees a summary still benefits from it, bounded because it is not a
    // security fact and must not be able to crowd one out.
    if let Some(narrative) = narrative {
        let prose: String = narrative
            .executive_summary
            .chars()
            .take(SUMMARY_PROSE_CHARS)
            .collect();
        text.push_str("\nAI explanation (non-authoritative)\n");
        text.push_str(&format!("{prose}\n"));
    }

    if !report.limitations.is_empty() {
        text.push_str("\nAudit limitations\n");
        for limitation in &report.limitations {
            text.push_str(&format!("  - {limitation}\n"));
        }
    }

    text.push_str(&format!(
        "\nReference: Fire Crow execution {} (attempt {}). Open this execution's report for the full findings.\n",
        report.identity.execution_id, report.identity.attempt_number,
    ));
    text
}
