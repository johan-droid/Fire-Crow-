use crate::schemas::ai_narrative::{
    validate_narrative, ReportNarrative, AI_NARRATIVE_SCHEMA_VERSION,
};
use crate::schemas::report::CanonicalAuditReport;

/// Version tag for the rendered prompt envelope, so a logged or cached prompt is
/// identifiable and a change to the prompt shape is visible rather than silent.
pub const PROMPT_SCHEMA_VERSION: u32 = 1;

/// Builds the exact prompt an AI reporter receives.
///
/// This function is the **input boundary** of Phase 14, and its constraints are
/// the point of the exercise:
///
/// * It takes a [`CanonicalAuditReport`] and nothing else. There is no parameter
///   through which a repository path, a scanner's raw JSON, a GitHub response, or
///   a database credential could arrive.
/// * It never includes finding evidence. The canonical audit is already
///   redacted, but omitting evidence entirely is stronger than relying on that: a
///   model given no secret material cannot echo one, so leak-freedom does not
///   depend on redaction having been correct upstream.
/// * It states the canonical facts the model may rely on and instructs it to
///   reference findings by id. The validator *enforces* that instruction; the
///   prompt *states* it so a well-behaved model rarely needs to be refused.
///
/// The output is deterministic: the same report always yields the same prompt.
pub fn build_prompt(report: &CanonicalAuditReport) -> String {
    let mut prompt = String::new();
    prompt.push_str(&format!(
        "You are writing an explanation of a completed security audit.\n\
         Prompt schema version: {PROMPT_SCHEMA_VERSION}\n\
         Output JSON schema version: {AI_NARRATIVE_SCHEMA_VERSION}\n\n"
    ));

    // The rules the validator enforces, stated up front so the model's first
    // instinct matches the validator. A prompt describing rules the validator
    // does not check would teach the model to trust an unenforced boundary,
    // which is worse than not mentioning it.
    prompt.push_str(
        "HARD RULES. These are enforced; violating any of them voids the whole response:\n\
         - Reference every finding by its exact id. Never invent a finding id.\n\
         - Never add, remove, merge, or re-rank findings.\n\
         - If you restate a severity, copy it exactly from the audit.\n\
         - Never state a confidence value; that is the scanner's measurement.\n\
         - Only cite CWE/CVE/OWASP identifiers that appear below.\n\
         - Never claim coverage is complete when the audit says it is partial.\n\
         - Never describe a scanner as successful unless the audit says so.\n\
         - Remediation is always a suggestion, never a verified fix.\n\
         - Never state or imply that no vulnerabilities exist if any were found.\n\
         - Never reproduce credentials, tokens, or secret values.\n\n",
    );

    prompt.push_str("AUDIT FACTS (the only permitted source of claims):\n");
    prompt.push_str(&format!(
        "  audit_id: {}\n  execution_id: {}\n  attempt_number: {}\n  repository: {}\n  snapshot_commit: {}\n",
        report.identity.audit_id,
        report.identity.execution_id,
        report.identity.attempt_number,
        report.identity.repository_url,
        report.identity
            .snapshot_commit
            .as_deref()
            .unwrap_or("(none recorded)"),
    ));
    prompt.push_str(&format!(
        "  coverage_state: {}\n  coverage_complete: {}\n",
        report.coverage.state.as_str(),
        report.coverage.complete
    ));
    prompt.push_str(&format!(
        "  total_findings: {}\n",
        report.summary.finding_count
    ));
    // A `null` score is stated as null, never as zero, so the model cannot learn
    // to describe "no score" as "a perfect score".
    match report.summary.security_score {
        Some(score) => prompt.push_str(&format!("  security_score: {score}\n")),
        None => prompt.push_str("  security_score: null (coverage incomplete)\n"),
    }

    if !report.coverage.unsuccessful_scanners.is_empty() {
        prompt.push_str("  scanners_that_did_not_succeed:\n");
        for (scanner, status) in &report.coverage.unsuccessful_scanners {
            prompt.push_str(&format!("    - {scanner}: {status}\n"));
        }
    }

    if !report.findings.is_empty() {
        prompt.push_str("\nFINDINGS:\n");
        for finding in &report.findings {
            prompt.push_str(&format!("  - id: {}\n", finding.id));
            prompt.push_str(&format!("    title: {}\n", finding.title));
            prompt.push_str(&format!("    severity: {}\n", finding.severity.as_str()));
            prompt.push_str(&format!("    scanner: {}\n", finding.provenance.scanner));
            // Unknown stays unknown. A missing CWE is omitted rather than
            // defaulted, so the model cannot learn that every finding has one.
            if let Some(cwe) = finding.cwe_id.as_deref() {
                prompt.push_str(&format!("    cwe: {cwe}\n"));
            }
            if let Some(owasp) = finding.owasp_category.as_deref() {
                prompt.push_str(&format!("    owasp: {owasp}\n"));
            }
        }
    }

    if !report.limitations.is_empty() {
        prompt.push_str("\nLIMITATIONS (reproduce exactly; do not add):\n");
        for limitation in &report.limitations {
            prompt.push_str(&format!("  - {limitation}\n"));
        }
    }

    prompt.push_str(
        "\nRespond with JSON only, no prose outside it:\n\
         {\n  \"narrative_schema_version\": 1,\n  \"executive_summary\": \"...\",\n  \
         \"finding_explanations\": [{\"finding_id\": \"...\", \"severity\": null, \"explanation\": \"...\"}],\n  \
         \"remediation_guidance\": [{\"finding_id\": \"...\", \"guidance\": \"...\", \"verified\": false}]\n}\n",
    );
    prompt
}

/// Parse and validate a model's raw response.
///
/// The two steps are fused deliberately. Parsing an untrusted string into a
/// typed narrative and accepting it as trustworthy are separate acts, and only
/// the second one is safe to skip. Fusing them means there is no way to obtain a
/// `ReportNarrative` from model output without passing the validator — the
/// failure mode of "validated in one place, constructed in another" is precisely
/// how unvalidated model text reaches a report.
pub fn parse_and_validate(
    report: &CanonicalAuditReport,
    raw: &str,
) -> std::result::Result<ReportNarrative, crate::schemas::ai_narrative::NarrativeViolation> {
    let narrative: ReportNarrative = serde_json::from_str(raw).map_err(|error| {
        crate::schemas::ai_narrative::NarrativeViolation::MalformedResponse {
            detail: error.to_string(),
        }
    })?;
    validate_narrative(report, &narrative)
}
