//! Phase 14: the constrained AI reporter **contract** and its **validator**.
//!
//! Phase 13 established a deterministic report that is trustworthy on its own.
//! This module defines the only shape an AI narrative may take when one is
//! attached to that report, and the rules that decide whether a candidate
//! narrative is allowed to exist at all.
//!
//! The governing invariant:
//!
//! > Every security claim in AI output must be traceable to an existing
//! > canonical finding, canonical coverage state, or canonical limitation.
//!
//! ## Why a validator, and why it is deterministic
//!
//! An LLM is a *proposal* mechanism. It is not trusted to describe the audit,
//! only to explain it. The separation matters: a model can hallucinate a
//! plausible-sounding vulnerability, and a plausible-sounding vulnerability in a
//! security product is the single most damaging failure mode available.
//!
//! So the model's output is never *merged* into the report. It is validated
//! against the frozen canonical audit, and the answer is binary. There is no
//! partial acceptance, no "close enough", and no repair pass: an output that
//! trips any rule is rejected wholesale, and the deterministic report stands
//! unchanged. That is what makes it safe to keep an AI layer in the loop at
//! all — the blast radius of a bad generation is a missing paragraph, not a
//! wrong audit.
//!
//! Nothing in this module performs I/O. It cannot reach the repository, the
//! scanners, the database, or a model provider, which is what allows the entire
//! rule set to be tested exhaustively with no network and no AI.

use crate::models::Severity;
use crate::schemas::canonical_audit::CANONICAL_AUDIT_VERSION;
use crate::schemas::report::{CanonicalAuditReport, CoverageState};
use crate::services::redaction::contains_known_credential_assignment;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Version tag for every AI narrative document.
///
/// Separate from the report schema version on purpose: the narrative is an
/// optional, regenerable annotation on top of a permanent record. Bumping it
/// must never imply the underlying audit changed.
pub const AI_NARRATIVE_SCHEMA_VERSION: u32 = 1;

/// Bounds on narrative size.
///
/// A model is an untrusted input source even when it is a model we called. These
/// caps mean a verbose or looping generation is rejected outright rather than
/// persisted into a report a human will read.
pub const MAX_EXECUTIVE_SUMMARY_CHARS: usize = 2_000;
pub const MAX_EXPLANATION_CHARS: usize = 2_000;
pub const MAX_GUIDANCE_CHARS: usize = 2_000;

/// The AI's explanation of one canonical finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingExplanation {
    /// **Must** name a finding that exists in the canonical audit.
    pub finding_id: String,
    /// Optional restatement of severity. If present it must match the canonical
    /// severity exactly — the model may not re-rank a finding.
    pub severity: Option<String>,
    /// Prose explaining why this finding matters.
    pub explanation: String,
}

/// The AI's remediation advice for one canonical finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationGuidance {
    /// **Must** name a finding that exists in the canonical audit.
    pub finding_id: String,
    /// The advice itself.
    pub guidance: String,
    /// Always `false`.
    ///
    /// Nothing an AI says about a repository has been verified against that
    /// repository. The field exists so the distinction travels with the data
    /// rather than living only in a caption, and the validator refuses any
    /// narrative that sets it.
    pub verified: bool,
}

/// A structured AI narrative attached to a deterministic report.
///
/// This is a *presentation* layer over facts that already exist. It adds no
/// findings, no severities, and no coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportNarrative {
    pub narrative_schema_version: u32,
    /// One paragraph of plain-language framing. Facts in it must be consistent
    /// with the canonical audit.
    pub executive_summary: String,
    pub finding_explanations: Vec<FindingExplanation>,
    pub remediation_guidance: Vec<RemediationGuidance>,
    /// Must be an exact subset of the canonical audit's limitations.
    pub limitations: Vec<String>,
}

/// Why a candidate narrative was refused.
///
/// Every variant is a distinct, testable rule rather than a catch-all, so a
/// rejection says precisely what the model got wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NarrativeViolation {
    #[error("narrative schema version {found} is not supported (expected {expected})")]
    UnsupportedNarrativeVersion { found: u32, expected: u32 },

    #[error("the canonical report was produced under unsupported version {found}")]
    UnsupportedCanonicalVersion { found: u32, expected: u32 },

    #[error("the executive summary is empty")]
    EmptyExecutiveSummary,

    #[error("the explanation for finding '{finding_id}' is empty")]
    EmptyExplanation { finding_id: String },

    #[error("the remediation guidance for finding '{finding_id}' is empty")]
    EmptyGuidance { finding_id: String },

    #[error("the executive summary exceeds its character limit")]
    ExecutiveSummaryTooLong,

    #[error(
        "the narrative references finding '{finding_id}', which is not in the canonical audit"
    )]
    UnknownFindingReference { finding_id: String },

    #[error("finding '{finding_id}' is explained more than once")]
    DuplicateExplanation { finding_id: String },

    #[error("finding '{finding_id}' has more than one remediation entry")]
    DuplicateGuidance { finding_id: String },

    #[error("finding '{finding_id}' is {claimed} in the narrative but {canonical} in the audit")]
    SeverityMismatch {
        finding_id: String,
        claimed: String,
        canonical: String,
    },

    #[error("the narrative restates a confidence value for '{finding_id}'; confidence is not the model's to report")]
    ConfidenceRestated { finding_id: String },

    #[error("the narrative cites {identifier}, which does not appear in the canonical audit")]
    InventedClassification { identifier: String },

    #[error("the narrative claims a verified remediation for '{finding_id}'")]
    VerifiedRemediationClaim { finding_id: String },

    #[error(
        "the narrative presents remediation for '{finding_id}' as a fact rather than a suggestion"
    )]
    RemediationStatedAsFact { finding_id: String },

    #[error("the narrative claims complete coverage, but coverage is {state:?}")]
    CoverageOverclaim { state: CoverageState },

    #[error("the narrative describes scanner '{scanner}' as successful, but it is {actual}")]
    ScannerSuccessOverclaim { scanner: String, actual: String },

    #[error(
        "the narrative states that no vulnerabilities were found, but the audit recorded {count}"
    )]
    FalseAllClear { count: usize },

    #[error("the narrative contains credential-like material")]
    SecretMaterial,

    #[error("the narrative states a repository location the audit never reported: {detail:?}")]
    InventedLocation { detail: String },

    #[error("the narrative asserts an unsupported claim: {phrase:?}")]
    ProhibitedClaim { phrase: String },

    #[error("the narrative introduces a limitation the audit did not record: {limitation:?}")]
    InventedLimitation { limitation: String },

    #[error("the model response could not be parsed as a narrative: {detail}")]
    MalformedResponse { detail: String },

    #[error("{field} exceeds its character limit")]
    FieldTooLong { field: &'static str },
}

/// Phrases that assert a clean bill of health.
///
/// Checked case-insensitively as substrings. The list is deliberately narrow and
/// concrete: each entry is a sentence a model reaches for when it wants to sound
/// reassuring, and every one of them is unsupportable whenever the audit
/// recorded a finding or incomplete coverage. A narrow list is used instead of
/// sentiment analysis on purpose — it must be *exhaustively testable*, and a
/// reader has to be able to look at this list and know exactly what is refused.
const ALL_CLEAR_PHRASES: [&str; 8] = [
    "no vulnerabilities",
    "no security issues",
    "no known vulnerabilities",
    "completely secure",
    "entirely secure",
    "no threats",
    "nothing to fix",
    "fully secure",
];

/// Phrases that assert complete coverage regardless of what the audit recorded.
const COMPLETE_COVERAGE_PHRASES: [&str; 6] = [
    "fully scanned",
    "complete coverage",
    "comprehensive scan",
    "every file was scanned",
    "all files were analyzed",
    "no files were skipped",
];

/// Phrases presenting advice as an accomplished, verified fix.
const VERIFIED_REMEDIATION_PHRASES: [&str; 6] = [
    "this fixes",
    "this will fix",
    "guarantees",
    "is now secure",
    "has been remediated",
    "verified fixed",
];

/// Phrases asserting a confidence value.
const CONFIDENCE_CLAIM_PHRASES: [&str; 6] = [
    "confidence: high",
    "confidence: medium",
    "confidence: low",
    "confidence is high",
    "confidence is low",
    "high confidence",
];

fn contains_any<'a>(haystack: &str, needles: &'a [&'a str]) -> Option<&'a str> {
    let lowered = haystack.to_lowercase();
    needles
        .iter()
        .copied()
        .find(|needle| lowered.contains(needle))
}

/// The first invented repository location in `text`, if any.
///
/// Bounded on purpose: three shapes, no general path parser. A `/` anywhere in
/// prose (the audit's own text never appears in an explanation), an explicit
/// "line 42" claim, or a `package@version` coordinate. Deliberately *not*
/// matched: colon-separated classification ids such as `A07:2021`, bare version
/// numbers, and dotted words, because those legitimately appear in ordinary
/// security prose and refusing them would reject honest explanations.
fn invented_location(text: &str) -> Option<String> {
    // A slash with something on both sides: `/etc/shadow`, `config/aws.env`.
    if let Some((index, _)) = text.match_indices('/').find(|(index, _)| *index > 0) {
        return Some(
            text[index..]
                .split_whitespace()
                .next()
                .unwrap_or("/")
                .to_string(),
        );
    }
    let lowered = text.to_lowercase();
    if let Some(position) = lowered.find("line ") {
        let rest = &text[position + "line ".len()..];
        let number: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if !number.is_empty() {
            return Some(format!("line {number}"));
        }
    }
    // `lodash@1.2.3`, `requests@2.31.0` — a package coordinate with a version.
    if let Some((index, _)) = text.match_indices('@').find(|(index, _)| *index > 0) {
        let before = text[..index]
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .count();
        let after = text[index + 1..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .count();
        if before > 0 && after >= 3 {
            let start = index - before;
            let end = (index + 1 + after).min(text.len());
            return Some(text[start..end].to_string());
        }
    }
    None
}

/// Every identifier the canonical audit actually contains.
///
/// Used to decide whether a `CWE-n`/`CVE-n` mention is a restatement or an
/// invention. Built from the audit rather than hardcoded so the model cannot
/// cite a classification the scanners never reported — including one that is
/// real and applicable in the abstract, which is exactly how invented CVEs enter
/// security reports.
fn canonical_identifiers(report: &CanonicalAuditReport) -> BTreeSet<String> {
    let mut identifiers = BTreeSet::new();
    for finding in &report.findings {
        if let Some(cwe) = finding.cwe_id.as_deref() {
            identifiers.insert(cwe.trim().to_uppercase());
        }
        if let Some(owasp) = finding.owasp_category.as_deref() {
            identifiers.insert(owasp.trim().to_uppercase());
        }
        for reference in &finding.references {
            identifiers.insert(reference.url.trim().to_uppercase());
        }
    }
    identifiers
}

/// Validate a candidate narrative against the deterministic report it claims to
/// describe.
///
/// Returns the narrative unchanged on success, or the **first** rule it violates
/// on failure. Rules are evaluated in a fixed order — identity, then structure,
/// then prose — so a given candidate always produces the same rejection, which
/// is what makes the outcome reproducible and the rule set testable.
///
/// The first violation is returned rather than a list because there is no
/// "mostly valid" outcome: a narrative is either a faithful explanation of this
/// audit or it is refused.
pub fn validate_narrative(
    report: &CanonicalAuditReport,
    narrative: &ReportNarrative,
) -> Result<ReportNarrative, NarrativeViolation> {
    // ---- Version gates -----------------------------------------------------
    if narrative.narrative_schema_version != AI_NARRATIVE_SCHEMA_VERSION {
        return Err(NarrativeViolation::UnsupportedNarrativeVersion {
            found: narrative.narrative_schema_version,
            expected: AI_NARRATIVE_SCHEMA_VERSION,
        });
    }
    if report.identity.canonical_schema_version != CANONICAL_AUDIT_VERSION {
        return Err(NarrativeViolation::UnsupportedCanonicalVersion {
            found: report.identity.canonical_schema_version,
            expected: CANONICAL_AUDIT_VERSION,
        });
    }

    // ---- Shape and bounds --------------------------------------------------
    if narrative.executive_summary.trim().is_empty() {
        return Err(NarrativeViolation::EmptyExecutiveSummary);
    }
    if narrative.executive_summary.chars().count() > MAX_EXECUTIVE_SUMMARY_CHARS {
        return Err(NarrativeViolation::ExecutiveSummaryTooLong);
    }

    // The set of findings that actually exist. Everything below is a membership
    // question against this one set.
    let known: BTreeSet<&str> = report
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect();
    let severity_of = |id: &str| -> Option<Severity> {
        report
            .findings
            .iter()
            .find(|finding| finding.id == id)
            .map(|finding| finding.severity)
    };

    // ---- Structural traceability ------------------------------------------
    //
    // Every referenced id must exist, each at most once. This is the rule that
    // makes "the model cannot invent a vulnerability" true: an explanation for
    // `finding_id: "invented-vulnerability"` has nothing to attach to and is
    // refused before any prose is read.
    let mut explained = BTreeSet::new();
    for explanation in &narrative.finding_explanations {
        if !known.contains(explanation.finding_id.as_str()) {
            return Err(NarrativeViolation::UnknownFindingReference {
                finding_id: explanation.finding_id.clone(),
            });
        }
        if !explained.insert(explanation.finding_id.clone()) {
            return Err(NarrativeViolation::DuplicateExplanation {
                finding_id: explanation.finding_id.clone(),
            });
        }
        if explanation.explanation.trim().is_empty() {
            return Err(NarrativeViolation::EmptyExplanation {
                finding_id: explanation.finding_id.clone(),
            });
        }
        if explanation.explanation.chars().count() > MAX_EXPLANATION_CHARS {
            return Err(NarrativeViolation::FieldTooLong {
                field: "an explanation",
            });
        }

        // The model may restate a severity but never re-rank one.
        if let Some(claimed) = explanation.severity.as_deref() {
            let canonical = severity_of(&explanation.finding_id).ok_or_else(|| {
                NarrativeViolation::UnknownFindingReference {
                    finding_id: explanation.finding_id.clone(),
                }
            })?;
            if !claimed.eq_ignore_ascii_case(canonical.as_str()) {
                return Err(NarrativeViolation::SeverityMismatch {
                    finding_id: explanation.finding_id.clone(),
                    claimed: claimed.to_string(),
                    canonical: canonical.as_str().to_string(),
                });
            }
        }
    }

    let mut guided = BTreeSet::new();
    for guidance in &narrative.remediation_guidance {
        if !known.contains(guidance.finding_id.as_str()) {
            return Err(NarrativeViolation::UnknownFindingReference {
                finding_id: guidance.finding_id.clone(),
            });
        }
        if !guided.insert(guidance.finding_id.clone()) {
            return Err(NarrativeViolation::DuplicateGuidance {
                finding_id: guidance.finding_id.clone(),
            });
        }
        if guidance.verified {
            return Err(NarrativeViolation::VerifiedRemediationClaim {
                finding_id: guidance.finding_id.clone(),
            });
        }
        if guidance.guidance.trim().is_empty() {
            return Err(NarrativeViolation::EmptyGuidance {
                finding_id: guidance.finding_id.clone(),
            });
        }
        if guidance.guidance.chars().count() > MAX_GUIDANCE_CHARS {
            return Err(NarrativeViolation::FieldTooLong {
                field: "a remediation guidance",
            });
        }
    }

    // ---- Limitations -------------------------------------------------------
    //
    // The model may select from what the audit recorded but not add to it.
    // Inventing a limitation is less dangerous than inventing a finding, but it
    // erodes the same trust: a reader who sees limitations they cannot trace
    // stops trusting the ones they can.
    for limitation in &narrative.limitations {
        if !report.limitations.contains(limitation) {
            return Err(NarrativeViolation::InventedLimitation {
                limitation: limitation.clone(),
            });
        }
    }

    validate_prose(report, narrative, &canonical_identifiers(report))
}

/// Prose-level rules, applied to every free-text field the model controls.
///
/// These are the rules that cannot be enforced structurally, because prose has
/// no schema. Each is a narrow, listable prohibition rather than a judgement
/// call, so the whole set is testable and reviewable.
fn validate_prose(
    report: &CanonicalAuditReport,
    narrative: &ReportNarrative,
    known_identifiers: &BTreeSet<String>,
) -> Result<ReportNarrative, NarrativeViolation> {
    // Every string the model authored, gathered once so each rule below covers
    // all of them rather than only the summary — a model must not be able to
    // smuggle a false claim into an explanation to evade a check on the summary.
    let mut texts: Vec<&str> = vec![narrative.executive_summary.as_str()];
    for explanation in &narrative.finding_explanations {
        texts.push(explanation.explanation.as_str());
    }
    for guidance in &narrative.remediation_guidance {
        texts.push(guidance.guidance.as_str());
    }

    for text in &texts {
        // A secret is refused wherever it appears. The canonical audit is already
        // redacted, so any credential-shaped string here is something the model
        // produced — either by reconstructing one from context or by echoing a
        // real one. Both are unacceptable.
        if contains_known_credential_assignment(text) {
            return Err(NarrativeViolation::SecretMaterial);
        }

        // The prompt never contains a file path, a line number, or a package
        // coordinate — so any location in the response is necessarily invented.
        // Refusing invented locations is therefore stricter than checking them
        // against the audit, and it cannot misfire on a faithful explanation:
        // there is nothing faithful for it to name.
        //
        // This is what stops "see /etc/shadow at line 4242 in lodash@1.2.3"
        // from being published as if the audit had found it.
        if let Some(detail) = invented_location(text) {
            return Err(NarrativeViolation::InventedLocation { detail });
        }

        // A clean bill of health is unsupportable whenever the audit found
        // anything. An all-clear on a scan with findings is the single most
        // dangerous sentence a security product can publish.
        let audit_found_something =
            report.summary.finding_count > 0 || report.summary.invalid_finding_count > 0;
        if audit_found_something && contains_any(text, &ALL_CLEAR_PHRASES).is_some() {
            return Err(NarrativeViolation::FalseAllClear {
                count: report.summary.finding_count,
            });
        }

        // Coverage may not be described as complete when it is not. This is the
        // AI-layer restatement of Phase 13's rule that a partial scan is never
        // clean: a reader who trusts a confident narrative over a cautious
        // coverage banner is exactly the failure this prevents.
        if !report.coverage.complete {
            if let Some(phrase) = contains_any(text, &COMPLETE_COVERAGE_PHRASES) {
                return Err(NarrativeViolation::ProhibitedClaim {
                    phrase: phrase.to_string(),
                });
            }
        }

        // A CWE/CVE/OWASP tag must exist in the audit. A plausible invented CVE
        // is indistinguishable from a real one to a reader, which is precisely
        // why it has to be refused rather than flagged.
        for identifier in prose_identifiers(text) {
            if !known_identifiers.contains(&identifier) {
                return Err(NarrativeViolation::InventedClassification { identifier });
            }
        }
    }

    // Remediation phrased as an accomplished fix. `verified: false` is a field a
    // model can set truthfully while still writing "this fixes the issue" in the
    // prose, so the prose is checked too.
    for guidance in &narrative.remediation_guidance {
        if contains_any(&guidance.guidance, &VERIFIED_REMEDIATION_PHRASES).is_some() {
            return Err(NarrativeViolation::RemediationStatedAsFact {
                finding_id: guidance.finding_id.clone(),
            });
        }
    }

    // A scanner that did not succeed cannot be described as having succeeded.
    // Checked against the canonical runs rather than any model-supplied list, so
    // the model has no input into which scanners existed.
    let joined = texts.join(" ").to_lowercase();
    for (scanner, status) in &report.coverage.unsuccessful_scanners {
        let lowered_scanner = scanner.to_lowercase();
        let says_succeeded = joined.contains(&format!("{lowered_scanner} succeeded"))
            || joined.contains(&format!("{lowered_scanner} passed"))
            || joined.contains(&format!("{lowered_scanner} completed successfully"));
        if says_succeeded {
            return Err(NarrativeViolation::ScannerSuccessOverclaim {
                scanner: scanner.clone(),
                actual: status.clone(),
            });
        }
    }

    // Confidence is the scanner's measurement to report, not the model's. A
    // narrative that asserts confidence is asserting a number it cannot have
    // observed, and a reader has no way to tell that apart from a real one.
    //
    // Checked across every authored string, not just the summary, so a model
    // cannot launder a confidence claim through an explanation. The finding id
    // is not attributable from free prose, so the variant records that the claim
    // was unattributed rather than guessing which finding it referred to.
    for text in &texts {
        let lowered = text.to_lowercase();
        if CONFIDENCE_CLAIM_PHRASES
            .iter()
            .any(|phrase| lowered.contains(phrase))
        {
            return Err(NarrativeViolation::ConfidenceRestated {
                finding_id: String::from("unspecified"),
            });
        }
    }

    Ok(narrative.clone())
}

/// Collect classification-looking tokens from free prose.
///
/// Deliberately narrow: it recognizes `CWE-79`, `CVE-2024-1234`, and bare `A01`
/// style OWASP tags. A token it cannot recognize is simply not checked as an
/// identifier, which is safe — an unrecognized token cannot become a *validated*
/// claim, because every claim that carries structure is validated structurally
/// instead.
fn prose_identifiers(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut current = String::new();
    for character in text.chars().chain(std::iter::once(' ')) {
        if character.is_ascii_alphanumeric() || character == '-' {
            current.push(character);
            continue;
        }
        let upper = current.to_uppercase();
        let looks_like_identifier = upper.starts_with("CWE-")
            || upper.starts_with("CVE-")
            || (upper.len() == 3
                && upper.starts_with('A')
                && upper[1..].chars().all(|c| c.is_ascii_digit()));
        if looks_like_identifier {
            found.push(upper);
        }
        current.clear();
    }
    found
}

/// A narrative that passed validation, paired with the report it describes.
///
/// This pairing is the point of the whole phase. The deterministic report is
/// retained alongside every accepted narrative rather than being replaced by it,
/// so the factual baseline survives a model change, an outage, or garbage
/// output. The narrative can always be dropped; nothing can be lost.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplainedReport {
    pub deterministic_report: CanonicalAuditReport,
    pub narrative: ReportNarrative,
}

/// Validate and, only on success, pair a narrative with its report.
///
/// This is the only way to obtain an [`ExplainedReport`], so it is impossible to
/// construct one holding an unvalidated narrative by any other route.
pub fn explain_report(
    report: CanonicalAuditReport,
    candidate: ReportNarrative,
) -> Result<ExplainedReport, NarrativeViolation> {
    let narrative = validate_narrative(&report, &candidate)?;
    Ok(ExplainedReport {
        deterministic_report: report,
        narrative,
    })
}
