//! AI narrative generation (Phase 15B).
//!
//! This module is the *model* boundary and nothing else. It receives a
//! finalized [`CanonicalAuditReport`] and produces a validated
//! [`ReportNarrative`]. It knows nothing about jobs, executions, the database,
//! scanners, repositories, Docker, or the filesystem — a fact enforced by its
//! signature: there is no parameter through which any of those could arrive.
//!
//! The pipeline is exactly the Phase 14 contract, wired to a transport:
//!
//! ```text
//! CanonicalAuditReport
//!     -> build_prompt(...)          (Phase 14; consumes the report and nothing else)
//!     -> model                      (untrusted transport output)
//!     -> parse_and_validate(...)    (Phase 14; the only accepted structure)
//!     -> ReportNarrative
//! ```
//!
//! The transport is a closure rather than a trait. Phase 14 established that a
//! deterministic validator already proves everything this contract claims, so no
//! network call is needed to prove it — and the closure keeps that true without
//! inventing a transport interface with a single production implementation. The
//! only thing a caller can substitute is *what text comes back*; it cannot skip
//! the prompt, the parse, or the validation.
//!
//! Everything the model returns is untrusted. There is no repair step, no
//! fence-stripping, and no "best effort" redaction: unsafe output is rejected,
//! never modified. That direction matters — a repair step would let a model
//! rewrite the rules it was asked to follow.

use crate::error::{AppError, Result};
use crate::schemas::ai_narrative::ReportNarrative;
use crate::schemas::report::CanonicalAuditReport;
use crate::services::llm::{build_prompt, parse_and_validate};
use std::future::Future;
use std::time::Duration;

/// Provider identity and bounds for one generation.
///
/// Deliberately separate from [`ReportNarrative`]: model metadata is an
/// operational fact about how a document was produced, not part of the
/// document's contract, so it must never leak into the persisted narrative.
#[derive(Clone)]
pub struct ModelConfig {
    pub provider: &'static str,
    /// Recorded for observability only; never part of the narrative.
    pub model: String,
    /// Not logged, not persisted, and never part of the prompt.
    pub api_key: String,
    /// Wall-clock ceiling for the model call. A model that hangs must not hold
    /// the execution: the deadline is an AI failure, never a scanner failure.
    pub timeout: Duration,
    /// Ceiling on the prompt, so a pathological report cannot produce an
    /// unbounded request.
    pub max_prompt_chars: usize,
    /// Ceiling on the response, so a flooding model cannot dictate how much
    /// memory the backend allocates before parsing.
    pub max_response_bytes: usize,
    /// Provider call attempts. Clamped by the transport; only transient
    /// failures are ever retried.
    pub max_attempts: u32,
}

/// Secret-safe `Debug`: the provider credential never renders.
///
/// A derived `Debug` would print `api_key` into any log line, panic message,
/// or test snapshot that formats the config. Everything else stays visible.
impl std::fmt::Debug for ModelConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelConfig")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("api_key", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("max_prompt_chars", &self.max_prompt_chars)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

impl ModelConfig {
    /// Build from application settings, reusing the provider configuration that
    /// already exists rather than introducing a second source of truth.
    pub fn from_settings(settings: &crate::config::Settings) -> Self {
        Self {
            provider: "gemini",
            // Empty when unset; the transport refuses to guess a model.
            model: settings.gemini_model.trim().to_string(),
            api_key: settings.gemini_api_key.trim().to_string(),
            timeout: Duration::from_secs(settings.gemini_timeout_seconds.max(1) as u64),
            max_prompt_chars: settings.gemini_max_prompt_chars.max(1) as usize,
            // The narrative schema caps its own fields; this bounds the wire
            // response before it is even parsed.
            max_response_bytes: 256 * 1024,
            max_attempts: settings.gemini_max_attempts.max(1) as u32,
        }
    }
}

/// What can go wrong, as a log-safe category.
///
/// Logging a category and a duration is the whole observability story: enough to
/// diagnose an AI failure, with no prompt text, no model response, no narrative
/// content, and no evidence.
pub fn failure_category(error: &AppError) -> &'static str {
    match error {
        // Provider failures keep their own class: an operator needs to tell a
        // rejected credential from a rate limit from an unreachable provider.
        AppError::Generation(error) => error.category(),
        AppError::Timeout(_) => "timeout",
        AppError::PayloadTooLarge => "prompt_too_large",
        AppError::ValidationError(_) => "validation_rejected",
        AppError::LlmError(_) => "provider_error",
        AppError::HttpClientError(_) => "transport_error",
        AppError::NotFound(_) => "no_deterministic_report",
        AppError::Conflict(_) => "execution_not_finalized",
        _ => "internal",
    }
}

/// Generate a validated narrative for one finalized deterministic report.
///
/// `completion` is the model transport. It receives the rendered prompt and
/// returns the raw, untrusted response body. It is the only place a network
/// call may occur, and it is bounded three ways: the prompt is capped before the
/// call, the call has an explicit deadline, and the response is capped before it
/// is parsed.
///
/// A rejection is a rejection. The whole narrative is refused if any rule is
/// broken; nothing is trimmed, softened, or partially accepted.
pub async fn generate_narrative<F, Fut>(
    report: &CanonicalAuditReport,
    model_config: &ModelConfig,
    completion: F,
) -> Result<ReportNarrative>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    let prompt = build_prompt(report);
    if prompt.chars().count() > model_config.max_prompt_chars {
        return Err(AppError::PayloadTooLarge);
    }

    let raw = match tokio::time::timeout(model_config.timeout, completion(prompt)).await {
        Ok(result) => result?,
        Err(_) => {
            // An AI-generation failure. Deliberately not a scanner or audit
            // failure: no coverage, score, or finding is affected by this.
            return Err(AppError::Timeout(format!(
                "AI narrative generation exceeded {}s",
                model_config.timeout.as_secs()
            )));
        }
    };

    if raw.len() > model_config.max_response_bytes {
        return Err(AppError::PayloadTooLarge);
    }

    parse_and_validate(report, &raw)
        .map_err(|violation| AppError::ValidationError(violation.to_string()))
}
