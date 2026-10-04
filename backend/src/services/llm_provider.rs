//! The production LLM transport: Google Gemini `generateContent`.
//!
//! This module is the *only* place in Fire Crow that speaks HTTP to a model
//! provider. Everything upstream of it — [`crate::services::narrative`] and
//! everything downstream — is provider-agnostic, so switching providers must
//! require changing this file, configuration, and `documentation/LLM_PROVIDER.md`,
//! and nothing else.
//!
//! What it does: build the request, authenticate, send, bound the response,
//! extract model text.
//!
//! What it deliberately does not do: parse a narrative, validate a finding,
//! touch a database, read a repository file, or decide what is true. It returns
//! untrusted text and nothing else. The verified provider contract this
//! implements is recorded in `documentation/LLM_PROVIDER.md`.

use crate::error::GenerationError;
use serde_json::Value;
use std::time::Duration;

/// Gemini's REST base path.
pub const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta";

/// Retry ceiling regardless of configuration.
///
/// Configuration may ask for more attempts; this caps them so a retry storm
/// cannot amplify an outage into an incident.
const MAX_ATTEMPTS: u32 = 3;

/// A Gemini transport.
///
/// Holds the credential, so it is deliberately not `Debug`-derivable in a form
/// that would print the key: the API key field is never logged, and this type
/// implements no `Display`.
pub struct ProviderClient {
    http: reqwest::Client,
    base_url: String,
    model: String,
    api_key: String,
    max_response_bytes: usize,
    max_attempts: u32,
    /// Total budget for the whole call, including retries.
    total_timeout: Duration,
    retry_backoff: Duration,
}

impl ProviderClient {
    /// Build from a validated configuration.
    ///
    /// Fails closed when the credential or the model is absent: §6 of the Phase
    /// 16 contract requires an explicitly configured model, and silently
    /// substituting another one would make the recorded model name a lie.
    pub fn from_model_config(
        config: &crate::services::narrative::ModelConfig,
        base_url: &str,
    ) -> Result<Self, GenerationError> {
        if config.api_key.trim().is_empty() || config.model.trim().is_empty() {
            return Err(GenerationError::NotConfigured);
        }
        Self::build(
            base_url,
            config.model.clone(),
            config.api_key.clone(),
            config.max_response_bytes,
            config.max_attempts,
            config.timeout,
        )
    }

    /// Construct directly. Used by tests against a local mock server.
    pub fn build(
        base_url: &str,
        model: impl Into<String>,
        api_key: impl Into<String>,
        max_response_bytes: usize,
        max_attempts: u32,
        total_timeout: Duration,
    ) -> Result<Self, GenerationError> {
        let base_url = validate_base_url(base_url)?;
        // The timeout covers the complete request; the service layer adds its own
        // deadline, and the earlier of the two wins.
        let http = reqwest::Client::builder()
            .timeout(total_timeout)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| GenerationError::Transport)?;
        Ok(Self {
            http,
            base_url,
            model: model.into(),
            api_key: api_key.into(),
            max_response_bytes,
            max_attempts: max_attempts.clamp(1, MAX_ATTEMPTS),
            total_timeout,
            retry_backoff: Duration::from_millis(250),
        })
    }

    /// Replace the inter-attempt backoff. Tests use zero to stay fast.
    pub fn with_retry_backoff(mut self, backoff: Duration) -> Self {
        self.retry_backoff = backoff;
        self
    }

    /// The configured model, for observability only.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Send `prompt` and return the model's text, untrusted and unparsed.
    ///
    /// The returned string is whatever the provider chose to emit. It has not
    /// been parsed, validated, trimmed, or repaired.
    pub async fn complete(&self, prompt: &str) -> Result<String, GenerationError> {
        // One hard deadline over every attempt, so retries cannot extend the call
        // beyond the configured budget.
        match tokio::time::timeout(self.total_timeout, self.complete_inner(prompt)).await {
            Ok(result) => result,
            Err(_) => Err(GenerationError::Timeout),
        }
    }

    async fn complete_inner(&self, prompt: &str) -> Result<String, GenerationError> {
        let body = request_body(prompt);
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let error = match self.send_once(&body).await {
                Ok(text) => return Ok(text),
                Err(error) => error,
            };
            // Retry only what is documented as transient, and only while attempts
            // and the caller's patience both remain.
            if !error.is_transient() || attempt >= self.max_attempts {
                return Err(error);
            }
            tokio::time::sleep(self.retry_backoff * attempt).await;
        }
    }

    async fn send_once(&self, body: &Value) -> Result<String, GenerationError> {
        let url = format!(
            "{}/models/{}:generateContent",
            self.base_url.trim_end_matches('/'),
            self.model
        );
        let response = self
            .http
            .post(&url)
            .header("x-goog-api-key", &self.api_key)
            .header("content-type", "application/json")
            .json(body)
            .send()
            .await
            .map_err(classify_transport_error)?;

        let status = response.status();
        if !status.is_success() {
            return Err(classify_status(status.as_u16()));
        }

        let text = read_bounded(response, self.max_response_bytes).await?;
        extract_model_text(&text)
    }
}

/// The Gemini request body.
///
/// Only the prompt and a JSON response MIME type. No `responseSchema`: the
/// narrative shape belongs to `schemas::ai_narrative`, and restating it here
/// would make the provider a second source of truth for the schema — the
/// coupling Phase 16 forbids.
fn request_body(prompt: &str) -> Value {
    serde_json::json!({
        "contents": [{
            "role": "user",
            "parts": [{ "text": prompt }],
        }],
        "generationConfig": {
            "responseMimeType": "application/json",
        },
    })
}

/// Map an HTTP status onto a failure class.
///
/// Gemini documents a distinct meaning per status, so they are not collapsed:
/// 401 is a credential to fix, 403 is a permission to fix, 429 is a wait, and
/// 5xx is an incident. The provider's own error body is deliberately not read.
fn classify_status(status: u16) -> GenerationError {
    match status {
        401 => GenerationError::Authentication,
        403 => GenerationError::Authorization,
        429 => GenerationError::RateLimited,
        400 | 404 | 405 | 415 | 422 => GenerationError::InvalidRequest,
        500..=599 => GenerationError::Unavailable,
        _ => GenerationError::Malformed,
    }
}

fn classify_transport_error(error: reqwest::Error) -> GenerationError {
    if error.is_timeout() {
        GenerationError::Timeout
    } else {
        GenerationError::Transport
    }
}

/// Read a response body with a hard byte ceiling.
///
/// The limit is enforced while streaming, not after buffering, so a provider
/// cannot dictate how much memory the backend allocates by promising a large
/// body. Content-Length is checked first when present, purely to fail faster.
async fn read_bounded(
    mut response: reqwest::Response,
    cap_bytes: usize,
) -> Result<String, GenerationError> {
    if response
        .content_length()
        .is_some_and(|declared| declared > cap_bytes as u64)
    {
        return Err(GenerationError::ResponseTooLarge { cap_bytes });
    }
    let mut buffer: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(classify_transport_error)? {
        if buffer.len() + chunk.len() > cap_bytes {
            // Rejected, never truncated: a truncated document could parse into a
            // narrative that misrepresents what the model actually said.
            return Err(GenerationError::ResponseTooLarge { cap_bytes });
        }
        buffer.extend_from_slice(&chunk);
    }
    String::from_utf8(buffer).map_err(|_| GenerationError::Malformed)
}

/// Pull the model's text out of a Gemini response.
///
/// Returns every text part in order; a response may be split across parts. A
/// body with no usable text — including one blocked before generation — is
/// malformed, and the reason is not forwarded to the caller.
fn extract_model_text(body: &str) -> Result<String, GenerationError> {
    let parsed: Value = serde_json::from_str(body).map_err(|_| GenerationError::Malformed)?;
    let candidates = parsed
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or(GenerationError::Malformed)?;
    let mut text = String::new();
    for candidate in candidates {
        let Some(parts) = candidate
            .get("content")
            .and_then(|content| content.get("parts"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for part in parts {
            if let Some(chunk) = part.get("text").and_then(Value::as_str) {
                text.push_str(chunk);
            }
        }
    }
    if text.trim().is_empty() {
        return Err(GenerationError::Malformed);
    }
    Ok(text)
}

/// Accept only an HTTPS endpoint, or plain HTTP on loopback.
///
/// The base URL is operator configuration, never user input — but a configurable
/// URL is still an SSRF primitive if it can be pointed anywhere, so the scheme is
/// constrained here rather than trusted. Loopback is allowed because the test
/// suite runs a mock server on 127.0.0.1.
fn validate_base_url(base_url: &str) -> Result<String, GenerationError> {
    let parsed = reqwest::Url::parse(base_url).map_err(|_| GenerationError::InvalidRequest)?;
    let host = parsed.host_str().unwrap_or_default();
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]");
    match parsed.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(GenerationError::InvalidRequest),
    }
    if !loopback && host != "generativelanguage.googleapis.com" {
        return Err(GenerationError::InvalidRequest);
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_endpoints_are_accepted() {
        assert!(validate_base_url(DEFAULT_BASE_URL).is_ok());
        assert!(validate_base_url("http://127.0.0.1:8080/v1beta").is_ok());
        // SSRF primitives and plaintext remote endpoints are refused.
        assert!(validate_base_url("http://generativelanguage.googleapis.com").is_err());
        assert!(validate_base_url("http://169.254.169.254/latest").is_err());
        assert!(validate_base_url("https://evil.example.com/v1beta").is_err());
        assert!(validate_base_url("file:///etc/passwd").is_err());
        assert!(validate_base_url("not a url").is_err());
    }

    #[test]
    fn statuses_are_not_collapsed_into_one_error() {
        assert_eq!(classify_status(401), GenerationError::Authentication);
        assert_eq!(classify_status(403), GenerationError::Authorization);
        assert_eq!(classify_status(429), GenerationError::RateLimited);
        assert_eq!(classify_status(400), GenerationError::InvalidRequest);
        assert_eq!(classify_status(404), GenerationError::InvalidRequest);
        assert_eq!(classify_status(503), GenerationError::Unavailable);
        assert_eq!(classify_status(500), GenerationError::Unavailable);
        assert_eq!(classify_status(302), GenerationError::Malformed);
    }

    #[test]
    fn only_documented_transient_failures_are_retryable() {
        assert!(GenerationError::RateLimited.is_transient());
        assert!(GenerationError::Unavailable.is_transient());
        for permanent in [
            GenerationError::Authentication,
            GenerationError::Authorization,
            GenerationError::InvalidRequest,
            GenerationError::Malformed,
            GenerationError::Timeout,
            GenerationError::Transport,
            GenerationError::ResponseTooLarge { cap_bytes: 1 },
            GenerationError::NotConfigured,
        ] {
            assert!(
                !permanent.is_transient(),
                "{permanent:?} must not be retried"
            );
        }
    }

    #[test]
    fn model_text_is_extracted_from_every_part() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {"parts": [{"text": "{\"a\":"}, {"text": "1}"}], "role": "model"},
                "finishReason": "STOP",
            }],
            "usageMetadata": {"totalTokenCount": 16},
        })
        .to_string();
        assert_eq!(extract_model_text(&body).unwrap(), "{\"a\":1}");
    }

    #[test]
    fn a_response_without_usable_text_is_malformed() {
        // Safety-blocked and empty-candidate shapes carry no text.
        let blocked = serde_json::json!({
            "promptFeedback": {"blockReason": "SAFETY"},
            "candidates": [{"finishReason": "SAFETY"}],
        })
        .to_string();
        assert_eq!(
            extract_model_text(&blocked),
            Err(GenerationError::Malformed)
        );
        assert_eq!(
            extract_model_text("not json"),
            Err(GenerationError::Malformed)
        );
        assert_eq!(extract_model_text("{}"), Err(GenerationError::Malformed));
        assert_eq!(
            extract_model_text(r#"{"candidates":[{"content":{"parts":[]}}]}"#),
            Err(GenerationError::Malformed)
        );
    }

    #[test]
    fn the_request_body_carries_the_prompt_and_nothing_else() {
        let body = request_body("PROMPT");
        assert_eq!(body["contents"][0]["parts"][0]["text"], "PROMPT");
        assert_eq!(
            body["generationConfig"]["responseMimeType"],
            "application/json"
        );
        // No schema is sent: the narrative shape has exactly one owner.
        assert!(body["generationConfig"].get("responseSchema").is_none());
    }
}
