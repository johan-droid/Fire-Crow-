//! The Telegram delivery transport (Phase 17.3).
//!
//! A *transport adapter* and nothing else: it knows how to put an already-rendered
//! message in front of a Telegram chat, and it knows nothing about security. It
//! receives plain message text that has already been through
//! [`crate::services::telegram_artifact`], so raw findings, scanner JSON,
//! repository files, model prompts, and model responses cannot reach it — there is
//! no parameter through which any of them could arrive.
//!
//! What it does: build the request, authenticate, send, bound the response, and
//! return the provider's message id.
//!
//! What it deliberately does not do: decide what a report says, render one, touch
//! PostgreSQL, read a repository file, or record delivery state. It returns a
//! provider's message id, or a log-safe failure class.
//!
//! ## The credential is in the URL
//!
//! Telegram's HTTP API carries the bot token as a path segment (`/bot<token>/…`),
//! not as a header. That makes the token far easier to leak than a bearer header
//! would be, because a `reqwest::Error`'s own `Display` includes the request URL.
//! So this module never formats a `reqwest::Error`: every failure path returns a
//! fixed enum variant, and the token appears in no log line, no error message, and
//! no `Display` output. See [`classify_transport_error`].

use crate::error::DeliveryError;
use serde_json::Value;
use std::time::Duration;

/// Telegram's API base path.
pub const DEFAULT_BASE_URL: &str = "https://api.telegram.org";

/// Retry ceiling regardless of configuration: a delivery must not become a retry
/// storm against the operator's chat.
const MAX_ATTEMPTS: u32 = 3;

/// A Telegram transport.
///
/// Holds the bot token, so it is deliberately not `Debug`-derivable in a form
/// that would print the token, and it implements no `Display`.
pub struct TelegramTransport {
    http: reqwest::Client,
    base_url: String,
    bot_token: String,
    max_response_bytes: usize,
    max_attempts: u32,
    /// Total budget for the whole call, including retries.
    total_timeout: Duration,
    retry_backoff: Duration,
}

impl TelegramTransport {
    /// Build from operator configuration.
    ///
    /// Fails closed when the credential or the destination is absent: a delivery
    /// with no configured chat must be refused rather than sent somewhere guessed.
    pub fn new(
        base_url: &str,
        bot_token: &str,
        max_response_bytes: usize,
        max_attempts: u32,
        total_timeout: Duration,
    ) -> Result<Self, DeliveryError> {
        if bot_token.trim().is_empty() {
            return Err(DeliveryError::NotConfigured);
        }
        let base_url = validate_base_url(base_url)?;
        // The timeout covers the complete request; the delivery orchestrator adds
        // its own deadline, and the earlier of the two wins.
        let http = reqwest::Client::builder()
            .timeout(total_timeout)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| DeliveryError::Transport)?;
        Ok(Self {
            http,
            base_url,
            bot_token: bot_token.trim().to_string(),
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

    /// Send `text` to `chat_id` and return the provider's message id.
    ///
    /// `chat_id` is operator configuration resolved by the caller, never request
    /// input: nothing in a request body may choose where a security report is
    /// sent.
    pub async fn send_message(&self, chat_id: &str, text: &str) -> Result<String, DeliveryError> {
        let chat_id = chat_id.trim();
        if chat_id.is_empty() || chat_id.len() > 64 {
            return Err(DeliveryError::NotConfigured);
        }
        // One hard deadline over every attempt, so retries cannot extend the call
        // beyond the configured budget.
        match tokio::time::timeout(self.total_timeout, self.send_inner(chat_id, text)).await {
            Ok(result) => result,
            Err(_) => Err(DeliveryError::Timeout),
        }
    }

    async fn send_inner(&self, chat_id: &str, text: &str) -> Result<String, DeliveryError> {
        let body = request_body(text);
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let error = match self.send_once(chat_id, &body).await {
                Ok(receipt) => return Ok(receipt),
                Err(error) => error,
            };
            // Retry only what is documented as transient, and only while attempts
            // and the caller's patience both remain. A rejected token or a
            // malformed request is never retried: it would fail identically.
            if !error.is_transient() || attempt >= self.max_attempts {
                return Err(error);
            }
            tokio::time::sleep(self.retry_backoff * attempt).await;
        }
    }

    async fn send_once(&self, chat_id: &str, body: &Value) -> Result<String, DeliveryError> {
        let url = format!(
            "{}/bot{}/sendMessage",
            self.base_url.trim_end_matches('/'),
            self.bot_token
        );
        let response = self
            .http
            .post(&url)
            .header("content-type", "application/json")
            .json(&json_with_chat(chat_id, body))
            .send()
            .await
            // Never `error.to_string()` here: that is the request URL, and the
            // request URL contains the bot token.
            .map_err(classify_transport_error)?;

        let status = response.status();
        if !status.is_success() {
            // Telegram's own error body is deliberately not read. It echoes the
            // chat id and carries internal diagnostics.
            return Err(classify_status(status.as_u16()));
        }

        let text = read_bounded(response, self.max_response_bytes).await?;
        extract_message_id(&text)
    }
}

/// The request payload, without the destination.
///
/// Kept separate so [`json_with_chat`] is the single place a chat id enters the
/// request, which makes the "destination is never request-derived" property
/// checkable by reading one function.
fn request_body(text: &str) -> Value {
    // Plain text, no parse_mode. Markdown would make the model-adjacent narrative
    // prose and repository-controlled finding titles an injection surface into the
    // message formatting, and Telegram's HTML/Markdown parsers reject on
    // unbalanced markup — a finding titled with a stray `*` would fail the whole
    // delivery. Plain text cannot be mis-parsed.
    serde_json::json!({ "text": text })
}

fn json_with_chat(chat_id: &str, body: &Value) -> Value {
    let mut payload = body.clone();
    if let Value::Object(map) = &mut payload {
        map.insert("chat_id".to_string(), Value::String(chat_id.to_string()));
    }
    payload
}

/// Map an HTTP status onto a failure class.
///
/// Not collapsed: 401 is a bot token to fix, 403 is a chat the bot was removed
/// from, 429 is a rate limit to wait out, and 5xx is an incident.
fn classify_status(status: u16) -> DeliveryError {
    match status {
        401 => DeliveryError::Authentication,
        // 403 means the bot cannot reach this chat any more — it was removed, or
        // the chat forbids it. That is a refused destination, not a second
        // credential problem, so it must not be reported as one.
        403 => DeliveryError::RecipientRejected,
        // 400 is Telegram's catch-all for "this request will never work",
        // including an unknown chat_id or text that is empty.
        400 | 404 | 405 | 415 | 422 => DeliveryError::InvalidRecipient,
        429 => DeliveryError::RateLimited,
        500..=599 => DeliveryError::Unavailable,
        _ => DeliveryError::Malformed,
    }
}

fn classify_transport_error(error: reqwest::Error) -> DeliveryError {
    if error.is_timeout() {
        DeliveryError::Timeout
    } else {
        DeliveryError::Transport
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
) -> Result<String, DeliveryError> {
    if response
        .content_length()
        .is_some_and(|declared| declared > cap_bytes as u64)
    {
        return Err(DeliveryError::ResponseTooLarge { cap_bytes });
    }
    let mut buffer: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(classify_transport_error)? {
        if buffer.len() + chunk.len() > cap_bytes {
            return Err(DeliveryError::ResponseTooLarge { cap_bytes });
        }
        buffer.extend_from_slice(&chunk);
    }
    String::from_utf8(buffer).map_err(|_| DeliveryError::Malformed)
}

/// Pull the message id out of a Telegram response.
///
/// Returned as the bare id because it is the only thing worth keeping: it is what
/// makes a delivery record reconcilable against the provider's own copy. The rest
/// of the response — the echoed chat id, the message text, the sender — is dropped
/// here and never travels further.
///
/// Telegram answers `200 OK` with `{"ok": false, ...}` for some failures, so a 2xx
/// status alone does not mean the message was delivered. `ok: true` is required
/// explicitly; anything else — including a body with no id — is malformed, and the
/// `description` field is never forwarded, because it echoes the request.
fn extract_message_id(body: &str) -> Result<String, DeliveryError> {
    let parsed: Value = serde_json::from_str(body).map_err(|_| DeliveryError::Malformed)?;
    if parsed.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(DeliveryError::Malformed);
    }
    let id = parsed
        .get("result")
        .and_then(|result| result.get("message_id"))
        .and_then(Value::as_i64)
        .ok_or(DeliveryError::Malformed)?;
    Ok(id.to_string())
}

/// Accept only an HTTPS endpoint, or plain HTTP on loopback.
///
/// The base URL is operator configuration, never user input — but a configurable
/// URL is still an SSRF primitive if it can be pointed anywhere, so the scheme and
/// host are constrained here rather than trusted. Loopback is allowed because the
/// test suite runs a mock server on 127.0.0.1.
fn validate_base_url(base_url: &str) -> Result<String, DeliveryError> {
    let parsed = reqwest::Url::parse(base_url).map_err(|_| DeliveryError::NotConfigured)?;
    let host = parsed.host_str().unwrap_or_default();
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]");
    match parsed.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err(DeliveryError::NotConfigured),
    }
    if !loopback && host != "api.telegram.org" {
        return Err(DeliveryError::NotConfigured);
    }
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_or_loopback_endpoints_are_accepted() {
        assert!(validate_base_url(DEFAULT_BASE_URL).is_ok());
        assert!(validate_base_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_base_url("http://api.telegram.org").is_err());
        assert!(validate_base_url("http://169.254.169.254/latest").is_err());
        assert!(validate_base_url("https://evil.example.com").is_err());
        assert!(validate_base_url("file:///etc/passwd").is_err());
        assert!(validate_base_url("not a url").is_err());
    }

    #[test]
    fn statuses_are_not_collapsed_into_one_error() {
        assert_eq!(classify_status(401), DeliveryError::Authentication);
        assert_eq!(classify_status(403), DeliveryError::RecipientRejected);
        assert_eq!(classify_status(429), DeliveryError::RateLimited);
        assert_eq!(classify_status(400), DeliveryError::InvalidRecipient);
        assert_eq!(classify_status(404), DeliveryError::InvalidRecipient);
        assert_eq!(classify_status(503), DeliveryError::Unavailable);
        assert_eq!(classify_status(500), DeliveryError::Unavailable);
        assert_eq!(classify_status(302), DeliveryError::Malformed);
    }

    #[test]
    fn only_transient_failures_are_retryable() {
        assert!(DeliveryError::RateLimited.is_transient());
        assert!(DeliveryError::Unavailable.is_transient());
        for permanent in [
            DeliveryError::Authentication,
            DeliveryError::RecipientRejected,
            DeliveryError::InvalidRecipient,
            DeliveryError::Malformed,
            DeliveryError::Timeout,
            DeliveryError::Transport,
            DeliveryError::ResponseTooLarge { cap_bytes: 1 },
            DeliveryError::NotConfigured,
        ] {
            assert!(
                !permanent.is_transient(),
                "{permanent:?} must not be retried"
            );
        }
    }

    #[test]
    fn a_two_hundred_that_says_not_ok_is_not_a_delivery() {
        // Telegram reports some failures with HTTP 200 and ok:false. Accepting
        // this as delivered would record a message nobody received.
        let refused = serde_json::json!({
            "ok": false,
            "error_code": 400,
            "description": "Bad Request: chat not found",
        })
        .to_string();
        assert_eq!(extract_message_id(&refused), Err(DeliveryError::Malformed));
        assert_eq!(
            extract_message_id("not json"),
            Err(DeliveryError::Malformed)
        );
        assert_eq!(extract_message_id("{}"), Err(DeliveryError::Malformed));
        // ok:true with no id is still not provable delivery.
        assert_eq!(
            extract_message_id(r#"{"ok":true}"#),
            Err(DeliveryError::Malformed)
        );
    }

    #[test]
    fn a_successful_response_yields_the_providers_message_id() {
        let ok = serde_json::json!({
            "ok": true,
            "result": {
                "message_id": 4242,
                "from": {"is_bot": true},
                "chat": {"id": 1},
                "date": 1700000000,
                "text": "Fire Crow security audit",
            },
        })
        .to_string();
        assert_eq!(extract_message_id(&ok).unwrap(), "4242");
    }

    #[test]
    fn the_destination_enters_the_request_in_exactly_one_place() {
        let body = request_body("REPORT");
        let with_chat = json_with_chat("-100123", &body);
        assert_eq!(with_chat["chat_id"], "-100123");
        assert_eq!(with_chat["text"], "REPORT");
        // Plain text only: no parse_mode, so repository-controlled text cannot be
        // interpreted as Telegram markup.
        assert!(with_chat.get("parse_mode").is_none());
        assert!(with_chat.get("entities").is_none());
    }
}
