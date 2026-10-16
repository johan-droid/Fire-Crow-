use crate::config::Settings;
use crate::error::{DeliveryError, Result};
use lettre::message::MultiPart;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

/// Retry ceiling regardless of configuration: a delivery must not become a retry
/// storm against the operator's mail provider.
const MAX_SEND_ATTEMPTS: u32 = 3;

/// Reject CRLF in a recipient. An address carrying line breaks is a header
/// injection attempt, and `lettre`'s parser is the only thing between it and an
/// additional header. Validated here so the check cannot be forgotten at a call
/// site.
fn validate_recipient(to: &str) -> std::result::Result<(), DeliveryError> {
    let trimmed = to.trim();
    if trimmed.is_empty() || trimmed.contains(['\r', '\n']) {
        return Err(DeliveryError::InvalidRecipient);
    }
    // Deliberately conservative: one @, a non-empty local part, and a dotted
    // domain. This is a guard against injection and obvious typos, not an RFC
    // 5322 parser.
    let Some((local, domain)) = trimmed.rsplit_once('@') else {
        return Err(DeliveryError::InvalidRecipient);
    };
    if local.is_empty()
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || trimmed.contains(char::is_whitespace)
    {
        return Err(DeliveryError::InvalidRecipient);
    }
    Ok(())
}

/// Classify an SMTP failure.
///
/// lettre already separates transient (4xx) from permanent (5xx) and exposes the
/// code. This maps those onto the classes a caller can act on, so a rejected
/// credential is never reported as congestion.
fn classify(error: &lettre::transport::smtp::Error) -> DeliveryError {
    if error.is_timeout() {
        return DeliveryError::Timeout;
    }
    let Some(code) = error.status() else {
        return if error.is_transient() {
            DeliveryError::Unavailable
        } else {
            DeliveryError::Transport
        };
    };
    let numeric: u16 = code.to_string().parse().unwrap_or(0);
    match numeric {
        // RFC 5321: 5xx is permanent, 4xx is temporary. Specific codes are
        // classified first because they need a different action.
        530 | 534 | 535 | 538 => DeliveryError::Authentication,
        550 | 551 | 553 | 511 => DeliveryError::RecipientRejected,
        421 | 450 | 451 | 452 => DeliveryError::RateLimited,
        400..=499 => DeliveryError::RateLimited,
        500..=599 => DeliveryError::Unavailable,
        _ => DeliveryError::Malformed,
    }
}

/// How bytes leave the process.
///
/// Selected by configuration in [`EmailService::from_settings`], never by a
/// caller: a Resend key selects the HTTP transport, SMTP otherwise. The public
/// surface (`send_artifact`) is identical either way, so the artifact's
/// determinism and the recipient validation cannot drift per provider.
enum Transport {
    Smtp {
        host: String,
        port: u16,
        user: String,
        password: String,
        /// Set only by [`EmailService::plaintext_loopback`], which refuses any
        /// non-loopback host.
        plaintext: bool,
    },
    /// Resend over its JSON HTTP API (`POST /emails`). `base_url` is the
    /// production constant except in tests, which point it at a local mock via
    /// [`EmailService::resend_loopback`].
    Resend {
        api_key: String,
        base_url: String,
        client: reqwest::Client,
    },
}

/// Classify a Resend HTTP transport failure.
///
/// Only a transport-level timeout and outright connection failures are
/// distinguished; everything else is a non-transient transport error so a
/// misbehaving network never becomes a retry storm.
fn classify_reqwest(error: reqwest::Error) -> DeliveryError {
    if error.is_timeout() {
        return DeliveryError::Timeout;
    }
    // Connection refused and everything else at this layer (request build,
    // body read) is reported as a plain transport failure — non-transient, so
    // a misbehaving network never becomes a retry storm. Server-side 5xx and
    // 429 arrive as statuses and are classified by the caller, not here.
    DeliveryError::Transport
}

pub struct EmailService {
    from_address: String,
    /// Whole-call deadline, covering connection, TLS, and the SMTP dialogue.
    timeout: Duration,
    max_attempts: u32,
    transport: Transport,
}

impl EmailService {
    pub fn new(
        from_address: &str,
        smtp_host: &str,
        smtp_port: u16,
        smtp_user: &str,
        smtp_password: &str,
    ) -> Self {
        Self {
            from_address: from_address.into(),
            timeout: Duration::from_secs(30),
            max_attempts: 2,
            transport: Transport::Smtp {
                host: smtp_host.into(),
                port: smtp_port,
                user: smtp_user.into(),
                password: smtp_password.into(),
                plaintext: false,
            },
        }
    }

    /// Build a transport pointed at a plaintext server.
    ///
    /// Refused unless the host is loopback. STARTTLS is the production path; a
    /// plaintext relay is only ever acceptable against a local test server, and
    /// `SMTP_HOST` is operator configuration that must not be able to silently
    /// downgrade delivery to cleartext.
    pub fn plaintext_loopback(
        from_address: &str,
        smtp_host: &str,
        smtp_port: u16,
        timeout: Duration,
    ) -> std::result::Result<Self, DeliveryError> {
        if !matches!(smtp_host, "127.0.0.1" | "localhost" | "::1") {
            return Err(DeliveryError::NotConfigured);
        }
        Ok(Self {
            from_address: from_address.into(),
            timeout,
            max_attempts: 1,
            transport: Transport::Smtp {
                host: smtp_host.into(),
                port: smtp_port,
                user: String::new(),
                password: String::new(),
                plaintext: true,
            },
        })
    }

    /// Build a transport pointed at a local mock of the Resend HTTP API.
    ///
    /// Test-only twin of [`Self::plaintext_loopback`]: refused unless the base
    /// URL is a loopback `http://` origin, so a test can drive the real request
    /// path (headers, JSON body, status classification) against an in-process
    /// server and no caller can quietly re-point production traffic.
    pub fn resend_loopback(
        from_address: &str,
        api_key: &str,
        base_url: &str,
        timeout: Duration,
    ) -> std::result::Result<Self, DeliveryError> {
        let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"];
        if !loopback.iter().any(|prefix| base_url.starts_with(prefix)) {
            return Err(DeliveryError::NotConfigured);
        }
        Ok(Self {
            from_address: from_address.into(),
            timeout,
            max_attempts: 1,
            transport: Transport::Resend {
                api_key: api_key.into(),
                base_url: base_url.trim_end_matches('/').into(),
                client: reqwest::Client::new(),
            },
        })
    }

    /// `with_timeout` sets the whole-call deadline, including retries.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Attempt ceiling; clamped to [`MAX_SEND_ATTEMPTS`].
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts.clamp(1, MAX_SEND_ATTEMPTS);
        self
    }

    /// Build a transport from settings, or `None` when email is not configured.
    ///
    /// An unconfigured server must return `None` so the caller can answer 501
    /// rather than claim a message was queued. FC-OPS-EMAIL-001: a configured
    /// `RESEND_API_KEY` selects the Resend HTTP transport; otherwise SMTP
    /// remains the transport. The sender address is `RESEND_FROM_EMAIL` when
    /// set (Resend), falling back to `SENDER_EMAIL` for both transports.
    pub fn from_settings(settings: &Settings) -> Option<Self> {
        let sender = settings.sender_email.trim();
        if !settings.resend_api_key.trim().is_empty() {
            let from = if settings.resend_from_email.trim().is_empty() {
                sender
            } else {
                settings.resend_from_email.trim()
            };
            if from.is_empty() {
                // A key with no sender address cannot build a message;
                // `Settings::validate` rejects this combination at startup, so
                // reaching it here is defense in depth, not a user path.
                return None;
            }
            return Some(Self {
                from_address: from.to_string(),
                timeout: Duration::from_secs(30),
                max_attempts: 2,
                transport: Transport::Resend {
                    api_key: settings.resend_api_key.clone(),
                    base_url: "https://api.resend.com".into(),
                    client: reqwest::Client::new(),
                },
            });
        }
        if settings.smtp_host.trim().is_empty() || sender.is_empty() {
            return None;
        }
        Some(Self {
            from_address: settings.sender_email.clone(),
            timeout: Duration::from_secs(30),
            max_attempts: 2,
            transport: Transport::Smtp {
                host: settings.smtp_host.clone(),
                port: settings.smtp_port,
                user: settings.smtp_user.clone(),
                password: settings.smtp_password.clone(),
                plaintext: false,
            },
        })
    }

    fn smtp_transport(
        &self,
    ) -> std::result::Result<AsyncSmtpTransport<Tokio1Executor>, DeliveryError> {
        let Transport::Smtp {
            host,
            port,
            user,
            password,
            plaintext,
        } = &self.transport
        else {
            return Err(DeliveryError::Transport);
        };
        let builder = if *plaintext {
            // Loopback only, enforced by the constructor.
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|_| DeliveryError::NotConfigured)?
        }
        .port(*port)
        // A bound on the whole SMTP exchange: without it a provider that
        // accepts the connection and then stalls holds the request open.
        .timeout(Some(self.timeout));
        let builder = if user.is_empty() {
            builder
        } else {
            builder.credentials(Credentials::new(user.clone(), password.clone()))
        };
        Ok(builder.build())
    }

    /// Send with a bounded deadline and bounded retries.
    ///
    /// Retries happen only for the two transient classes (`RateLimited`,
    /// `Unavailable`); a timeout is never retried because the provider may
    /// already have accepted the message. The whole sequence is wrapped in one
    /// deadline, so retries cannot extend the call past it.
    async fn send_with_retry(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        html_body: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> std::result::Result<Option<String>, DeliveryError> {
        let attempts = self.max_attempts.clamp(1, MAX_SEND_ATTEMPTS);
        match tokio::time::timeout(
            self.timeout * attempts,
            self.send_attempts(to, subject, body, html_body, idempotency_key, attempts),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(DeliveryError::Timeout),
        }
    }

    async fn send_attempts(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        html_body: Option<&str>,
        idempotency_key: Option<&str>,
        attempts: u32,
    ) -> std::result::Result<Option<String>, DeliveryError> {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let error = match &self.transport {
                Transport::Smtp { .. } => {
                    let message = self.build_message(to, subject, body, html_body)?;
                    let transport = self.smtp_transport()?;
                    match transport.send(message).await {
                        Ok(_) => return Ok(None),
                        Err(error) => classify(&error),
                    }
                }
                Transport::Resend {
                    api_key,
                    base_url,
                    client,
                } => {
                    match self
                        .resend_send(
                            client,
                            base_url,
                            api_key,
                            to,
                            subject,
                            body,
                            html_body,
                            idempotency_key,
                        )
                        .await
                    {
                        Ok(message_id) => return Ok(message_id),
                        Err(error) => error,
                    }
                }
            };
            if !error.is_transient() || attempt >= attempts {
                return Err(error);
            }
        }
    }

    /// One Resend HTTP attempt. `POST {base_url}/emails`.
    ///
    /// FC-OPS-EMAIL-001 semantics: a 2xx is *provider acceptance*, not inbox
    /// delivery — the delivery state machine upstream records exactly that and
    /// nothing stronger. The deterministic `Idempotency-Key` (derived from the
    /// artifact's execution id and attempt, never from request input) makes the
    /// transient retries above safe against provider-side double-sends. No
    /// response body is read or logged: only the status code leaves this
    /// function's logs, and never the key.
    #[allow(clippy::too_many_arguments)]
    async fn resend_send(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        api_key: &str,
        to: &str,
        subject: &str,
        body: &str,
        html_body: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> std::result::Result<Option<String>, DeliveryError> {
        let mut request = client
            .post(format!("{base_url}/emails"))
            .header("Authorization", format!("Bearer {api_key}"))
            .json(&serde_json::json!({
                "from": self.from_address,
                "to": [to],
                "subject": subject,
                "text": body,
                "html": html_body,
            }));
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        let response = request.send().await.map_err(classify_reqwest)?;
        let status = response.status();
        if status.is_success() {
            // Resend's success body is `{"id": "<message-id>"}`. We keep only the
            // id (an opaque reference) for the delivery record; the body itself
            // can echo addresses and must never be logged.
            let message_id = response
                .json::<serde_json::Value>()
                .await
                .ok()
                .and_then(|value| {
                    value
                        .get("id")
                        .and_then(|id| id.as_str().map(|id| id.to_string()))
                });
            return Ok(message_id);
        }
        // Status code only — the body can echo addresses and must stay out of
        // logs, and the caller gets fixed Fire Crow text, never provider text.
        tracing::warn!(status = %status, "resend rejected the email request");
        Err(match status.as_u16() {
            401 | 403 => DeliveryError::Authentication,
            429 => DeliveryError::RateLimited,
            408 => DeliveryError::Timeout,
            400 | 422 => DeliveryError::Malformed,
            500..=599 => DeliveryError::Unavailable,
            _ => DeliveryError::Transport,
        })
    }

    /// Build the SMTP `Message` for one attempt.
    fn build_message(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        html_body: Option<&str>,
    ) -> std::result::Result<Message, DeliveryError> {
        let builder = Message::builder()
            .from(
                self.from_address
                    .parse()
                    .map_err(|_| DeliveryError::Malformed)?,
            )
            .to(to.parse().map_err(|_| DeliveryError::Malformed)?)
            .subject(subject);
        match html_body {
            Some(html) => builder
                .multipart(MultiPart::alternative_plain_html(
                    body.to_string(),
                    html.to_string(),
                ))
                .map_err(|_| DeliveryError::Malformed),
            None => builder
                .body(body.to_string())
                .map_err(|_| DeliveryError::Malformed),
        }
    }

    /// Send a plain-text (optionally HTML) message.
    ///
    /// Private: the only legitimate email is a rendered [`EmailArtifact`] via
    /// [`Self::send_artifact`]. A public raw-send would let a future caller
    /// bypass the artifact's determinism, validation, and error classification.
    async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        html_body: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<Option<String>> {
        validate_recipient(to)?;
        Ok(self
            .send_with_retry(to, subject, body, html_body, idempotency_key)
            .await?)
    }

    /// Send a rendered [`EmailArtifact`].
    ///
    /// Both parts always travel together, so the plain-text version is never
    /// contingent on HTML support in the reader. Returns the provider's message
    /// id when the channel supplies one (Resend), `None` otherwise (SMTP).
    pub async fn send_artifact(
        &self,
        to: &str,
        artifact: &crate::services::email_artifact::EmailArtifact,
    ) -> Result<Option<String>> {
        // Deterministic, server-derived idempotency key: the artifact's
        // execution identity, never request input. Resend dedupes provider
        // retries on this key; the delivery state machine remains the
        // authoritative idempotency for the application.
        let idempotency_key = format!(
            "firecrow-email-{}-{}",
            artifact.execution_id, artifact.attempt_number
        );
        self.send_email(
            to,
            &artifact.subject,
            &artifact.text_body,
            Some(&artifact.html_body),
            Some(&idempotency_key),
        )
        .await
    }
}
