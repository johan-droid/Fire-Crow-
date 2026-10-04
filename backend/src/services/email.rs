use crate::config::Settings;
use crate::error::{AppError, DeliveryError, Result};
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

pub struct EmailService {
    from_address: String,
    smtp_host: String,
    smtp_port: u16,
    smtp_user: String,
    smtp_password: String,
    /// Whole-call deadline, covering connection, TLS, and the SMTP dialogue.
    timeout: Duration,
    max_attempts: u32,
    /// Set only by [`EmailService::plaintext_loopback`], which refuses any
    /// non-loopback host. STARTTLS is the production path; this exists so the
    /// test suite can drive a real SMTP dialogue without a certificate.
    plaintext: bool,
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
            smtp_host: smtp_host.into(),
            smtp_port,
            smtp_user: smtp_user.into(),
            smtp_password: smtp_password.into(),
            timeout: Duration::from_secs(30),
            max_attempts: 2,
            plaintext: false,
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
            smtp_host: smtp_host.into(),
            smtp_port,
            smtp_user: String::new(),
            smtp_password: String::new(),
            timeout,
            max_attempts: 1,
            plaintext: true,
        })
    }

    /// Whole-call deadline, including retries.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Attempt ceiling; clamped to [`MAX_SEND_ATTEMPTS`].
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts.clamp(1, MAX_SEND_ATTEMPTS);
        self
    }

    /// Build a transport from settings, or `None` when SMTP is not configured.
    ///
    /// An unconfigured server must return `None` so the caller can answer 501
    /// rather than claim a message was queued.
    pub fn from_settings(settings: &Settings) -> Option<Self> {
        if settings.smtp_host.trim().is_empty() || settings.sender_email.trim().is_empty() {
            return None;
        }
        Some(Self {
            from_address: settings.sender_email.clone(),
            smtp_host: settings.smtp_host.clone(),
            smtp_port: settings.smtp_port,
            smtp_user: settings.smtp_user.clone(),
            smtp_password: settings.smtp_password.clone(),
            timeout: Duration::from_secs(30),
            max_attempts: 2,
            plaintext: false,
        })
    }

    fn transport(&self) -> std::result::Result<AsyncSmtpTransport<Tokio1Executor>, DeliveryError> {
        let builder = if self.plaintext {
            // Loopback only, enforced by the constructor.
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.smtp_host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.smtp_host)
                .map_err(|_| DeliveryError::NotConfigured)?
        }
        .port(self.smtp_port)
        // A bound on the whole SMTP exchange: without it a provider that
        // accepts the connection and then stalls holds the request open.
        .timeout(Some(self.timeout));
        let builder = if self.smtp_user.is_empty() {
            builder
        } else {
            builder.credentials(Credentials::new(
                self.smtp_user.clone(),
                self.smtp_password.clone(),
            ))
        };
        Ok(builder.build())
    }

    /// Send a message with a bounded deadline and bounded retries.
    ///
    /// Retries happen only for the two transient classes. The whole sequence is
    /// wrapped in one deadline, so retries cannot extend the call past it.
    async fn send_with_retry(&self, message: Message) -> std::result::Result<(), DeliveryError> {
        let attempts = self.max_attempts.clamp(1, MAX_SEND_ATTEMPTS);
        match tokio::time::timeout(
            self.timeout * attempts,
            self.send_attempts(message, attempts),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(DeliveryError::Timeout),
        }
    }

    async fn send_attempts(
        &self,
        message: Message,
        attempts: u32,
    ) -> std::result::Result<(), DeliveryError> {
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            let transport = self.transport()?;
            let error = match transport.send(message.clone()).await {
                Ok(_) => return Ok(()),
                Err(error) => error,
            };
            let error = classify(&error);
            if !error.is_transient() || attempt >= attempts {
                return Err(error);
            }
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
    ) -> Result<()> {
        validate_recipient(to)?;
        let builder = Message::builder()
            .from(
                self.from_address
                    .parse()
                    .map_err(|e| AppError::EmailError(format!("invalid from address: {e}")))?,
            )
            .to(to
                .parse()
                .map_err(|e| AppError::EmailError(format!("invalid recipient: {e}")))?)
            .subject(subject);

        let message = match html_body {
            Some(html) => builder
                .multipart(MultiPart::alternative_plain_html(
                    body.to_string(),
                    html.to_string(),
                ))
                .map_err(|_| AppError::Delivery(DeliveryError::Malformed))?,
            None => builder
                .body(body.to_string())
                .map_err(|_| AppError::Delivery(DeliveryError::Malformed))?,
        };

        self.send_with_retry(message).await?;
        Ok(())
    }

    /// Send a rendered [`EmailArtifact`].
    ///
    /// Both parts always travel together, so the plain-text version is never
    /// contingent on HTML support in the reader.
    pub async fn send_artifact(
        &self,
        to: &str,
        artifact: &crate::services::email_artifact::EmailArtifact,
    ) -> Result<()> {
        self.send_email(
            to,
            &artifact.subject,
            &artifact.text_body,
            Some(&artifact.html_body),
        )
        .await
    }
}
