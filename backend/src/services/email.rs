use crate::config::Settings;
use crate::error::{AppError, Result};
use lettre::message::{header::ContentType, Attachment, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

pub struct EmailService {
    from_address: String,
    smtp_host: String,
    smtp_port: u16,
    smtp_user: String,
    smtp_password: String,
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
        }
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
        })
    }

    fn transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.smtp_host)
            .map_err(|e| AppError::EmailError(format!("invalid SMTP host: {e}")))?
            .port(self.smtp_port);
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

    /// Send a plain-text (optionally HTML) message.
    pub async fn send_email(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        html_body: Option<&str>,
    ) -> Result<()> {
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
                .map_err(|e| AppError::EmailError(e.to_string()))?,
            None => builder
                .body(body.to_string())
                .map_err(|e| AppError::EmailError(e.to_string()))?,
        };

        self.transport()?
            .send(message)
            .await
            .map_err(|e| AppError::EmailError(e.to_string()))?;
        Ok(())
    }

    /// Send the report markdown as an attachment.
    pub async fn send_report_email(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        report_markdown: &str,
    ) -> Result<()> {
        let content_type = ContentType::parse("text/markdown")
            .map_err(|e| AppError::EmailError(format!("invalid content type: {e}")))?;
        let attachment = Attachment::new("firecrow-report.md".to_string())
            .body(report_markdown.to_string(), content_type);

        let message = Message::builder()
            .from(
                self.from_address
                    .parse()
                    .map_err(|e| AppError::EmailError(format!("invalid from address: {e}")))?,
            )
            .to(to
                .parse()
                .map_err(|e| AppError::EmailError(format!("invalid recipient: {e}")))?)
            .subject(subject)
            .multipart(
                MultiPart::mixed()
                    .singlepart(SinglePart::plain(body.to_string()))
                    .singlepart(attachment),
            )
            .map_err(|e| AppError::EmailError(e.to_string()))?;

        self.transport()?
            .send(message)
            .await
            .map_err(|e| AppError::EmailError(e.to_string()))?;
        Ok(())
    }
}
