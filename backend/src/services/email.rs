use crate::error::Result;

pub struct EmailService {
    from_address: String,
    smtp_host: String,
    smtp_port: u16,
    smtp_user: String,
    smtp_password: String,
}

impl EmailService {
    pub fn new(from_address: &str, smtp_host: &str, smtp_port: u16, smtp_user: &str, smtp_password: &str) -> Self {
        Self { from_address: from_address.into(), smtp_host: smtp_host.into(), smtp_port, smtp_user: smtp_user.into(), smtp_password: smtp_password.into() }
    }
    pub async fn send_email(&self, to: &str, subject: &str, _body: &str, _html_body: Option<&str>) -> Result<()> {
        tracing::info!("Email [STUB]: to={}, subject={}", to, subject);
        Ok(())
    }
    pub async fn send_report_email(&self, to: &str, subject: &str, _body: &str, pdf_data: Vec<u8>) -> Result<()> {
        tracing::info!("Email with PDF [STUB]: to={}, subject={}, pdf_size={}", to, subject, pdf_data.len());
        Ok(())
    }
}
