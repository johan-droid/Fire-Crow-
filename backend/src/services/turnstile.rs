//! Cloudflare Turnstile Bot Defense Service
//! Verifies client tokens with Cloudflare Turnstile API to protect endpoints against automated attacks.

use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct TurnstileVerifyRequest<'a> {
    secret: &'a str,
    response: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remoteip: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
pub struct TurnstileVerifyResponse {
    pub success: bool,
    #[serde(rename = "error-codes", default)]
    pub error_codes: Vec<String>,
    pub challenge_ts: Option<String>,
    pub hostname: Option<String>,
    pub action: Option<String>,
    pub cdata: Option<String>,
}

pub struct TurnstileService {
    client: reqwest::Client,
    secret_key: String,
    enabled: bool,
}

impl TurnstileService {
    pub fn new(secret_key: String, enabled: bool) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();

        Self {
            client,
            secret_key,
            enabled,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled && !self.secret_key.is_empty()
    }

    /// Verifies a Turnstile response token against Cloudflare's siteverify API.
    pub async fn verify_token(&self, token: &str, remote_ip: Option<&str>) -> Result<TurnstileVerifyResponse> {
        if !self.is_enabled() {
            // Bypass verification when Turnstile is disabled
            return Ok(TurnstileVerifyResponse {
                success: true,
                error_codes: Vec::new(),
                challenge_ts: None,
                hostname: Some("local-bypass".into()),
                action: None,
                cdata: None,
            });
        }

        if token.trim().is_empty() {
            return Err(AppError::BadRequest("Cloudflare Turnstile token missing".into()));
        }

        let params = [
            ("secret", self.secret_key.as_str()),
            ("response", token),
        ];

        let mut req = self.client.post("https://challenges.cloudflare.com/turnstile/v0/siteverify").form(&params);
        if let Some(ip) = remote_ip {
            req = req.query(&[("remoteip", ip)]);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("Cloudflare Turnstile connection failed: {}", e)))?;

        let result: TurnstileVerifyResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed parsing Turnstile response: {}", e)))?;

        if !result.success {
            tracing::warn!("Cloudflare Turnstile verification failed: errors={:?}", result.error_codes);
            return Err(AppError::Unauthorized("Cloudflare Turnstile security verification failed".into()));
        }

        Ok(result)
    }
}
