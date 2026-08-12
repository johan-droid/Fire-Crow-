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
            client, secret_key, enabled,
        }
    }

    pub async fn verify_token(&self, token: &str, remote_ip: Option<&str>) -> Result<TurnstileVerifyResponse> {
        if !self.enabled || self.secret_key.is_empty() {
            return Ok(TurnstileVerifyResponse {
                success: true,
                error_codes: vec![],
                challenge_ts: None,
                hostname: None,
                action: None,
                cdata: None,
            });
        }

        let req = TurnstileVerifyRequest {
            secret: &self.secret_key,
            response: token,
            remoteip: remote_ip,
        };

        let resp = self
            .client
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&req)
            .send()
            .await
            .map_err(|e| AppError::HttpClientError(e.to_string()))?;

        let result: TurnstileVerifyResponse = resp
            .json()
            .await
            .map_err(|e| AppError::HttpClientError(e.to_string()))?;

        if result.success {
            Ok(result)
        } else {
            Err(AppError::ValidationError(format!(
                "Turnstile verification failed: {:?}",
                result.error_codes
            )))
        }
    }
}
