//! Cloudflare Turnstile Bot Defense Service
//! Verifies client tokens with Cloudflare Turnstile API to protect endpoints against automated attacks.

use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct TurnstileVerifyRequest<'a> {
    pub secret: &'a str,
    pub response: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remoteip: Option<&'a str>,
}

/// Secret-safe `Debug` (Phase 20): the derived impl printed the Turnstile
/// secret and the user's verification token.
impl std::fmt::Debug for TurnstileVerifyRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnstileVerifyRequest")
            .field("secret", &"[REDACTED]")
            .field("response", &"[REDACTED]")
            .field("remoteip", &self.remoteip)
            .finish()
    }
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

    pub async fn verify_token(
        &self,
        token: &str,
        remote_ip: Option<&str>,
    ) -> Result<TurnstileVerifyResponse> {
        if !self.enabled {
            // Explicitly disabled (dev/test default): no challenge is asked
            // of the client and none is verified.
            return Ok(TurnstileVerifyResponse {
                success: true,
                error_codes: vec![],
                challenge_ts: None,
                hostname: None,
                action: None,
                cdata: None,
            });
        }
        // P0-A (ZT-01-23): enabled-but-unconfigured must fail CLOSED. The old
        // `!enabled || secret.is_empty()` stub silently approved every token,
        // so an operator who switched Turnstile on without a secret got a
        // control that verified nothing.
        if self.secret_key.is_empty() {
            return Err(AppError::Internal(
                "Turnstile is enabled but no secret key is configured".into(),
            ));
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
