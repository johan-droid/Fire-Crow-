use crate::config::Settings;
use crate::error::Result;
use crate::models::CreatePaymentRequest;
use crate::services::payment_service::PaymentService;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DodoCheckoutSessionRequest {
    pub amount: f64,
    pub currency: Option<String>,
    pub package_name: String,
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DodoCheckoutSessionResponse {
    pub checkout_url: String,
    pub session_id: String,
    pub amount: f64,
    pub currency: String,
    pub environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DodoWebhookEvent {
    pub event_type: String,
    pub payment_id: String,
    pub user_id: String,
    pub tenant_id: Option<String>,
    pub amount: f64,
    pub currency: Option<String>,
    pub transaction_reference: String,
}

pub struct DodoPaymentService;

/// P1-G (ZT-06-14): the only webhook `event_type` values that may credit
/// balance. `event_type` is attacker-influenceable (the HMAC proves the body
/// came from the configured sender, not that its contents are meaningful),
/// and it was previously stringified straight into the stored description
/// with no check at all. Anything outside this allowlist — refunds, failures,
/// lifecycle noise, or an arbitrary forged string — is rejected before it
/// touches the ledger or the `payment_records` row. Billing is currently
/// disabled, so the set is deliberately minimal; extend it only alongside the
/// matching credit logic. Idempotency is unchanged: legitimate events are
/// still deduped on `transaction_reference` by `PaymentService::record_payment`.
const ALLOWED_WEBHOOK_EVENT_TYPES: &[&str] = &["payment.succeeded", "subscription.active"];

/// Whether an event type may credit balance (see the allowlist above).
fn credits_balance(event_type: &str) -> bool {
    ALLOWED_WEBHOOK_EVENT_TYPES.contains(&event_type)
}

impl DodoPaymentService {
    fn get_base_url(settings: &Settings) -> &'static str {
        if settings.dodo_payments_environment == "live_mode"
            || settings.dodo_payments_environment == "live"
        {
            "https://live.dodopayments.com"
        } else {
            "https://test.dodopayments.com"
        }
    }

    pub async fn create_checkout_session(
        settings: &Settings,
        user_id: &str,
        req: DodoCheckoutSessionRequest,
    ) -> Result<DodoCheckoutSessionResponse> {
        let base_url = Self::get_base_url(settings);
        let session_id = format!("dodo_sess_{}", uuid::Uuid::new_v4());
        let currency = req.currency.unwrap_or_else(|| "USD".to_string());

        // Call Dodo Payments API if API key is present, or fallback to signed checkout URL
        let checkout_url = if !settings.dodo_payments_api_key.is_empty() {
            // security_s_16: `Client::new()` has no timeout, so a stalled peer
            // pins a connection from a small pool for as long as it likes. The
            // unauthenticated GitHub endpoints were the worst case: ~40 stalled
            // callbacks exhaust the pool.
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default();
            let payload = serde_json::json!({
                "product_id": req.package_name,
                "amount": req.amount,
                "currency": currency,
                "customer": { "user_id": user_id },
                "metadata": { "tenant_id": req.tenant_id, "session_id": session_id },
                "return_url": format!("{}/dashboard?payment=success", settings.frontend_url),
            });

            match client
                .post(format!("{}/v1/checkouts", base_url))
                .bearer_auth(&settings.dodo_payments_api_key)
                .json(&payload)
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        if let Ok(json) = resp.json::<serde_json::Value>().await {
                            if let Some(url) = json.get("checkout_url").and_then(|v| v.as_str()) {
                                url.to_string()
                            } else {
                                format!("{}/pay/{}", base_url, session_id)
                            }
                        } else {
                            format!("{}/pay/{}", base_url, session_id)
                        }
                    } else {
                        format!("{}/pay/{}", base_url, session_id)
                    }
                }
                Err(_) => format!("{}/pay/{}", base_url, session_id),
            }
        } else {
            format!("{}/pay/{}", base_url, session_id)
        };

        Ok(DodoCheckoutSessionResponse {
            checkout_url,
            session_id,
            amount: req.amount,
            currency,
            environment: settings.dodo_payments_environment.clone(),
        })
    }

    pub async fn process_webhook(
        pool: &sqlx::PgPool,
        _settings: &Settings,
        event: DodoWebhookEvent,
    ) -> Result<crate::models::PaymentRecord> {
        // P1-G (ZT-06-14): allowlist before anything is recorded. Unknown
        // event types are an error (not a silent 200) so a misconfigured or
        // spoofed sender is visible instead of quietly minting credit.
        if !credits_balance(&event.event_type) {
            // Fixed message: no echo of the attacker-controlled event_type
            // into logs or the response.
            return Err(crate::error::AppError::BadRequest(
                "Unsupported webhook event type".into(),
            ));
        }

        let payment_req = CreatePaymentRequest {
            tenant_id: event.tenant_id,
            amount: event.amount,
            currency: event.currency,
            payment_provider: Some("dodo_payments".to_string()),
            transaction_reference: event.transaction_reference,
            description: Some(format!("Dodo Payments Event: {}", event.event_type)),
        };

        PaymentService::record_payment(pool, &event.user_id, payment_req).await
    }
}

#[cfg(test)]
mod tests {
    use super::{credits_balance, ALLOWED_WEBHOOK_EVENT_TYPES};

    /// P1-G (ZT-06-14): only allowlisted payment-success events credit
    /// balance; everything else (refunds, failures, forged strings) must not.
    #[test]
    fn webhook_event_allowlist_gates_balance_credits() {
        assert!(credits_balance("payment.succeeded"));
        assert!(credits_balance("subscription.active"));
        for rejected in [
            "payment.failed",
            "refund.processed",
            "",
            "Payment.Succeeded",
        ] {
            assert!(!credits_balance(rejected), "{rejected} must not credit");
        }
        // Case-sensitivity is deliberate: the allowlist is exact-match.
        assert!(ALLOWED_WEBHOOK_EVENT_TYPES.len() == 2);
    }
}
