use axum::{Json, Router, extract::{Path, State}, routing::{get, post}};
use axum::http::HeaderMap;
use axum::body::Bytes;
use std::sync::Arc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use crate::error::{AppError, Result};
use crate::services::dodo_payment_service::{
    DodoCheckoutSessionRequest, DodoCheckoutSessionResponse, DodoPaymentService, DodoWebhookEvent,
};

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/checkout", post(create_checkout))
        .route("/webhook", post(handle_webhook))
        .route("/verify/:payment_id", get(verify_payment))
}

pub async fn create_checkout(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
    Json(payload): Json<DodoCheckoutSessionRequest>,
) -> Result<Json<DodoCheckoutSessionResponse>> {
    // P0-2: The audit engine is currently a stub, returning canned results.
    // Billing is disabled until a real analysis engine is implemented.
    return Err(AppError::Unauthorized("Service temporarily unavailable while audit engine is being upgraded.".into()));
}

pub async fn handle_webhook(
    State(state): State<Arc<crate::AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>> {
    let signature = headers
        .get("dodo-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing signature".into()))?;

    type HmacSha256 = Hmac<Sha256>;
    let secret = state.settings.dodo_payments_webhook_secret.as_bytes();
    if secret.is_empty() {
        return Err(AppError::Internal("Webhook secret not configured".into()));
    }

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| AppError::Internal("Invalid HMAC key".into()))?;
    mac.update(&body);
    let expected_sig = hex::encode(mac.finalize().into_bytes());

    if expected_sig.as_bytes().ct_eq(signature.as_bytes()).unwrap_u8() == 0 {
        return Err(AppError::Unauthorized("Invalid signature".into()));
    }

    let payload: DodoWebhookEvent = serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("Invalid payload".into()))?;
    let record = DodoPaymentService::process_webhook(state.pool(), &state.settings, payload).await?;
    Ok(Json(serde_json::json!({
        "status": "success",
        "payment_id": record.id,
        "amount": record.amount,
        "processed_at": record.created_at
    })))
}

pub async fn verify_payment(
    State(state): State<Arc<crate::AppState>>,
    Path(payment_id): Path<String>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<serde_json::Value>> {
    let record = sqlx::query_as::<_, crate::models::PaymentRecord>(
        "SELECT * FROM payment_records WHERE id = $1 AND user_id = $2"
    )
    .bind(&payment_id)
    .bind(&user.user_id)
    .fetch_optional(state.pool())
    .await
    .map_err(AppError::Database)?;

    if let Some(r) = record {
        Ok(Json(serde_json::json!({
            "status": "verified",
            "payment": r
        })))
    } else {
        Err(AppError::NotFound("Payment transaction not found".into()))
    }
}
