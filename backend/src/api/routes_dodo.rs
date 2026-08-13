use axum::{Json, Router, extract::{Path, State}, routing::{get, post}};
use std::sync::Arc;
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
    if payload.amount <= 0.0 {
        return Err(AppError::BadRequest("Payment amount must be greater than zero".into()));
    }

    let session = DodoPaymentService::create_checkout_session(&state.settings, &user.user_id, payload).await?;
    Ok(Json(session))
}

pub async fn handle_webhook(
    State(state): State<Arc<crate::AppState>>,
    Json(payload): Json<DodoWebhookEvent>,
) -> Result<Json<serde_json::Value>> {
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
