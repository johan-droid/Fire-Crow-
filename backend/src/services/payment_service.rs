use crate::error::{AppError, Result};
use crate::models::{CreatePaymentRequest, PaymentRecord};
use chrono::Utc;
use uuid::Uuid;

pub struct PaymentService;

impl PaymentService {
    pub async fn record_payment(
        pool: &sqlx::PgPool,
        user_id: &str,
        req: CreatePaymentRequest,
    ) -> Result<PaymentRecord> {
        if !req.amount.is_finite() || req.amount <= 0.0 {
            return Err(AppError::BadRequest(
                "Payment amount must be a positive number".into(),
            ));
        }

        let mut tx = pool.begin().await.map_err(AppError::Database)?;

        // Idempotency: prevent double-crediting if transaction_reference was already recorded
        if !req.transaction_reference.trim().is_empty() {
            let existing: Option<PaymentRecord> = sqlx::query_as(
                "SELECT * FROM payment_records WHERE transaction_reference = $1",
            )
            .bind(&req.transaction_reference)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database)?;

            if let Some(record) = existing {
                tx.commit().await.map_err(AppError::Database)?;
                return Ok(record);
            }
        }

        let id = Uuid::new_v4().to_string();
        let currency = req.currency.unwrap_or_else(|| "USD".to_string());
        let provider = req.payment_provider.unwrap_or_else(|| "stripe".to_string());
        let receipt_url = format!("/api/v1/billing/receipt/{}", id);

        let record = sqlx::query_as::<_, PaymentRecord>(
            "INSERT INTO payment_records (id, user_id, tenant_id, amount, currency, status, payment_provider, transaction_reference, description, receipt_pdf_url, created_at)
             VALUES ($1, $2, $3, $4, $5, 'completed', $6, $7, $8, $9, $10)
             RETURNING *"
        )
        .bind(&id)
        .bind(user_id)
        .bind(&req.tenant_id)
        .bind(req.amount)
        .bind(&currency)
        .bind(&provider)
        .bind(&req.transaction_reference)
        .bind(&req.description)
        .bind(&receipt_url)
        .bind(Utc::now().naive_utc())
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        // Top-up user or tenant credit balance atomically
        if let Some(ref tenant_id) = req.tenant_id {
            sqlx::query("UPDATE tenants SET credit_balance = COALESCE(credit_balance, 0.0) + $1 WHERE id = $2")
                .bind(req.amount)
                .bind(tenant_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;
        } else {
            sqlx::query("UPDATE users SET credit_balance = COALESCE(credit_balance, 0.0) + $1 WHERE id = $2")
                .bind(req.amount)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::Database)?;
        }

        tx.commit().await.map_err(AppError::Database)?;
        Ok(record)
    }

    pub async fn list_user_payments(
        pool: &sqlx::PgPool,
        user_id: &str,
    ) -> Result<Vec<PaymentRecord>> {
        sqlx::query_as::<_, PaymentRecord>(
            "SELECT * FROM payment_records WHERE user_id = $1 ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)
    }

    pub async fn list_tenant_payments(
        pool: &sqlx::PgPool,
        tenant_id: &str,
    ) -> Result<Vec<PaymentRecord>> {
        sqlx::query_as::<_, PaymentRecord>(
            "SELECT * FROM payment_records WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)
    }
}
