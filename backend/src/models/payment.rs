use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PaymentRecord {
    pub id: String,
    pub user_id: String,
    pub tenant_id: Option<String>,
    pub amount: f64,
    pub currency: String,
    pub status: String,
    pub payment_provider: String,
    pub transaction_reference: String,
    pub description: Option<String>,
    pub receipt_pdf_url: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePaymentRequest {
    pub tenant_id: Option<String>,
    pub amount: f64,
    pub currency: Option<String>,
    pub payment_provider: Option<String>,
    pub transaction_reference: String,
    pub description: Option<String>,
}
