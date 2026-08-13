use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub domain: Option<String>,
    pub plan: String,
    pub usecase: Option<String>,
    pub industry_type: Option<String>,
    pub credit_balance: Option<f64>,
    pub billing_email: Option<String>,
    pub max_users: Option<i32>,
    pub max_storage_gb: Option<i32>,
    pub is_active: bool,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TenantMembership {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub role: String,
    pub joined_at: NaiveDateTime,
}
