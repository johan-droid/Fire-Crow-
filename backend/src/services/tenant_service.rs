use crate::error::{AppError, Result};
use crate::models::Tenant;
use chrono::Utc;
use serde::{Deserialize, Serialize};

pub struct TenantService;

impl TenantService {
    pub async fn list(pool: &sqlx::PgPool) -> Result<Vec<Tenant>> {
        sqlx::query_as::<_, Tenant>("SELECT * FROM tenants ORDER BY created_at DESC")
            .fetch_all(pool)
            .await
            .map_err(AppError::Database)
    }

    pub async fn list_for_tenant(pool: &sqlx::PgPool, tenant_id: &str) -> Result<Vec<Tenant>> {
        sqlx::query_as::<_, Tenant>("SELECT * FROM tenants WHERE id = $1 ORDER BY created_at DESC")
            .bind(tenant_id)
            .fetch_all(pool)
            .await
            .map_err(AppError::Database)
    }

    pub async fn create(pool: &sqlx::PgPool, tenant: Tenant) -> Result<Tenant> {
        let usecase = tenant.usecase.unwrap_or_else(|| "security_audit".to_string());
        let industry = tenant.industry_type.unwrap_or_else(|| "technology".to_string());
        let balance = tenant.credit_balance.unwrap_or(0.0);

        sqlx::query_as::<_, Tenant>(
            "INSERT INTO tenants (id, name, slug, domain, plan, usecase, industry_type, credit_balance, billing_email, max_users, max_storage_gb, is_active, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             RETURNING *"
        )
        .bind(tenant.id)
        .bind(tenant.name)
        .bind(tenant.slug)
        .bind(tenant.domain)
        .bind(tenant.plan)
        .bind(&usecase)
        .bind(&industry)
        .bind(balance)
        .bind(tenant.billing_email)
        .bind(tenant.max_users)
        .bind(tenant.max_storage_gb)
        .bind(tenant.is_active)
        .bind(Utc::now().naive_utc())
        .fetch_one(pool)
        .await
        .map_err(AppError::Database)
    }

    pub async fn get_by_id(pool: &sqlx::PgPool, id: &str) -> Result<Option<Tenant>> {
        sqlx::query_as::<_, Tenant>("SELECT * FROM tenants WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(AppError::Database)
    }

    pub async fn get_by_slug(pool: &sqlx::PgPool, slug: &str) -> Result<Option<Tenant>> {
        sqlx::query_as::<_, Tenant>("SELECT * FROM tenants WHERE slug = $1")
            .bind(slug)
            .fetch_optional(pool)
            .await
            .map_err(AppError::Database)
    }

    pub async fn update(pool: &sqlx::PgPool, id: &str, updates: &TenantUpdate) -> Result<Option<Tenant>> {
        sqlx::query(
            "UPDATE tenants SET 
                name = COALESCE($1, name), 
                domain = COALESCE($2, domain), 
                plan = COALESCE($3, plan), 
                usecase = COALESCE($4, usecase),
                industry_type = COALESCE($5, industry_type),
                billing_email = COALESCE($6, billing_email),
                max_users = COALESCE($7, max_users), 
                max_storage_gb = COALESCE($8, max_storage_gb) 
             WHERE id = $9"
        )
        .bind(updates.name.as_ref())
        .bind(updates.domain.as_ref())
        .bind(updates.plan.as_ref())
        .bind(updates.usecase.as_ref())
        .bind(updates.industry_type.as_ref())
        .bind(updates.billing_email.as_ref())
        .bind(updates.max_users)
        .bind(updates.max_storage_gb)
        .bind(id)
        .execute(pool)
        .await
        .map_err(AppError::Database)?;

        Self::get_by_id(pool, id).await
    }

    pub async fn deactivate(pool: &sqlx::PgPool, id: &str) -> Result<bool> {
        let r = sqlx::query("UPDATE tenants SET is_active = false WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(AppError::Database)?;
        Ok(r.rows_affected() > 0)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantUpdate {
    pub name: Option<String>,
    pub domain: Option<String>,
    pub plan: Option<String>,
    pub usecase: Option<String>,
    pub industry_type: Option<String>,
    pub billing_email: Option<String>,
    pub max_users: Option<i32>,
    pub max_storage_gb: Option<i32>,
}
