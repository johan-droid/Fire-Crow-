use crate::error::{AppError, Result};
use crate::models::Tenant;
use chrono::Utc;

pub struct TenantService;
impl TenantService {
    pub async fn list(pool: &sqlx::PgPool) -> Result<Vec<Tenant>> {
        sqlx::query_as::<_, Tenant>("SELECT * FROM tenants ORDER BY created_at DESC").fetch_all(pool).await.map_err(AppError::Database)
    }
    pub async fn list_for_tenant(pool: &sqlx::PgPool, tenant_id: &str) -> Result<Vec<Tenant>> {
        sqlx::query_as::<_, Tenant>("SELECT * FROM tenants WHERE id = $1 ORDER BY created_at DESC")
            .bind(tenant_id).fetch_all(pool).await.map_err(AppError::Database)
    }
    pub async fn create(pool: &sqlx::PgPool, tenant: Tenant) -> Result<Tenant> {
        sqlx::query_as::<_, Tenant>(
            "INSERT INTO tenants (id, name, slug, domain, plan, max_users, max_storage_gb, is_active, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *"
        )
        .bind(tenant.id).bind(tenant.name).bind(tenant.slug).bind(tenant.domain).bind(tenant.plan).bind(tenant.max_users).bind(tenant.max_storage_gb).bind(tenant.is_active).bind(Utc::now().naive_utc())
        .fetch_one(pool).await.map_err(AppError::Database)
    }
    pub async fn get_by_id(pool: &sqlx::PgPool, id: &str) -> Result<Option<Tenant>> {
        sqlx::query_as::<_, Tenant>("SELECT * FROM tenants WHERE id = $1").bind(id).fetch_optional(pool).await.map_err(AppError::Database)
    }
    pub async fn get_by_slug(pool: &sqlx::PgPool, slug: &str) -> Result<Option<Tenant>> {
        sqlx::query_as::<_, Tenant>("SELECT * FROM tenants WHERE slug = $1").bind(slug).fetch_optional(pool).await.map_err(AppError::Database)
    }
    pub async fn update(pool: &sqlx::PgPool, id: &str, updates: &TenantUpdate) -> Result<Option<Tenant>> {
        sqlx::query(
            "UPDATE tenants SET name=COALESCE($1,name), domain=COALESCE($2,domain), plan=COALESCE($3,plan), max_users=COALESCE($4,max_users), max_storage_gb=COALESCE($5,max_storage_gb) WHERE id=$6"
        )
        .bind(updates.name.as_ref()).bind(updates.domain.as_ref()).bind(updates.plan.as_ref()).bind(updates.max_users).bind(updates.max_storage_gb).bind(id)
        .execute(pool).await.map_err(AppError::Database)?;
        Self::get_by_id(pool, id).await
    }
    pub async fn deactivate(pool: &sqlx::PgPool, id: &str) -> Result<bool> {
        let r = sqlx::query("UPDATE tenants SET is_active=false WHERE id=$1").bind(id).execute(pool).await.map_err(AppError::Database)?;
        Ok(r.rows_affected() > 0)
    }
}
#[derive(Debug, Clone, Default)]
pub struct TenantUpdate {
    pub name: Option<String>, pub domain: Option<String>, pub plan: Option<String>,
    pub max_users: Option<i32>, pub max_storage_gb: Option<i32>,
}
