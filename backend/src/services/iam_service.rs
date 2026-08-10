use crate::error::{AppError, Result};
use crate::models::{IamPolicy, RolePermission, ServiceAccount};
use chrono::Utc;

pub struct IamService;
impl IamService {
    pub async fn list_policies(pool: &sqlx::PgPool) -> Result<Vec<IamPolicy>> {
        sqlx::query_as::<_, IamPolicy>("SELECT * FROM iam_policies ORDER BY priority DESC, name")
            .fetch_all(pool).await.map_err(AppError::Database)
    }
    pub async fn create_policy(pool: &sqlx::PgPool, policy: IamPolicy) -> Result<IamPolicy> {
        sqlx::query_as::<_, IamPolicy>(
            "INSERT INTO iam_policies (id, name, effect, actions, resources, description, conditions, priority, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *"
        )
        .bind(policy.id).bind(policy.name).bind(policy.effect).bind(policy.actions).bind(policy.resources).bind(policy.description).bind(policy.conditions).bind(policy.priority).bind(Utc::now().naive_utc())
        .fetch_one(pool).await.map_err(AppError::Database)
    }
    pub async fn delete_policy(pool: &sqlx::PgPool, policy_id: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM iam_policies WHERE id = $1").bind(policy_id).execute(pool).await.map_err(AppError::Database)?;
        Ok(r.rows_affected() > 0)
    }
    pub async fn assign_permission(pool: &sqlx::PgPool, role_id: &str, permission: &str, resource_pattern: &str) -> Result<RolePermission> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query_as::<_, RolePermission>("INSERT INTO role_permissions (id, role_id, permission, resource_pattern) VALUES ($1,$2,$3,$4) RETURNING *")
            .bind(id).bind(role_id).bind(permission).bind(resource_pattern)
            .fetch_one(pool).await.map_err(AppError::Database)
    }
    pub async fn remove_permission(pool: &sqlx::PgPool, permission_id: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM role_permissions WHERE id = $1").bind(permission_id).execute(pool).await.map_err(AppError::Database)?;
        Ok(r.rows_affected() > 0)
    }
    pub async fn create_service_account(pool: &sqlx::PgPool, account: ServiceAccount) -> Result<ServiceAccount> {
        sqlx::query_as::<_, ServiceAccount>(
            "INSERT INTO service_accounts (id, name, token_hash, permissions, description, expires_at, created_by, is_active, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *"
        )
        .bind(account.id).bind(account.name).bind(account.token_hash).bind(account.permissions).bind(account.description).bind(account.expires_at).bind(account.created_by).bind(account.is_active).bind(Utc::now().naive_utc())
        .fetch_one(pool).await.map_err(AppError::Database)
    }
    pub async fn revoke_service_account(pool: &sqlx::PgPool, account_id: &str) -> Result<bool> {
        let r = sqlx::query("UPDATE service_accounts SET is_active=false WHERE id=$1").bind(account_id).execute(pool).await.map_err(AppError::Database)?;
        Ok(r.rows_affected() > 0)
    }
    pub async fn audit_log(pool: &sqlx::PgPool, user_id: &str, action: &str, actor_id: &str, details: Option<&str>) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO account_audit_logs (id, user_id, action, details, actor_id, created_at) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(id).bind(user_id).bind(action).bind(details).bind(actor_id).bind(Utc::now().naive_utc())
            .execute(pool).await.map_err(AppError::Database)?;
        Ok(())
    }
}
