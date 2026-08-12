use crate::error::{AppError, Result};
use crate::models::{PrivilegedAccessGrant, PrivilegedAccessRequest};
use chrono::Utc;

pub struct PamService;
impl PamService {
    pub async fn create_request(pool: &sqlx::PgPool, req: PrivilegedAccessRequest) -> Result<PrivilegedAccessRequest> {
        sqlx::query_as::<_, PrivilegedAccessRequest>(
            "INSERT INTO pam_requests (id, user_id, role_name, permission, reason, requested_duration_minutes, ticket_ref, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8) RETURNING *"
        )
        .bind(req.id).bind(req.user_id).bind(req.role_name).bind(req.permission).bind(req.reason).bind(req.requested_duration_minutes).bind(req.ticket_ref).bind(Utc::now().naive_utc())
        .fetch_one(pool).await.map_err(AppError::Database)
    }
    pub async fn list_requests(pool: &sqlx::PgPool, _tenant_id: Option<&str>) -> Result<Vec<PrivilegedAccessRequest>> {
        sqlx::query_as::<_, PrivilegedAccessRequest>("SELECT * FROM pam_requests ORDER BY created_at DESC")
            .fetch_all(pool).await.map_err(AppError::Database)
    }
    pub async fn list_pending(pool: &sqlx::PgPool) -> Result<Vec<PrivilegedAccessRequest>> {
        sqlx::query_as::<_, PrivilegedAccessRequest>("SELECT * FROM pam_requests WHERE status = 'pending' ORDER BY created_at ASC")
            .fetch_all(pool).await.map_err(AppError::Database)
    }
    pub async fn approve_request(pool: &sqlx::PgPool, request_id: &str, approver_id: &str, duration_minutes: i32) -> Result<PrivilegedAccessGrant> {
        let request = sqlx::query_as::<_, PrivilegedAccessRequest>("SELECT * FROM pam_requests WHERE id = $1")
            .bind(request_id)
            .fetch_optional(pool).await.map_err(AppError::Database)?.ok_or_else(|| AppError::NotFound("Request not found".into()))?;
        if request.status != "pending" { return Err(AppError::BadRequest("Request is not pending".into())); }
        // HIGH-06: a user must never be able to approve their own privilege request.
        if request.user_id == approver_id {
            return Err(AppError::Forbidden("You cannot approve your own privilege request".into()));
        }
        let now = Utc::now().naive_utc();
        let ends_at = now + chrono::Duration::minutes(duration_minutes as i64);
        sqlx::query("UPDATE pam_requests SET status='approved', approver_id=$1, started_at=$2, ends_at=$3 WHERE id=$4")
            .bind(approver_id).bind(now).bind(ends_at).bind(request_id)
            .execute(pool).await.map_err(AppError::Database)?;
        let grant_id = uuid::Uuid::new_v4().to_string();
        sqlx::query_as::<_, PrivilegedAccessGrant>(
            "INSERT INTO pam_grants (id, request_id, granted_by, expires_at, created_at) VALUES ($1,$2,$3,$4,$5) RETURNING *"
        )
        .bind(grant_id).bind(request_id).bind(approver_id).bind(ends_at).bind(now)
        .fetch_one(pool).await.map_err(AppError::Database)
    }
    pub async fn revoke_grant(pool: &sqlx::PgPool, grant_id: &str, actor_id: &str) -> Result<()> {
        let grant = sqlx::query_as::<_, PrivilegedAccessGrant>("SELECT * FROM pam_grants WHERE id = $1 AND revoked = false")
            .bind(grant_id)
            .fetch_optional(pool).await.map_err(AppError::Database)?.ok_or_else(|| AppError::NotFound("Grant not found".into()))?;
        let now = Utc::now().naive_utc();
        sqlx::query("UPDATE pam_grants SET revoked=true, revoked_at=$1, revoked_by=$2 WHERE id=$3")
            .bind(now).bind(actor_id).bind(grant_id)
            .execute(pool).await.map_err(AppError::Database)?;
        let audit_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO pam_audit (id, request_id, action, actor_id, details, created_at) VALUES ($1,$2,'revoke',$3,$4,$5)")
            .bind(audit_id).bind(grant.request_id).bind(actor_id).bind("Revoked by admin").bind(now)
            .execute(pool).await.map_err(AppError::Database)?;
        Ok(())
    }
    pub async fn list_grants(pool: &sqlx::PgPool) -> Result<Vec<PrivilegedAccessGrant>> {
        sqlx::query_as::<_, PrivilegedAccessGrant>("SELECT * FROM pam_grants ORDER BY created_at DESC")
            .fetch_all(pool).await.map_err(AppError::Database)
    }
}
