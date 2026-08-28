use axum::{Json, Router, extract::State, routing::get};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::error::Result;

/// Aggregated dashboard payload — replaces 8 separate round-trips
/// (`/audit/jobs`, `/sso/providers`, `/pam/requests`, `/pam/grants`,
///  `/iam/policies`, `/verify/domains`, `/auth/activities`, `/mfa/status`)
/// with a single authenticated request.  This collapses 8 token
/// validations (each hits Redis/DB) + 8 HTTP handshakes into 1.
#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub jobs: Vec<crate::schemas::audit_api::JobResponse>,
    pub sso_providers: Vec<crate::models::SsoProvider>,
    pub pam_requests: Vec<crate::models::PrivilegedAccessRequest>,
    pub pam_grants: Vec<crate::models::PrivilegedAccessGrant>,
    pub iam_policies: Vec<crate::models::IamPolicy>,
    pub domains: Vec<crate::models::DomainVerification>,
    pub activities: Vec<crate::models::UserActivityEvent>,
    pub mfa_status: serde_json::Value,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

pub fn router() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/summary", get(dashboard_summary))
        // lightweight poll endpoint — only jobs + timestamp, for active-job polling
        .route("/jobs-lite", get(jobs_lite))
}

async fn dashboard_summary(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<DashboardSummary>> {
    // Short-lived Redis cache (5 s) per user — avoids thundering herd when
    // multiple dashboard tabs poll concurrently.
    if let Some(redis) = state.redis() {
        let cache_key = format!("firecrow:dashboard:{}", user.user_id);
        let mut conn = redis.clone();
        let cached: Option<String> = conn.get(&cache_key).await.unwrap_or(None);
        if let Some(json_str) = cached {
            if let Ok(val) = serde_json::from_str::<DashboardSummary>(&json_str) {
                // serve cached copy without touching Postgres
                return Ok(Json(val));
            }
        }
    }

    let pool = state.pool().clone();
    let crypto = state.crypto().clone();
    let user_id = user.user_id.clone();

    // Run all 8 fetches concurrently.  Failures for non-critical sections
    // degrade to empty lists so the dashboard still renders.
    let jobs_fut = fetch_jobs(&pool, &user_id);
    let sso_fut = crate::services::sso_service::SsoService::list_providers(&pool, &crypto);
    let pam_req_fut = crate::services::pam_service::PamService::list_requests(&pool, Some(&user_id));
    let pam_grant_fut = crate::services::pam_service::PamService::list_grants(&pool, Some(&user_id));
    let iam_fut = crate::services::iam_service::IamService::list_policies(&pool);
    let domain_fut = crate::services::domain_verify::DomainVerifyService::list(&pool, &user_id);
    let activities_fut = crate::services::user_activity::list_user_activities(&pool, &user_id, 50);
    let mfa_fut = fetch_mfa_status(&pool, &user_id);

    let (jobs_res, sso_res, pam_req_res, pam_grant_res, iam_res, domain_res, activities_res, mfa_res) =
        tokio::join!(jobs_fut, sso_fut, pam_req_fut, pam_grant_fut, iam_fut, domain_fut, activities_fut, mfa_fut);

    let summary = DashboardSummary {
        jobs: jobs_res.unwrap_or_default(),
        sso_providers: sso_res.unwrap_or_default(),
        pam_requests: pam_req_res.unwrap_or_default(),
        pam_grants: pam_grant_res.unwrap_or_default(),
        iam_policies: iam_res.unwrap_or_default(),
        domains: domain_res.unwrap_or_default(),
        activities: activities_res.unwrap_or_default(),
        mfa_status: mfa_res.unwrap_or(serde_json::json!({"enabled": false, "backup_codes_remaining": 0})),
        generated_at: chrono::Utc::now(),
    };

    // Cache for 5 s in Redis (best-effort, ignore errors)
    if let Some(redis) = state.redis() {
        let cache_key = format!("firecrow:dashboard:{}", user.user_id);
        let mut conn = redis.clone();
        if let Ok(json_str) = serde_json::to_string(&summary) {
            let _: redis::RedisResult<()> = conn.set_ex(cache_key, json_str, 5).await;
        }
    }

    Ok(Json(summary))
}

/// Minimal response for active-job polling — ~90% cheaper than full summary.
/// Frontend should use this inside the 2 s interval loop instead of
/// re-fetching all 8 collections.
#[derive(Debug, Serialize, Deserialize)]
pub struct JobsLiteResponse {
    pub jobs: Vec<crate::schemas::audit_api::JobResponse>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

async fn jobs_lite(
    State(state): State<Arc<crate::AppState>>,
    user: crate::middleware::auth::AuthenticatedUser,
) -> Result<Json<JobsLiteResponse>> {
    let jobs = fetch_jobs(state.pool(), &user.user_id).await.unwrap_or_default();
    Ok(Json(JobsLiteResponse { jobs, generated_at: chrono::Utc::now() }))
}

async fn fetch_jobs(pool: &sqlx::PgPool, user_id: &str) -> Result<Vec<crate::schemas::audit_api::JobResponse>> {
    let jobs: Vec<crate::models::AuditJob> =
        sqlx::query_as::<_, crate::models::AuditJob>("SELECT * FROM audit_jobs WHERE user_id=$1 ORDER BY created_at DESC")
            .bind(user_id)
            .fetch_all(pool)
            .await
            .map_err(crate::error::AppError::Database)?;
    Ok(jobs.into_iter().map(crate::schemas::audit_api::JobResponse::from).collect())
}

async fn fetch_mfa_status(pool: &sqlx::PgPool, user_id: &str) -> Result<serde_json::Value> {
    let db_user: Option<crate::models::User> =
        sqlx::query_as::<_, crate::models::User>("SELECT * FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .map_err(crate::error::AppError::Database)?;
    let enabled = db_user.map(|u| u.mfa_enabled).unwrap_or(false);
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mfa_recovery_codes rc \
         JOIN mfa_configurations cfg ON rc.mfa_config_id = cfg.id \
         WHERE cfg.user_id = $1 AND rc.used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(crate::error::AppError::Database)?;
    Ok(serde_json::json!({"enabled": enabled, "backup_codes_remaining": remaining}))
}
