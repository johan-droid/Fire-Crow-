use crate::error::AppError;
use crate::services::auth::validate_token_with_anti_replay;
use axum::http::request::Parts;
use std::sync::Arc;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub username: String,
    pub jti: String,
    pub token_family: String,
    // NEW: tenant_id extracted from JWT claims
    pub tenant_id: String,
}

#[axum::async_trait]
impl axum::extract::FromRequestParts<Arc<crate::AppState>> for AuthenticatedUser {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &Arc<crate::AppState>) -> Result<Self, Self::Rejection> {
        let token_opt = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|auth_header| auth_header.strip_prefix("Bearer ").map(|t| t.to_string()))
            .or_else(|| {
                parts
                    .headers
                    .get(axum::http::header::COOKIE)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|cookie_str| {
                        let cookie_name = &state.settings().auth_cookie_name;
                        cookie_str.split(';').find_map(|pair| {
                            let mut parts = pair.trim().splitn(2, '=');
                            let key = parts.next()?;
                            let val = parts.next()?;
                            if key == cookie_name.as_str() {
                                Some(val.to_string())
                            } else {
                                None
                            }
                        })
                    })
            });

        let token = token_opt.ok_or_else(|| AppError::Unauthorized("Missing authentication token".into()))?;
        
        let claims = validate_token_with_anti_replay(
            &token,
            &state.settings().secret_key,
            state.redis(),
            state.pool(),
        )
        .await
        .map_err(|e| {
            warn!("Token validation failed: {}", e);
            e
        })?;

        Ok(Self {
            user_id: claims.claims.sub,
            username: claims.claims.username,
            jti: claims.claims.jti,
            token_family: claims.claims.token_family,
            tenant_id: claims.claims.tenant_id,
        })
    }
}

/// Authenticated user that is additionally verified to hold administrator
/// privileges (CRIT-04). Admin-ness is derived from the user's role via the
/// `role_permissions` table — the same source of truth used by the IAM service.
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthenticatedUser);

/// Permissions that grant administrative authority when attached to a role.
const ADMIN_PERMISSIONS: &[&str] = &[
    "admin",
    "superadmin",
    "tenant_admin",
    "iam:manage",
    "iam:*",
    "iam:admin",
    "sso:manage",
    "sso:*",
    "sso:admin",
    "pam:approve",
    "pam:manage",
    "pam:*",
    "pam:admin",
    "mfa:admin",
    "mfa:enforce",
    "user:manage",
    "user:admin",
    "billing:manage",
    "audit:admin",
    "tenant:manage",
];

#[axum::async_trait]
impl axum::extract::FromRequestParts<Arc<crate::AppState>> for AdminUser {
    type Rejection = AppError;
    async fn from_request_parts(parts: &mut Parts, state: &Arc<crate::AppState>) -> Result<Self, Self::Rejection> {
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;

        let is_admin: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1
                FROM users u
                JOIN role_permissions rp ON u.role_id = rp.role_id
                WHERE u.id = $1 AND rp.permission = ANY($2::text[])
             )",
        )
        .bind(&user.user_id)
        .bind(ADMIN_PERMISSIONS.to_vec())
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Database)?;

        if !is_admin {
            return Err(AppError::Forbidden("Administrator privileges required".into()));
        }
        Ok(AdminUser(user))
    }
}

