use crate::error::AppError;
use crate::services::auth::validate_access_token;
use axum::http::request::Parts;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub username: String,
    pub jti: String,
    pub token_family: String,
    // Tenant id re-read from the database on every request (see below): the JWT
    // claim is only a cache written at mint time and may be stale after a
    // tenant change, deactivation, or membership revocation.
    pub tenant_id: String,
}

#[axum::async_trait]
impl axum::extract::FromRequestParts<Arc<crate::AppState>> for AuthenticatedUser {
    type Rejection = AppError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<crate::AppState>,
    ) -> Result<Self, Self::Rejection> {
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
                            let (key, val) = pair.trim().split_once('=')?;

                            if key == cookie_name.as_str() {
                                Some(val.to_string())
                            } else {
                                None
                            }
                        })
                    })
            });
        // FC-AUTH-02: Query-string token auth (?token=, ?access_token=, ?ticket=) removed.
        // SSE connections use HttpOnly cookies with `withCredentials: true` (EventSource).
        // Query-string JWTs appear in proxy/CDN access logs, leaking long-lived tokens.

        let token = token_opt
            .ok_or_else(|| AppError::Unauthorized("Missing authentication token".into()))?;

        // V1: REST and SSE share this extractor, so both enforce the
        // `Access` purpose. Refresh tokens presented here are rejected.
        let claims = validate_access_token(
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

        // Account lifecycle is re-checked against the database on every request.
        // A signed, unexpired token must not outlive account deactivation, and a
        // stale JWT tenant claim must not survive a tenant change: the `users`
        // row is the source of truth; the claim is only a cache written at mint
        // time (routes_auth.rs mints it from `users.tenant_id`).
        let row: Option<(bool, Option<String>)> =
            sqlx::query_as("SELECT is_active, tenant_id FROM users WHERE id = $1")
                .bind(&claims.claims.sub)
                .fetch_optional(state.pool())
                .await
                .map_err(AppError::Database)?;
        let Some((is_active, db_tenant_id)) = row else {
            return Err(AppError::Unauthorized("Account no longer exists".into()));
        };
        if !is_active {
            return Err(AppError::Unauthorized("Account is not active".into()));
        }

        Ok(Self {
            user_id: claims.claims.sub,
            username: claims.claims.username,
            jti: claims.claims.jti,
            token_family: claims.claims.token_family,
            tenant_id: db_tenant_id.unwrap_or_default(),
        })
    }
}

/// Authenticated user that is additionally verified to hold *platform*
/// administrator privileges (CRIT-04). Admin-ness is derived from the user's
/// role via the `role_permissions` table — the same source of truth used by the
/// IAM service. Tenant-scoped permissions deliberately do NOT qualify.
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthenticatedUser);

/// Permissions that grant *platform* administrative authority when attached to
/// a role.
///
/// FC-AUTHZ-01/03: this list is deliberately disjoint from tenant-scoped
/// authority. Before the split, `tenant_admin` and `tenant:manage` sat in the
/// same flat list as `superadmin`, so a tenant administrator of one tenant was
/// indistinguishable from a platform superadministrator: they could rewrite
/// global SSO/IAM configuration, manage every tenant, and flip the
/// platform-wide MFA-enforcement flag.
///
/// `admin` and `superadmin` are retained as legacy platform strings so
/// provisioned platform roles keep working through the migration. Removal
/// condition: once a `platform:admin` role is provisioned through the
/// bootstrap procedure in `documentation/BOOTSTRAP_ADMIN.md`, the legacy
/// strings drop to a deprecation window and then out of this list.
const PLATFORM_ADMIN_PERMISSIONS: &[&str] = &[
    "admin",
    "superadmin",
    "platform:admin",
    "platform:*",
    "platform:sso",
    "platform:iam",
    "platform:ops",
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
];

/// Permissions that grant *tenant* administrative authority. Holding one of
/// these never implies platform authority; it only qualifies a caller for
/// tenant-scoped administration of the tenant they belong to (see
/// [`authorize_tenant_admin`]).
const TENANT_ADMIN_PERMISSIONS: &[&str] = &["tenant_admin", "tenant:manage"];

#[axum::async_trait]
impl axum::extract::FromRequestParts<Arc<crate::AppState>> for AdminUser {
    type Rejection = AppError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<crate::AppState>,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;

        if !is_platform_admin(state.pool(), &user.user_id).await? {
            return Err(AppError::Forbidden(
                "Administrator privileges required".into(),
            ));
        }
        Ok(AdminUser(user))
    }
}

/// Whether `user_id`'s role carries platform administrative authority.
///
/// Single source of truth shared by the [`AdminUser`] extractor, the dashboard
/// summary (which must not leak platform configuration to non-admins), and
/// tenant administration.
pub async fn is_platform_admin(pool: &PgPool, user_id: &str) -> Result<bool, AppError> {
    permission_query(pool, user_id, PLATFORM_ADMIN_PERMISSIONS).await
}

/// Whether `user_id`'s role carries tenant administrative authority.
async fn is_tenant_admin(pool: &PgPool, user_id: &str) -> Result<bool, AppError> {
    permission_query(pool, user_id, TENANT_ADMIN_PERMISSIONS).await
}

async fn permission_query(
    pool: &PgPool,
    user_id: &str,
    permissions: &[&str],
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1
            FROM users u
            JOIN role_permissions rp ON u.role_id = rp.role_id
            WHERE u.id = $1 AND rp.permission = ANY($2::text[])
         )",
    )
    .bind(user_id)
    .bind(permissions.to_vec())
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)
}

/// Authorize tenant-scoped administration of exactly one tenant.
///
/// Grants access when the caller is a platform administrator, or when the
/// caller is a tenant administrator *of that same tenant* and the tenant is
/// still active. A tenant administrator of Tenant A acting on Tenant B is
/// refused; a tenant administrator whose tenant was deactivated is refused.
/// Tenant context comes from the database-fresh `users.tenant_id` carried by
/// [`AuthenticatedUser`], never from client input.
pub async fn authorize_tenant_admin(
    pool: &PgPool,
    user: &AuthenticatedUser,
    tenant_id: &str,
) -> Result<(), AppError> {
    if is_platform_admin(pool, &user.user_id).await? {
        return Ok(());
    }
    if user.tenant_id.is_empty() || user.tenant_id != tenant_id {
        return Err(AppError::Forbidden("Tenant access denied".into()));
    }
    if !is_tenant_admin(pool, &user.user_id).await? {
        return Err(AppError::Forbidden("Tenant administrator required".into()));
    }
    let active: Option<bool> = sqlx::query_scalar("SELECT is_active FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(AppError::Database)?;
    match active {
        Some(true) => Ok(()),
        Some(false) => Err(AppError::Forbidden("Tenant is not active".into())),
        None => Err(AppError::NotFound("Tenant not found".into())),
    }
}
