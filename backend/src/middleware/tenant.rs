use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use crate::middleware::auth::AuthenticatedUser;

#[derive(Debug, Clone, Default)]
pub struct TenantContext {
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub is_admin: bool,
}

pub async fn tenant_middleware(
    mut req: Request,
    next: Next,
) -> Response {
    let tenant_context = extract_tenant_context(&req);
    req.extensions_mut().insert(tenant_context);
    next.run(req).await
}

fn extract_tenant_context(req: &Request) -> TenantContext {
    if let Some(auth_user) = req.extensions().get::<AuthenticatedUser>() {
        return TenantContext {
            tenant_id: Some(auth_user.tenant_id.clone()),
            user_id: Some(auth_user.user_id.clone()),
            is_admin: false,
        };
    }

    TenantContext::default()
}

/// Middleware layer that enforces tenant presence. Use with `axum::middleware::from_fn`.
pub async fn require_tenant(
    mut req: Request,
    next: Next,
) -> Response {
    let tenant_context = extract_tenant_context(&req);
    if tenant_context.tenant_id.is_none() {
        return axum::http::Response::builder()
            .status(axum::http::StatusCode::BAD_REQUEST)
            .body("Tenant ID is required".into())
            .unwrap();
    }
    req.extensions_mut().insert(tenant_context);
    next.run(req).await
}