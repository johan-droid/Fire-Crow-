use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

#[derive(Debug, Clone, Default)]
pub struct TenantContext {
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub is_admin: bool,
}

pub async fn tenant_middleware(req: Request, next: Next) -> Response {
    next.run(req).await
}
