//! CSRF protection middleware.
//!
//! The auth cookies are `SameSite=Strict`, which already blocks the classic
//! cross-site cookie-sending vector. As a second line of defense this middleware
//! rejects state-changing requests whose `Origin` header is present but is not in
//! the configured allowlist. Requests without an `Origin` header (same-origin page,
//! non-browser clients, the worker proxy) pass through unchanged.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

pub async fn csrf_middleware(
    State(state): State<Arc<crate::AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, axum::http::StatusCode> {
    let method = req.method().clone();
    if method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
    {
        return Ok(next.run(req).await);
    }

    if let Some(origin) = req.headers().get("origin").and_then(|v| v.to_str().ok()) {
        let origin = origin.trim_end_matches('/').to_string();
        let allowed = state.settings().cors_origins();
        if !allowed.contains(&origin) {
            return Err(axum::http::StatusCode::FORBIDDEN);
        }
    }

    Ok(next.run(req).await)
}