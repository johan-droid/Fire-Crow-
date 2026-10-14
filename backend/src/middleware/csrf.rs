//! CSRF protection middleware.
//!
//! Auth-cookie `SameSite` is configuration, not a constant: the backend
//! default is `Strict` (same-origin topology), but cross-origin deployments —
//! Vercel frontend + Render backend, see `render.yaml` and
//! `documentation/API_TOPOLOGY.md` — run with `AUTH_COOKIE_SAMESITE=none`
//! (+ `Secure`), which makes browsers send the session cookies on cross-site
//! requests. **SameSite must therefore never be treated as the CSRF control.**
//! This middleware is the actual control for cookie-authenticated
//! state-changing requests (F4):
//!
//! - `GET`/`HEAD`/`OPTIONS` pass through unchanged. They are read-only, and
//!   this covers `/health` and the GET-based OAuth callback.
//! - When an `Origin` header is present it must be in the configured origin
//!   allowlist (`Settings::cors_origins`); anything else is rejected with
//!   403. Browsers attach `Origin` to every cross-site request and to
//!   same-origin `POST`/`PUT`/`PATCH`/`DELETE`, so an allowlisted Origin is
//!   positive evidence the request came from our own frontend.
//! - When `Origin` is absent, a request that carries the auth session
//!   cookies is rejected: a legitimate browser mutation always carries
//!   `Origin`, so a cookie-bearing mutation without one is a non-browser
//!   client forging a browser-shaped request. Cookie-less callers
//!   (bearer-token API clients, workers, probes) pass through — a cross-site
//!   page cannot attach an `Authorization` header, so they are not a CSRF
//!   vector.
//!
//! CORS (middleware/cors.rs) is a separate concern: a permissive CORS policy
//! is not CSRF protection, and a restrictive one is not required for this
//! check to hold.

use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use std::sync::Arc;

/// Whether the request carries the auth session cookies (access or refresh).
///
/// Matches on `name=` boundaries so the access cookie name is never confused
/// with the `{access}_refresh` cookie or an unrelated cookie that merely
/// shares a prefix.
fn carries_auth_cookies(headers: &HeaderMap, cookie_name: &str) -> bool {
    let Some(cookie_header) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let access = format!("{cookie_name}=");
    let refresh = format!("{cookie_name}_refresh=");
    cookie_header
        .split(';')
        .any(|pair| pair.trim().starts_with(&access) || pair.trim().starts_with(&refresh))
}

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
        return Ok(next.run(req).await);
    }

    // No Origin header. Browsers always send Origin on cross-site requests
    // and on same-origin state-changing methods, so a cookie-authenticated
    // mutation without one is not a browser — refuse it. Cookie-less callers
    // (bearer tokens, health probes, server-to-server) are unaffected.
    if carries_auth_cookies(req.headers(), &state.settings().auth_cookie_name) {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }

    Ok(next.run(req).await)
}
