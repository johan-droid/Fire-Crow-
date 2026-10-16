use crate::config::Settings;
use axum::http::HeaderValue;
use tower_http::cors::CorsLayer as TowerCorsLayer;

pub fn cors_layer(settings: &Settings) -> TowerCorsLayer {
    let origins: Vec<HeaderValue> = settings
        .cors_origins()
        .into_iter()
        .filter_map(|o| HeaderValue::from_str(&o).ok())
        .collect();
    if origins.is_empty() {
        // Fail loud, not silent: with no allowlist every credentialed
        // cross-origin call (and the CSRF check sharing this set) rejects.
        tracing::warn!(
            "CORS allowlist is empty: cross-origin browser calls will be rejected. \
             Set FRONTEND_URL or CORS_ORIGINS (exact origins, no wildcards)."
        );
    }
    TowerCorsLayer::new()
        .allow_origin(origins)
        .allow_credentials(true)
        .max_age(std::time::Duration::from_secs(600))
        .expose_headers([
            axum::http::header::RETRY_AFTER,
            "X-Request-ID".parse().unwrap(),
        ])
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::PATCH,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::COOKIE,
            axum::http::header::ACCEPT,
            axum::http::header::ORIGIN,
            "X-Request-ID".parse().unwrap(),
            "X-CSRF-Token".parse().unwrap(),
        ])
}
