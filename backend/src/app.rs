//! Application assembly.
//!
//! The router used to be built inline in `main.rs`, which made it impossible to
//! exercise the real middleware stack, rate limiting, CORS and error
//! sanitization from a test. Everything above the `serve` call now lives here so
//! that `main` and the integration tests build the *same* application.
//!
//! Middleware note: in axum the LAST `.layer()` is the OUTERMOST, so the chains
//! below read bottom-up. `CatchPanicLayer` must sit OUTSIDE `http_audit_logger`,
//! otherwise a panic inside the logger escapes it. See security_p0_1.

use std::sync::Arc;

use axum::middleware::{from_fn, from_fn_with_state};
use axum::Router;
use tracing::{info, warn};

use crate::config::Settings;
use crate::middleware::cors::cors_layer;
use crate::state::AppState;

/// Rejects oversized request bodies before they reach a handler.
///
/// Layered on top of `RequestBodyLimitLayer`, which bounds streamed bodies; this
/// one rejects an oversized declared `Content-Length` immediately.
pub async fn body_size_limit_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, axum::http::StatusCode> {
    let content_type = req
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let body_limit = if content_type.contains("application/json") {
        2 * 1024 * 1024
    } else {
        10 * 1024 * 1024
    };

    let content_length = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());

    if let Some(len) = content_length {
        if len > body_limit {
            return Err(axum::http::StatusCode::PAYLOAD_TOO_LARGE);
        }
    }

    Ok(next.run(req).await)
}

/// The versioned API surface, before any middleware is applied.
pub fn api_router() -> Router<Arc<AppState>> {
    Router::new()
        // /auth rate limits are applied per route group inside
        // routes_auth::router(): credential endpoints keep the strict
        // 5/minute brute-force ceiling, while the read-only session checks
        // (me/session/activities) get their own bucket. Sharing one bucket
        // made a successful login surface as a failure when its immediate
        // follow-up GET /auth/me was throttled with 429.
        .nest("/auth", crate::api::routes_auth::router())
        .nest(
            "/audit",
            crate::api::routes_audit::router()
                .layer(crate::middleware::rate_limit::rate_limiter("10/minute")),
        )
        .nest("/system", crate::api::routes_system::router())
        .nest("/storage", crate::api::routes_storage::router())
        .nest("/chat", crate::api::routes_chat::router())
        .nest("/leaderboard", crate::api::routes_leaderboard::router())
        .nest("/push", crate::api::routes_push::router())
        .nest("/user", crate::api::routes_user::router())
        .nest(
            "/mfa",
            crate::api::routes_mfa::router()
                .layer(crate::middleware::rate_limit::rate_limiter("5/minute")),
        )
        .nest("/sso", crate::api::routes_sso::router())
        .nest("/pam", crate::api::routes_pam::router())
        .nest("/iam", crate::api::routes_iam::router())
        // KNOWN ROUTING INCONSISTENCY (deferred to the API phase): `/tenant` is
        // the only collection mounted at a bare root path. `nest("/tenant",
        // route("/"))` resolves `/api/v1/tenant` and returns 404 for
        // `/api/v1/tenant/`. Nesting the router twice is not a fix - it collides
        // on `GET /tenant/:id`. The correct remedy is a trailing-slash
        // normalisation layer, which is a global routing behaviour change and so
        // does not belong in the schema-reconciliation phase.
        .nest("/tenant", crate::api::routes_tenant::router())
        .nest("/verify", crate::api::routes_verify::router())
        .nest(
            "/payments/dodo",
            crate::api::routes_dodo::router()
                .layer(crate::middleware::rate_limit::rate_limiter("30/minute")),
        )
        .nest("/dashboard", crate::api::routes_dashboard::router())
        .nest("/sse", crate::api::routes_sse::router())
        // GitHub App webhooks: HMAC-verified, so no user session is required
        // or accepted. Rate-limited like the payment webhook: the signature
        // check is cheap, but a public endpoint still gets a ceiling.
        .nest(
            "/github",
            crate::api::routes_github::router()
                .layer(crate::middleware::rate_limit::rate_limiter("30/minute")),
        )
}

/// Build the complete application for `state`.
///
/// `serve_frontend` is false in tests, so the router has no static-file fallback
/// and a request to an unknown path returns 404 instead of `index.html`.
pub fn build_app(state: Arc<AppState>, serve_frontend: bool) -> Router {
    let settings = state.settings().clone();

    let app = Router::new()
        .nest("/api/v1", api_router())
        .merge(crate::api::routes_health::router());

    let app = if serve_frontend {
        let frontend_dir =
            std::env::var("FRONTEND_DIST_DIR").unwrap_or_else(|_| "../frontend/dist".to_string());
        if std::path::Path::new(&frontend_dir).exists() {
            info!("Serving static files from {}", frontend_dir);
            app.fallback_service(tower_http::services::ServeDir::new(&frontend_dir).fallback(
                tower_http::services::ServeFile::new(format!("{}/index.html", frontend_dir)),
            ))
        } else {
            warn!(
                "Static files directory {} not found, static file serving is disabled",
                frontend_dir
            );
            app.route(
                "/",
                axum::routing::get(|| async {
                    axum::Json(serde_json::json!({
                        "status": "ok",
                        "service": "firecrow-backend",
                        "version": env!("CARGO_PKG_VERSION")
                    }))
                }),
            )
        }
    } else {
        app
    };

    // Invariant Middleware Order (Section II.1):
    // In Axum, the last `.layer()` is the OUTERMOST layer on ingress and innermost on response egress.
    // Layers are composed bottom-up so that execution on request arrival follows:
    //   1. request_id_middleware (generates x-request-id)
    //   2. security_headers_middleware (injects CSP, HSTS, frame options)
    //   3. cors_layer (outermost to ensure preflights and rejections 429/403/500 carry CORS headers)
    //   4. cloudflare_middleware (extracts verified CF-Connecting-IP)
    //   5. http_audit_logger (logs request/response metadata using verified IP)
    //   6. error_sanitizer (intercepts internal errors before logger writes)
    //   7. CatchPanicLayer (recovers from unwinds and maps cleanly to 500)
    //   8. body_size_limit_middleware (rejects oversized payloads early)
    //   9. rate_limiter & csrf_middleware (enforces rate limits and Double-Submit Cookie CSRF)

    // 9. rate_limiter & csrf_middleware (innermost: runs closest to route handlers)
    let app = if settings.csrf_enabled {
        app.layer(from_fn_with_state(
            state.clone(),
            crate::middleware::csrf::csrf_middleware,
        ))
    } else {
        app
    };

    let app = if settings.rate_limit_enabled {
        let rate_limiter_conf = tower_governor::governor::GovernorConfigBuilder::default()
            .per_second(20)
            .burst_size(40)
            .key_extractor(crate::middleware::rate_limit::ClientIpKeyExtractor)
            .finish()
            .expect("rate limiter config is valid");
        app.layer(tower_governor::GovernorLayer {
            config: Arc::new(rate_limiter_conf),
        })
    } else {
        info!("Global rate limiting disabled via RATE_LIMIT_ENABLED=false");
        app
    };

    // 8. body_size_limit_middleware & payload bounds
    let app = app
        .layer(from_fn(body_size_limit_middleware))
        .layer(axum::extract::DefaultBodyLimit::max(
            settings.max_json_body_bytes as usize,
        ))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            settings.max_request_body_bytes as usize,
        ))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(30),
        ));

    // 7. CatchPanicLayer: Recover from internal thread unwinds and map to 500
    let app = app.layer(tower_http::catch_panic::CatchPanicLayer::new());

    // 6. error_sanitizer: Map database and internal unwinds to opaque HTTP 500
    let app = app.layer(from_fn_with_state(
        state.clone(),
        crate::middleware::error_sanitizer::error_sanitizer,
    ));

    // 5. http_audit_logger: Log request/response metadata using the verified IP
    let app = app.layer(from_fn(crate::middleware::http_logger::http_audit_logger));

    // 4. cloudflare_middleware: Extract CF-Connecting-IP only if peer matches verified Cloudflare CIDRs
    let app = app.layer(from_fn(
        crate::middleware::cloudflare::cloudflare_middleware,
    ));

    // 3. cors_layer: Guarantee preflights and rejection responses (429, 403, 500) carry valid CORS headers
    let app = app.layer(cors_layer(&settings));

    // 2. security_headers_middleware: Inject CSP, HSTS, X-Content-Type-Options, Frame options
    let app = app.layer(from_fn(
        crate::middleware::security_headers::security_headers_middleware,
    ));

    // 1. request_id_middleware: Generate and trace x-request-id (outermost on ingress)
    app.layer(from_fn(
        crate::middleware::request_id::request_id_middleware,
    ))
    .with_state(state.clone())
}

/// Assemble `AppState` for a running server or a test.
///
/// `pool` is supplied rather than created here so that tests can hand in the
/// per-test database pool produced by `#[sqlx::test]`.
pub async fn build_state(
    settings: Settings,
    pool: sqlx::PgPool,
    redis: Option<Arc<redis::aio::MultiplexedConnection>>,
) -> anyhow::Result<Arc<AppState>> {
    // F1: install the operator-declared proxy trust list used by
    // `resolve_client_ip` (rate limiting, audit logging). `Settings::validate`
    // already rejects malformed values for real startups; parsing again here
    // makes a broken fixture fail loudly instead of silently degrading to
    // "trust nobody".
    crate::middleware::cloudflare::init_trusted_proxies(&settings.trusted_proxy_cidrs)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let crypto =
        crate::services::crypto::crypto_manager(&settings.secret_key, &settings.encryption_key)?;
    let storage = Arc::new(
        crate::services::storage::StorageService::new(
            if settings.r2_endpoint_url.is_empty() {
                None
            } else {
                Some(settings.r2_endpoint_url.clone())
            },
            &settings.r2_access_key_id,
            &settings.r2_secret_access_key,
            &settings.r2_bucket_name,
            format!("{}/workspace/storage", crate::config::WORKSPACE_DIR),
            "auto",
        )
        .await,
    );

    Ok(Arc::new(AppState {
        settings: Arc::new(settings),
        pool,
        storage,
        crypto,
        redis,
        csrf: Arc::new(crate::services::csrf::CsrfStore::new()),
        job_tx: crate::state::global_job_tx(),
    }))
}
