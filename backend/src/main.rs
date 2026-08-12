#![allow(dead_code, unused_variables, unused_imports, deprecated)]

//! Fire Crow Backend — main entry point.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

mod agents;
mod api;
mod config;
mod error;
mod graph;
mod middleware;
mod models;
mod orchestrator;
mod schemas;
mod services;
mod state;
mod utils;
mod workers;

pub use state::AppState;

use config::Settings;
use error::AppError;
use graph::GraphStore;
use middleware::cors::cors_layer;
use services::auth;
use services::csrf::CsrfStore;
use services::storage::StorageService;
use services::telemetry::init_registry;
use workers::WorkerPool;
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,firecrow_backend=info,tower_http=info"))
        )
        .init();
    info!("Fire Crow Backend starting...");

    let settings = Settings::new().map_err(|e| {
        error!("Configuration error: {}", e);
        anyhow::anyhow!(e)
    })?;

    config::ensure_workspace_dirs(&settings)?;

    info!(
        "Environment: {} | Debug: {}",
        if settings.debug { "development" } else { "production" },
        settings.debug
    );

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://firecrow:firecrow@localhost:5432/firecrow".to_string());

    let connect_options = std::str::FromStr::from_str(&database_url)
        .map(|opts: sqlx::postgres::PgConnectOptions| opts.statement_cache_capacity(0))
        .unwrap_or_default();

    let pool = PgPoolOptions::new()
        .max_connections(settings.database_pool_size)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect_lazy_with(connect_options);

    let pool_migrator = pool.clone();
    tokio::spawn(async move {
        info!("Running database migrations...");
        match sqlx::migrate!("./migrations").run(&pool_migrator).await {
            Ok(_) => info!("Database migrations applied successfully"),
            Err(e) => error!("Database migrations error: {}", e),
        }
    });

    // Initialize metrics
    init_registry();

    // Initialize storage
    let r2_endpoint = if settings.r2_endpoint_url.is_empty() { None } else { Some(settings.r2_endpoint_url.clone()) };
    let storage = Arc::new(
        StorageService::new(
            r2_endpoint,
            &settings.r2_access_key_id,
            &settings.r2_secret_access_key,
            &settings.r2_bucket_name,
            format!("{}/workspace/storage", config::WORKSPACE_DIR),
            "auto",
        )
        .await,
    );

    // Initialize crypto
    let crypto = services::crypto::crypto_manager(&settings.secret_key, &settings.encryption_key)?;

    // Initialize Redis
    let redis_conn = if !settings.redis_url.is_empty() {
        match redis::Client::open(settings.redis_url.as_str()) {
            Ok(client) => {
                match client.get_multiplexed_async_connection().await {
                    Ok(conn) => {
                        info!("Redis connected");
                        Some(Arc::new(conn))
                    }
                    Err(e) => {
                        tracing::warn!("Redis connection failed: {} — continuing without cache", e);
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Redis client creation failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Verify graph store (Neon Postgres)
    if let Err(e) = GraphStore::verify_connectivity(&pool).await {
        tracing::warn!("Graph store connectivity check failed: {}", e);
    }

    // Build application state
    let state = Arc::new(AppState {
        settings: Arc::new(settings.clone()),
        pool,
        storage,
        crypto,
        redis: redis_conn,
        csrf: Arc::new(CsrfStore::new()),
    });

    // Build router
    use axum::middleware::{from_fn, from_fn_with_state};
    use crate::middleware::request_id::request_id_middleware;

    let api_v1 = axum::Router::new()
        .nest("/auth", crate::api::routes_auth::router())
        .nest("/audit", crate::api::routes_audit::router())
        .nest("/system", crate::api::routes_system::router())
        .nest("/storage", crate::api::routes_storage::router())
        .nest("/chat", crate::api::routes_chat::router())
        .nest("/leaderboard", crate::api::routes_leaderboard::router())
        .nest("/push", crate::api::routes_push::router())
        .nest("/user", crate::api::routes_user::router())
        .nest("/mfa", crate::api::routes_mfa::router())
        .nest("/sso", crate::api::routes_sso::router())
        .nest("/pam", crate::api::routes_pam::router())
        .nest("/iam", crate::api::routes_iam::router())
        .nest("/tenant", crate::api::routes_tenant::router())
        .nest("/verify", crate::api::routes_verify::router())
        .nest("/sse", crate::api::routes_sse::router());

    let app = axum::Router::new()
        .nest("/api/v1", api_v1)
        .merge(crate::api::routes_health::router())
        .layer(cors_layer(&settings))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            settings.max_request_body_bytes as usize
        ))
        .layer(tower_http::timeout::TimeoutLayer::new(
            std::time::Duration::from_secs(30)
        ))
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(from_fn(crate::middleware::http_logger::http_audit_logger))
        .layer(from_fn(crate::middleware::cloudflare::cloudflare_middleware))
        .layer(from_fn(request_id_middleware))
        .layer(from_fn(body_size_limit_middleware))
        .with_state(state.clone());

    // Global rate limiting keyed by peer IP.
    let mut rate_limiter_conf = tower_governor::governor::GovernorConfigBuilder::default()
        .per_second(20)
        .burst_size(40)
        .key_extractor(tower_governor::key_extractor::PeerIpKeyExtractor);

    let app = app.layer(tower_governor::GovernorLayer {
        config: std::sync::Arc::new(rate_limiter_conf.finish().expect("rate limiter config is valid")),
    });

    // Add CSRF protection when enabled.
    let app = if settings.csrf_enabled {
        app.layer(from_fn_with_state(state.clone(), crate::middleware::csrf::csrf_middleware))
    } else {
        app
    };

    let addr = SocketAddr::new(settings.host.parse()?, settings.port);
    info!("Server listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;

    let worker_pool = WorkerPool::new(state.pool().clone(), settings.clone());
    worker_pool.start(4).await;

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
            info!("Shutdown signal received");
            worker_pool.stop().await;
        })
        .await?;

    info!("Server stopped");
    Ok(())
}

async fn body_size_limit_middleware(
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
