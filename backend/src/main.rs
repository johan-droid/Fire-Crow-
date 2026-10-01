#![allow(dead_code, unused_variables, unused_imports, deprecated)]

//! Fire Crow Backend — main entry point.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

mod agents;
mod api;
mod app;
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
use sqlx::postgres::PgPoolOptions;
use workers::WorkerPool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,firecrow_backend=info,tower_http=info")),
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
        if settings.debug {
            "development"
        } else {
            "production"
        },
        settings.debug
    );

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL environment variable is required"))?;

    let clean_database_url = database_url
        .replace("&channel_binding=require", "")
        .replace("?channel_binding=require&", "?")
        .replace("?channel_binding=require", "");

    // security: a malformed DATABASE_URL previously fell back to
    // PgConnectOptions::default(), which silently pointed the pool at the local
    // default socket instead of failing. That turned a configuration mistake into
    // a confusing runtime error, or worse, a connection to the wrong database.
    // The error deliberately omits the URL so no credential can reach the log.
    let connect_options = std::str::FromStr::from_str(&clean_database_url)
        .map(|opts: sqlx::postgres::PgConnectOptions| opts.statement_cache_capacity(0))
        .map_err(|e| {
            anyhow::anyhow!("DATABASE_URL is not a valid PostgreSQL connection URL: {e}")
        })?;

    let pool = PgPoolOptions::new()
        .max_connections(settings.database_pool_size)
        .min_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .idle_timeout(std::time::Duration::from_secs(600))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect_lazy_with(connect_options);

    // Initialize metrics
    init_registry();

    // Initialize storage
    // Initialize Redis
    let redis_conn = if !settings.redis_url.is_empty() {
        match redis::Client::open(settings.redis_url.as_str()) {
            Ok(client) => match client.get_multiplexed_async_connection().await {
                Ok(conn) => {
                    info!("Redis connected");
                    Some(Arc::new(conn))
                }
                Err(e) => {
                    tracing::warn!("Redis connection failed: {} — continuing without cache", e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Redis client creation failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    // ---- REQUIRED dependency gates -----------------------------------------
    // Startup order is now: configuration -> database reachable -> schema
    // migrated -> HTTP listener. Previously the migration ran in a detached
    // tokio::spawn whose failure was only logged, and the listener was bound
    // before it finished. The process therefore came up "healthy" while serving
    // requests against an incomplete or unmigrated schema, and /health only
    // runs `SELECT 1` so it reported the database as connected regardless.

    // 1. Database must actually be reachable before anything depends on it.
    GraphStore::verify_connectivity(&pool).await.map_err(|e| {
        error!("Database unreachable at startup: {}", e);
        anyhow::anyhow!("cannot reach PostgreSQL using DATABASE_URL: {}", e)
    })?;

    // 2. Schema must be fully migrated. Awaited, not detached, and fatal.
    info!("Running database migrations...");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| {
            error!("Database migrations failed: {}", e);
            anyhow::anyhow!("database migration failed, refusing to start: {}", e)
        })?;
    info!("Database migrations applied successfully");

    let state = crate::app::build_state(settings.clone(), pool, redis_conn).await?;

    let app = crate::app::build_app(state.clone(), true);

    let addr = SocketAddr::new(settings.host.parse()?, settings.port);
    info!("Server listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;

    let worker_pool = WorkerPool::new(state.pool().clone(), settings.clone());
    worker_pool.start(2).await;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutdown signal received");
        worker_pool.stop().await;
    })
    .await?;

    info!("Server stopped");
    Ok(())
}
