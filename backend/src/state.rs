use std::sync::Arc;
use crate::config::Settings;
use crate::services::crypto::CryptoManager;
use crate::services::csrf::CsrfStore;
use crate::services::storage::StorageService;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub pool: sqlx::PgPool,
    pub storage: Arc<StorageService>,
    pub crypto: Arc<CryptoManager>,
    pub redis: Option<Arc<redis::aio::MultiplexedConnection>>,
    pub csrf: Arc<CsrfStore>,
}

impl AppState {
    pub fn new(
        settings: Arc<Settings>,
        pool: sqlx::PgPool,
        storage: Arc<StorageService>,
        crypto: Arc<CryptoManager>,
        redis: Option<Arc<redis::aio::MultiplexedConnection>>,
        csrf: Arc<CsrfStore>,
    ) -> Self {
        Self { settings, pool, storage, crypto, redis, csrf }
    }

    pub fn settings(&self) -> &Settings { &self.settings }
    pub fn pool(&self) -> &sqlx::PgPool { &self.pool }
    pub fn storage(&self) -> &StorageService { &self.storage }
    pub fn crypto(&self) -> &Arc<CryptoManager> { &self.crypto }
    pub fn redis(&self) -> Option<&redis::aio::MultiplexedConnection> { self.redis.as_deref() }
    pub fn csrf(&self) -> &CsrfStore { &self.csrf }
}
