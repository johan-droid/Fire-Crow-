use crate::config::Settings;
use crate::services::crypto::CryptoManager;
use crate::services::csrf::CsrfStore;
use crate::services::storage::StorageService;
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Clone, Debug, serde::Serialize)]
pub struct JobBroadcastEvent {
    pub job_id: String,
    pub user_id: String,
    pub status: String,
    pub job: Option<crate::schemas::audit_api::JobResponse>,
    pub phases: Option<Vec<crate::models::PhaseLedgerModel>>,
    pub is_terminal: bool,
}

static GLOBAL_JOB_TX: std::sync::OnceLock<broadcast::Sender<JobBroadcastEvent>> =
    std::sync::OnceLock::new();

pub fn global_job_tx() -> broadcast::Sender<JobBroadcastEvent> {
    GLOBAL_JOB_TX
        .get_or_init(|| {
            let (tx, _) = broadcast::channel(1024);
            tx
        })
        .clone()
}

#[allow(clippy::result_large_err)]
pub fn broadcast_job_event(
    event: JobBroadcastEvent,
) -> Result<usize, broadcast::error::SendError<JobBroadcastEvent>> {
    global_job_tx().send(event)
}

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub pool: sqlx::PgPool,
    pub storage: Arc<StorageService>,
    pub crypto: Arc<CryptoManager>,
    pub redis: Option<Arc<redis::aio::MultiplexedConnection>>,
    pub csrf: Arc<CsrfStore>,
    pub job_tx: broadcast::Sender<JobBroadcastEvent>,
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
        Self {
            settings,
            pool,
            storage,
            crypto,
            redis,
            csrf,
            job_tx: global_job_tx(),
        }
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
    pub fn storage(&self) -> &StorageService {
        &self.storage
    }
    pub fn crypto(&self) -> &Arc<CryptoManager> {
        &self.crypto
    }
    pub fn redis(&self) -> Option<&redis::aio::MultiplexedConnection> {
        self.redis.as_deref()
    }
    pub fn csrf(&self) -> &CsrfStore {
        &self.csrf
    }

    #[allow(clippy::result_large_err)]
    pub fn broadcast_job_update(
        &self,
        event: JobBroadcastEvent,
    ) -> Result<usize, broadcast::error::SendError<JobBroadcastEvent>> {
        self.job_tx.send(event)
    }

    pub fn subscribe_job_updates(&self) -> broadcast::Receiver<JobBroadcastEvent> {
        self.job_tx.subscribe()
    }
}
