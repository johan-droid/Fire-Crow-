use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use std::sync::{Arc, RwLock};

lazy_static::lazy_static! {
    pub static ref REGISTRY: Arc<RwLock<Registry>> = Arc::new(RwLock::new(Registry::default()));
    pub static ref HTTP_REQUESTS: Arc<RwLock<Family<Vec<(String, String)>, Gauge>>> =
        Arc::new(RwLock::new(Family::default()));
    pub static ref HTTP_DURATION: Arc<RwLock<Family<Vec<(String, String)>, Histogram>>> =
        Arc::new(RwLock::new(Family::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.001, 2.0, 15))
        })));
    pub static ref ACTIVE_JOBS: Arc<RwLock<Gauge>> =
        Arc::new(RwLock::new(Gauge::default()));
    pub static ref DB_POOL_CONNECTIONS: Arc<RwLock<Gauge>> =
        Arc::new(RwLock::new(Gauge::default()));
}

pub fn init_registry() {
    let _ = &*REGISTRY;
}

pub fn get_metrics() -> String {
    let mut buf = String::new();
    let registry = REGISTRY.read().unwrap();
    encode(&mut buf, &registry).unwrap();
    buf
}
