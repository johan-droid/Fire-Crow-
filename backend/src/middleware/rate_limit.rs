use crate::middleware::cloudflare::extract_client_ip;
use crate::services::limiter::parse_rate_limit;
use axum::http::Request;
use governor::middleware::NoOpMiddleware;
use tower_governor::errors::GovernorError;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::KeyExtractor;
use tower_governor::GovernorLayer;
use std::net::IpAddr;

#[derive(Clone, Copy)]
pub struct CloudflareKeyExtractor;

impl KeyExtractor for CloudflareKeyExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        let ip_str = extract_client_ip(req.headers(), None);
        ip_str
            .parse::<IpAddr>()
            .map_err(|_| GovernorError::UnableToExtractKey)
    }
}

pub fn rate_limiter(rate_str: &str) -> GovernorLayer<CloudflareKeyExtractor, NoOpMiddleware> {
    let (count, period) = parse_rate_limit(rate_str);
    let config = GovernorConfigBuilder::default()
        .per_millisecond(period.as_millis() as u64)
        .burst_size(count)
        .key_extractor(CloudflareKeyExtractor)
        .finish()
        .unwrap();
    GovernorLayer {
        config: std::sync::Arc::new(config),
    }
}
