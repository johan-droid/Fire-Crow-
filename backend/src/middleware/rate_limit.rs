use crate::services::limiter::parse_rate_limit;
use governor::middleware::NoOpMiddleware;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::GovernorLayer;

pub fn rate_limiter(rate_str: &str) -> GovernorLayer<PeerIpKeyExtractor, NoOpMiddleware> {
    let (count, period) = parse_rate_limit(rate_str);
    let config = GovernorConfigBuilder::default()
        .per_millisecond(period.as_millis() as u64)
        .burst_size(count)
        .finish()
        .unwrap();
    GovernorLayer { config: std::sync::Arc::new(config) }
}
