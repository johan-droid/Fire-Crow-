use crate::middleware::cloudflare::{peer_ip_of, resolve_client_ip};
use crate::services::limiter::parse_rate_limit;
use axum::http::Request;
use governor::middleware::NoOpMiddleware;
use tower_governor::errors::GovernorError;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::KeyExtractor;
use tower_governor::GovernorLayer;

/// Derives the rate-limit key from the *verified* client address.
///
/// security_s1: this previously read `CloudflareInfo` from request extensions
/// and fell back to `extract_client_ip(headers, None)`. Because the governor
/// layer was applied outside the Cloudflare middleware, `CloudflareInfo` was
/// never present and the fallback ran — trusting attacker-supplied
/// `CF-Connecting-IP` and handing every request its own fresh bucket.
///
/// The key is now derived directly from the TCP peer, so the result does not
/// depend on middleware ordering at all.
#[derive(Clone, Copy)]
pub struct ClientIpKeyExtractor;

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = String;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        Ok(resolve_client_ip(req.headers(), peer_ip_of(req)))
    }
}

pub fn rate_limiter(rate_str: &str) -> GovernorLayer<ClientIpKeyExtractor, NoOpMiddleware> {
    let (count, period) = parse_rate_limit(rate_str);
    let config = GovernorConfigBuilder::default()
        .per_millisecond(period.as_millis() as u64)
        .burst_size(count)
        .key_extractor(ClientIpKeyExtractor)
        .finish()
        .unwrap();
    GovernorLayer {
        config: std::sync::Arc::new(config),
    }
}
