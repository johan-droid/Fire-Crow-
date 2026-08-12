//! Cloudflare Edge Headers & Client Real IP Middleware
//! Extracts visitor real IP (`CF-Connecting-IP`), Cloudflare Ray ID (`CF-Ray`),
//! visitor geolocation (`CF-IPCountry`), and connection protocol scheme (`CF-Visitor`).
//!
//! Security note (HIGH-07): `CF-*`, `X-Forwarded-For` and `X-Real-IP` headers are
//! ONLY trusted when the request's TCP peer address is itself a Cloudflare edge IP.
//! Otherwise an attacker connecting straight to the backend could forge headers to
//! spoof their IP and evade rate limiting / audit logging.

use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CloudflareInfo {
    pub client_ip: String,
    pub ray_id: Option<String>,
    pub country: Option<String>,
    pub scheme: String,
    pub is_behind_cloudflare: bool,
}

impl Default for CloudflareInfo {
    fn default() -> Self {
        Self {
            client_ip: "127.0.0.1".to_string(),
            ray_id: None,
            country: None,
            scheme: "http".to_string(),
            is_behind_cloudflare: false,
        }
    }
}

// Cloudflare edge prefixes (https://www.cloudflare.com/ips/).
const CF_IPV4_RANGES: &[(&str, u8)] = &[
    ("173.245.48.0", 20), ("103.21.244.0", 22), ("103.22.200.0", 22),
    ("103.31.4.0", 22), ("141.101.64.0", 18), ("108.162.192.0", 18),
    ("190.93.240.0", 20), ("188.114.96.0", 20), ("197.234.240.0", 22),
    ("198.41.128.0", 17), ("162.158.0.0", 15), ("104.16.0.0", 13),
    ("104.24.0.0", 14), ("172.64.0.0", 13), ("131.0.72.0", 22),
];

const CF_IPV6_RANGES: &[(&str, u8)] = &[
    ("2400:cb00::", 32), ("2606:4700::", 32), ("2803:f800::", 32),
    ("2405:b500::", 32), ("2405:8100::", 32), ("2a06:98c0::", 29),
    ("2c0f:f248::", 32),
];

fn cidr_contains_v4(ip: Ipv4Addr, network: &str, bits: u8) -> bool {
    let Ok(net) = network.parse::<Ipv4Addr>() else { return false; };
    if bits == 0 { return true; }
    let mask = if bits >= 32 { u32::MAX } else { u32::MAX << (32 - bits) };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn cidr_contains_v6(ip: Ipv6Addr, network: &str, bits: u8) -> bool {
    let Ok(net) = network.parse::<Ipv6Addr>() else { return false; };
    let ip_u = u128::from(ip);
    let net_u = u128::from(net);
    let mask = if bits >= 128 { u128::MAX } else { u128::MAX << (128 - bits) };
    (ip_u & mask) == (net_u & mask)
}

fn is_cloudflare_peer(peer: IpAddr) -> bool {
    match peer {
        IpAddr::V4(ip) => CF_IPV4_RANGES.iter().any(|(net, bits)| cidr_contains_v4(ip, net, *bits)),
        IpAddr::V6(ip) => CF_IPV6_RANGES.iter().any(|(net, bits)| cidr_contains_v6(ip, net, *bits)),
    }
}

/// Helper function to extract real client IP from Cloudflare or standard proxy headers.
/// Only call this when the peer address is a trusted Cloudflare edge.
pub fn extract_client_ip(headers: &HeaderMap, peer_ip: Option<IpAddr>) -> String {
    // 1. Prioritize Cloudflare's direct client IP header
    if let Some(cf_ip) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = cf_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    // 2. Fall back to X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = real_ip.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    // 3. Fall back to X-Forwarded-For (first IP in chain)
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first_ip) = xff.split(',').next() {
            let trimmed = first_ip.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    // 4. Fall back to Socket Peer Address
    if let Some(ip) = peer_ip {
        return ip.to_string();
    }

    "127.0.0.1".to_string()
}

/// Middleware that inspects Cloudflare edge headers and attaches `CloudflareInfo` extension to the request.
pub async fn cloudflare_middleware(
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = req.headers();

    let ray_id = headers
        .get("cf-ray")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let country = headers
        .get("cf-ipcountry")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    // HIGH-07: only trust Cloudflare headers if the connection actually came from
    // a Cloudflare edge. Otherwise fall back to the real peer address.
    let trusted_edge = peer_ip.map(is_cloudflare_peer).unwrap_or(false);
    let is_behind_cf = trusted_edge && (ray_id.is_some() || headers.contains_key("cf-connecting-ip"));

    let scheme = if trusted_edge {
        headers
            .get("cf-visitor")
            .and_then(|v| v.to_str().ok())
            .and_then(|json_str| {
                serde_json::from_str::<serde_json::Value>(json_str)
                    .ok()
                    .and_then(|v| v.get("scheme").and_then(|s| s.as_str()).map(|s| s.to_string()))
            })
            .or_else(|| {
                headers
                    .get("x-forwarded-proto")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "http".to_string())
    } else {
        peer_ip.map(|_| "https".to_string()).unwrap_or_else(|| "http".to_string())
    };

    let client_ip = if trusted_edge {
        extract_client_ip(req.headers(), peer_ip)
    } else {
        peer_ip.map(|p| p.to_string()).unwrap_or_else(|| "127.0.0.1".to_string())
    };

    let cf_info = CloudflareInfo {
        client_ip,
        ray_id: ray_id.clone(),
        country,
        scheme,
        is_behind_cloudflare: is_behind_cf,
    };

    req.extensions_mut().insert(cf_info);

    let mut response = next.run(req).await;

    // Attach CF-Ray response header if request came through Cloudflare
    if let Some(ray) = ray_id {
        if trusted_edge {
            if let Ok(val) = ray.parse() {
                response.headers_mut().insert("cf-ray", val);
            }
        }
    }

    Ok(response)
}