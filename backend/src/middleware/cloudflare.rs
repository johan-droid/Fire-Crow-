//! Cloudflare Edge Headers & Client Real IP Middleware
//! Extracts visitor real IP (`CF-Connecting-IP`), Cloudflare Ray ID (`CF-Ray`),
//! visitor geolocation (`CF-IPCountry`), and connection protocol scheme (`CF-Visitor`).

use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::net::IpAddr;

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

/// Helper function to extract real client IP from Cloudflare or standard proxy headers
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

    let is_behind_cf = ray_id.is_some() || headers.contains_key("cf-connecting-ip");

    let scheme = headers
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
        .unwrap_or_else(|| "http".to_string());

    let client_ip = extract_client_ip(req.headers(), None);

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
        if let Ok(val) = ray.parse() {
            response.headers_mut().insert("cf-ray", val);
        }
    }

    Ok(response)
}
