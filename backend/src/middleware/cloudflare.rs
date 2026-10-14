//! Cloudflare Edge Headers & Client Real IP Middleware
//! Extracts visitor real IP (`CF-Connecting-IP`), Cloudflare Ray ID (`CF-Ray`),
//! visitor geolocation (`CF-IPCountry`), and connection protocol scheme (`CF-Visitor`).
//!
//! Security note (HIGH-07): `CF-*`, `X-Forwarded-For` and `X-Real-IP` headers are
//! ONLY trusted when the request's TCP peer address is itself a Cloudflare edge IP.
//! Otherwise an attacker connecting straight to the backend could forge headers to
//! spoof their IP and evade rate limiting / audit logging.
//!
//! F1: deployments behind an operator-controlled reverse proxy (e.g. Render's
//! routing layer) may additionally declare that proxy's addresses in
//! `TRUSTED_PROXY_CIDRS`. Trust is still never implicit: private, loopback and
//! RFC1918 ranges are treated exactly like any other address — a peer only
//! counts as a proxy when it appears in the explicit list (or in Cloudflare's
//! published edge ranges). Forwarded chains are walked right-to-left, so a
//! client-supplied prefix can never become the verified client address.

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
    ("173.245.48.0", 20),
    ("103.21.244.0", 22),
    ("103.22.200.0", 22),
    ("103.31.4.0", 22),
    ("141.101.64.0", 18),
    ("108.162.192.0", 18),
    ("190.93.240.0", 20),
    ("188.114.96.0", 20),
    ("197.234.240.0", 22),
    ("198.41.128.0", 17),
    ("162.158.0.0", 15),
    ("104.16.0.0", 13),
    ("104.24.0.0", 14),
    ("172.64.0.0", 13),
    ("131.0.72.0", 22),
];

const CF_IPV6_RANGES: &[(&str, u8)] = &[
    ("2400:cb00::", 32),
    ("2606:4700::", 32),
    ("2803:f800::", 32),
    ("2405:b500::", 32),
    ("2405:8100::", 32),
    ("2a06:98c0::", 29),
    ("2c0f:f248::", 32),
];

fn cidr_contains_v4(ip: Ipv4Addr, network: Ipv4Addr, bits: u8) -> bool {
    let net = network;
    if bits == 0 {
        return true;
    }
    let mask = if bits >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - bits)
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn cidr_contains_v6(ip: Ipv6Addr, network: Ipv6Addr, bits: u8) -> bool {
    let net = network;
    let ip_u = u128::from(ip);
    let net_u = u128::from(net);
    let mask = if bits >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - bits)
    };
    (ip_u & mask) == (net_u & mask)
}

pub fn is_cloudflare_peer(peer: IpAddr) -> bool {
    match peer {
        IpAddr::V4(ip) => CF_IPV4_RANGES.iter().any(|(net, bits)| {
            net.parse::<Ipv4Addr>()
                .map(|n| cidr_contains_v4(ip, n, *bits))
                .unwrap_or(false)
        }),
        IpAddr::V6(ip) => CF_IPV6_RANGES.iter().any(|(net, bits)| {
            net.parse::<Ipv6Addr>()
                .map(|n| cidr_contains_v6(ip, n, *bits))
                .unwrap_or(false)
        }),
    }
}

/// Whether `ip` falls inside `network/bits`. A family mismatch is never a match.
pub fn ip_in_cidr(ip: IpAddr, network: IpAddr, bits: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => cidr_contains_v4(ip, net, bits),
        (IpAddr::V6(ip), IpAddr::V6(net)) => cidr_contains_v6(ip, net, bits),
        _ => false,
    }
}

/// Parses the operator-declared trusted proxy list (`TRUSTED_PROXY_CIDRS`).
///
/// Each comma-separated entry is a bare IP address (treated as a single-host
/// network) or a CIDR (`address/bits`). Entries are validated strictly: a
/// malformed address or a non-numeric / out-of-range prefix length is an
/// error, never a silently skipped entry — a skipped entry would silently
/// *drop* a proxy the operator meant to trust, collapsing every user behind it
/// into one rate-limit bucket. An empty (or all-whitespace) value yields an
/// empty list, which is the fail-safe default: no reverse proxy is trusted.
pub fn parse_trusted_proxy_cidrs(raw: &str) -> Result<Vec<(IpAddr, u8)>, String> {
    let mut out = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (addr_str, bits_str) = match entry.split_once('/') {
            Some((addr, bits)) => (addr.trim(), Some(bits.trim())),
            None => (entry, None),
        };
        let addr: IpAddr = addr_str.parse().map_err(|_| {
            format!("TRUSTED_PROXY_CIDRS entry '{entry}' is not a valid IP address or CIDR")
        })?;
        let max_bits: u8 = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match bits_str {
            None => max_bits,
            Some(b) => b.parse::<u8>().map_err(|_| {
                format!("TRUSTED_PROXY_CIDRS entry '{entry}' has a non-numeric prefix length")
            })?,
        };
        if bits > max_bits {
            return Err(format!(
                "TRUSTED_PROXY_CIDRS entry '{entry}' prefix length exceeds /{max_bits} \
                 for this address family"
            ));
        }
        out.push((addr, bits));
    }
    Ok(out)
}

/// Process-wide trusted proxy list, installed once from `Settings`
/// (`app::build_state`). Empty until initialized; an empty list trusts no
/// reverse proxy — every peer is treated as a direct client and its
/// forwarding headers are ignored.
static TRUSTED_PROXY_CIDRS: std::sync::OnceLock<Vec<(IpAddr, u8)>> = std::sync::OnceLock::new();

/// Installs the process-wide trusted proxy list.
///
/// The first successful call wins; later calls re-parse (so a broken value is
/// still reported) but do not replace the installed list.
pub fn init_trusted_proxies(raw: &str) -> Result<(), String> {
    let parsed = parse_trusted_proxy_cidrs(raw)?;
    let _ = TRUSTED_PROXY_CIDRS.set(parsed);
    Ok(())
}

/// The installed trusted proxy list (empty when none was configured).
pub fn trusted_proxies() -> &'static [(IpAddr, u8)] {
    TRUSTED_PROXY_CIDRS.get_or_init(Vec::new).as_slice()
}

fn is_trusted_proxy_ip(ip: IpAddr, trusted: &[(IpAddr, u8)]) -> bool {
    trusted
        .iter()
        .any(|(net, bits)| ip_in_cidr(ip, *net, *bits))
}

/// Ceiling on the number of `X-Forwarded-For` hops walked. Header sizes are
/// already bounded by the HTTP layer; this is a second, explicit ceiling so a
/// pathological chain cannot turn resolution into unbounded work.
const MAX_FORWARDED_HOPS: usize = 64;

/// Walks an `X-Forwarded-For` chain right-to-left and returns the nearest
/// address that is *not* a trusted proxy.
///
/// The rightmost entries were appended by infrastructure we stand behind; the
/// leftmost is whatever the client itself supplied and is never chosen while a
/// less-derived hop exists. A hop that does not parse strictly aborts the walk
/// entirely (returns `None`): an unverifiable chain must not be guessed at,
/// because everything to its left is attacker-controlled. If every hop is a
/// trusted proxy, the furthest one is returned — the closest thing to an
/// origin address the chain can actually prove.
fn forwarded_client_ip(
    xff: &str,
    trusted: &[(IpAddr, u8)],
    peer_is_cloudflare: bool,
) -> Option<IpAddr> {
    let mut outermost: Option<IpAddr> = None;
    for hop in xff.split(',').rev().take(MAX_FORWARDED_HOPS) {
        let hop = hop.trim();
        if hop.is_empty() {
            continue;
        }
        let Ok(addr) = hop.parse::<IpAddr>() else {
            return None;
        };
        let hop_is_proxy =
            (peer_is_cloudflare && is_cloudflare_peer(addr)) || is_trusted_proxy_ip(addr, trusted);
        if !hop_is_proxy {
            return Some(addr);
        }
        outermost = Some(addr);
    }
    outermost
}

/// Resolves the real client IP for logging and rate limiting.
///
/// Trust is decided **here**, not by the caller, so the function cannot be
/// misused: forwarding headers are honoured only when the TCP peer is itself a
/// Cloudflare edge address or an address listed in `TRUSTED_PROXY_CIDRS`. Any
/// other peer is reported as-is, and its `CF-Connecting-IP` / `X-Real-IP` /
/// `X-Forwarded-For` headers are ignored.
///
/// security_s1: previously this read the headers unconditionally, so
/// `rate_limit.rs` (called with `peer_ip: None`) let any client mint a fresh
/// rate-limit bucket per request and forge its IP in the audit log.
///
/// F1: behind a platform proxy (Render et al.) every request otherwise
/// resolves to the proxy's own address, so unrelated clients share one
/// rate-limit bucket. The proxy must be declared in `TRUSTED_PROXY_CIDRS`;
/// private/loopback ranges are never trusted implicitly.
///
/// When the peer address is unknown (`None`) we cannot establish trust, so we
/// return a single shared sentinel rather than an attacker-controlled key.
pub fn resolve_client_ip(headers: &HeaderMap, peer_ip: Option<IpAddr>) -> String {
    resolve_client_ip_with(headers, peer_ip, trusted_proxies())
}

/// The testable core of [`resolve_client_ip`]: identical rules, with the
/// trusted proxy list passed explicitly instead of read from process-wide
/// configuration.
pub fn resolve_client_ip_with(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted: &[(IpAddr, u8)],
) -> String {
    let Some(peer) = peer_ip else {
        // Unverifiable peer: one shared bucket rather than a forgeable key.
        return "unresolved".to_string();
    };

    let peer_is_cloudflare = is_cloudflare_peer(peer);
    let peer_is_trusted_proxy = peer_is_cloudflare || is_trusted_proxy_ip(peer, trusted);

    if !peer_is_trusted_proxy {
        // Direct client (or an unknown peer): forwarding headers are entirely
        // attacker-controlled and are ignored.
        return peer.to_string();
    }

    if peer_is_cloudflare {
        // Cloudflare's own attribute is authoritative for the visitor. It
        // must parse strictly; a malformed value falls through instead of
        // becoming a rate-limit key.
        if let Some(cf_ip) = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(addr) = cf_ip.trim().parse::<IpAddr>() {
                return addr.to_string();
            }
        }
        // X-Real-IP, when present on an edge request, was written by the
        // origin's own proxy. Strict parse, same fail-through.
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(addr) = real_ip.trim().parse::<IpAddr>() {
                return addr.to_string();
            }
        }
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(addr) = forwarded_client_ip(xff, trusted, peer_is_cloudflare) {
            return addr.to_string();
        }
    }

    if !peer_is_cloudflare {
        // A configured (non-Cloudflare) proxy commonly sets X-Real-IP when it
        // does not build an XFF chain. Strict parse; malformed falls through.
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(addr) = real_ip.trim().parse::<IpAddr>() {
                return addr.to_string();
            }
        }
    }

    // Trusted hop with no usable forwarding header: attribute to the proxy
    // itself — one shared bucket, never a forgeable per-client key.
    peer.to_string()
}

/// The TCP peer address of the connection, if the server was built with
/// `into_make_service_with_connect_info`.
pub fn peer_ip_of<B>(req: &Request<B>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Middleware that inspects Cloudflare edge headers and attaches `CloudflareInfo` extension to the request.
pub async fn cloudflare_middleware(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = req.headers();

    let ray_id = headers
        .get("cf-ray")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let country = headers
        .get("cf-ipcountry")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let peer_ip = peer_ip_of(&req);

    let trusted_edge = peer_ip.map(is_cloudflare_peer).unwrap_or(false);
    let is_behind_cf =
        trusted_edge && (ray_id.is_some() || headers.contains_key("cf-connecting-ip"));

    let scheme = if trusted_edge {
        headers
            .get("cf-visitor")
            .and_then(|v| v.to_str().ok())
            .and_then(|json_str| {
                serde_json::from_str::<serde_json::Value>(json_str)
                    .ok()
                    .and_then(|v| {
                        v.get("scheme")
                            .and_then(|s| s.as_str())
                            .map(|s| s.to_string())
                    })
            })
            .or_else(|| {
                headers
                    .get("x-forwarded-proto")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "http".to_string())
    } else {
        peer_ip
            .map(|_| "https".to_string())
            .unwrap_or_else(|| "http".to_string())
    };

    let client_ip = resolve_client_ip(req.headers(), peer_ip);

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
