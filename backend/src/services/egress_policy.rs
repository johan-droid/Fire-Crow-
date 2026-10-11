//! OSV scanner egress policy and destination validation (Phase C / H2).
//!
//! OSV-Scanner is the sole scanner granted network access ([`NetworkMode::Bridge`]),
//! which it requires to query the live Open Source Vulnerabilities database.
//! This module defines the strict egress allowlist and validation logic to block
//! access to cloud metadata services, RFC 1918 private networks, loopback,
//! and arbitrary non-OSV external destinations.
//!
//! Two layers, tested separately (see `tests/osv_egress_policy.rs` vs
//! `tests/osv_egress_enforcement.rs`):
//!
//! 1. **Policy functions** ([`evaluate_ip`], [`evaluate_egress_target`]) are the
//!    machine-readable contract a filtering proxy must implement: allowlisted
//!    OSV domains on 443/53 only, everything else blocked — including
//!    alternative IP spellings, smuggled userinfo/ports, and redirect targets.
//! 2. **Runtime enforcement** is the mandatory filtering proxy itself:
//!    [`resolve_osv_egress_proxy`] fails closed when `OSV_EGRESS_PROXY` is
//!    missing or malformed, and the dependency-scan entry point refuses to run
//!    without it. The Docker socket proxy constrains *Docker API* calls, never
//!    container *network* traffic — it must not be mistaken for egress control.

use crate::error::AppError;
use std::net::{IpAddr, Ipv4Addr};

/// Allowlisted domains for OSV vulnerability lookups.
pub const OSV_APPROVED_DOMAINS: &[&str] = &["api.osv.dev", "osv.dev"];

/// Policy decision for an outbound network target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressDecision {
    Allow,
    Block(&'static str),
}

/// Evaluates whether an IP address is permitted under the strict egress policy.
pub fn evaluate_ip(ip: IpAddr) -> EgressDecision {
    match ip {
        IpAddr::V4(ipv4) => {
            // Loopback (127.0.0.0/8)
            if ipv4.is_loopback() {
                return EgressDecision::Block("loopback blocked");
            }
            // Cloud metadata / Link-local (169.254.0.0/16)
            if ipv4.is_link_local() || ipv4 == Ipv4Addr::new(169, 254, 169, 254) {
                return EgressDecision::Block("cloud metadata and link-local blocked");
            }
            // RFC 1918 Private networks
            if ipv4.is_private() {
                return EgressDecision::Block("RFC1918 private network blocked");
            }
            // Broadcast & Unspecified
            if ipv4.is_broadcast() || ipv4.is_unspecified() {
                return EgressDecision::Block("broadcast/unspecified blocked");
            }
            // Documentation / benchmark / reserved
            let octets = ipv4.octets();
            // 0.0.0.0/8 "software scope": never a real remote peer.
            if octets[0] == 0 {
                return EgressDecision::Block("software-scope address blocked");
            }
            // TEST-NET-1/2/3 documentation ranges: reserved, never OSV infra.
            if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            {
                return EgressDecision::Block("documentation range blocked");
            }
            if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
                // 100.64.0.0/10 Carrier-grade NAT
                return EgressDecision::Block("carrier-grade NAT blocked");
            }
            if octets[0] >= 224 {
                return EgressDecision::Block("multicast/reserved blocked");
            }
            EgressDecision::Allow
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() {
                return EgressDecision::Block("IPv6 loopback blocked");
            }
            if ipv6.is_unspecified() {
                return EgressDecision::Block("IPv6 unspecified blocked");
            }
            // Check for IPv4-mapped IPv6 addresses
            if let Some(mapped_v4) = ipv6.to_ipv4_mapped() {
                return evaluate_ip(IpAddr::V4(mapped_v4));
            }
            // Link-local (fe80::/10): same metadata/neighbor role as IPv4
            // link-local; `to_ipv4_mapped` does not cover it.
            if ipv6.is_unicast_link_local() {
                return EgressDecision::Block("IPv6 link-local blocked");
            }
            // Unique-local (fc00::/7): the IPv6 equivalent of RFC 1918.
            if ipv6.is_unique_local() {
                return EgressDecision::Block("IPv6 unique-local blocked");
            }
            // Multicast (ff00::/8) and documentation (2001:db8::/32) ranges
            // are never legitimate OSV destinations.
            if ipv6.is_multicast() || (ipv6.segments()[0] == 0x2001 && ipv6.segments()[1] == 0x0db8)
            {
                return EgressDecision::Block("IPv6 multicast/documentation blocked");
            }
            EgressDecision::Allow
        }
    }
}

/// Parse IPv4 spellings Rust's `FromStr` rejects but kernels and resolvers
/// historically accept: full-range decimal (`2130706433`), full hex
/// (`0x7f000001`), and dotted parts in hex (`0x7f.0.0.1`) or octal
/// (`0177.0.0.1`). Without this, `127.0.0.1` written as `2130706433`
/// would fall through to the hostname path and be blocked only by luck of
/// the allowlist; canonicalizing first gives the precise block reason and
/// keeps the policy correct even if the allowlist ever widens.
fn parse_alt_ipv4(host: &str) -> Option<Ipv4Addr> {
    // Integer forms (`0x7f000001`, `2130706433`) only exist without dots;
    // dotted input always takes the dotted-quad path below.
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            if hex.is_empty() || hex.len() > 8 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            return u32::from_str_radix(hex, 16).ok().map(Ipv4Addr::from);
        }
        if !host.is_empty() && host.chars().all(|c| c.is_ascii_digit()) {
            return host.parse::<u32>().ok().map(Ipv4Addr::from);
        }
        return None;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return None;
        }
        let value: u32 =
            if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return None;
                }
                u32::from_str_radix(hex, 16).ok()?
            } else if part.len() > 1 && part.starts_with('0') {
                if !part.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                u32::from_str_radix(part, 8).ok()?
            } else {
                if !part.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                part.parse::<u32>().ok()?
            };
        if value > 255 {
            return None;
        }
        out[i] = value as u8;
    }
    Some(Ipv4Addr::new(out[0], out[1], out[2], out[3]))
}

/// Evaluates whether a destination host (hostname or IP string) and port are permitted.
pub fn evaluate_egress_target(host: &str, port: u16) -> EgressDecision {
    // Only HTTPS (443) and DNS (53) are valid ports for OSV database queries
    if port != 443 && port != 53 {
        return EgressDecision::Block("non-standard port blocked; only 443 and 53 permitted");
    }

    let host_trimmed = host.trim().to_lowercase();
    // A single trailing dot is a semantically identical FQDN spelling
    // (`api.osv.dev.`); normalize it so allowlist and blocklist agree.
    let host_trimmed = host_trimmed.strip_suffix('.').unwrap_or(&host_trimmed);

    // Check if the host is directly an IP literal
    if let Ok(ip) = host_trimmed.parse::<IpAddr>() {
        let ip_dec = evaluate_ip(ip);
        if ip_dec != EgressDecision::Allow {
            return ip_dec;
        }
        // Direct IP connects to arbitrary external IPs without approved hostname are blocked
        return EgressDecision::Block(
            "direct IP connect not permitted; must match approved OSV domain",
        );
    }
    // Alternative IP spellings (hex/octal/decimal) canonicalize to an address
    // first, so `0x7f.0.0.1` is judged as 127.0.0.1 rather than as a hostname.
    if let Some(alt) = parse_alt_ipv4(host_trimmed) {
        let ip_dec = evaluate_ip(IpAddr::V4(alt));
        if ip_dec != EgressDecision::Allow {
            return ip_dec;
        }
        return EgressDecision::Block(
            "direct IP connect not permitted; must match approved OSV domain",
        );
    }

    // Smuggled authority components: `user@host`, `host:port`, `host/path`,
    // or bracketed literals must never reach the allowlist comparison, where
    // a naive suffix match could be fooled (`evil.com@api.osv.dev` style).
    if host_trimmed.contains(['@', '/', ':', '[', ']'])
        || host_trimmed
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return EgressDecision::Block("malformed host: authority smuggling blocked");
    }

    // Hostname check against allowlist
    let is_approved = OSV_APPROVED_DOMAINS
        .iter()
        .any(|&domain| host_trimmed == domain || host_trimmed.ends_with(&format!(".{domain}")));

    if is_approved {
        EgressDecision::Allow
    } else {
        EgressDecision::Block("domain not in approved OSV allowlist")
    }
}

/// Validate the operator-configured filtering proxy URL (`OSV_EGRESS_PROXY`).
///
/// Shape-only on purpose: the proxy host is operator infrastructure (a
/// sidecar on an internal network is legitimate), so private addresses are
/// *not* blocked here. What is enforced: `http`/`https` scheme only, a real
/// host, a sane port, no credentials (they would land in execution records
/// and `-e` argv — use proxy IP allowlisting instead), and no control
/// characters or paths that could smuggle a second destination. Returns the
/// normalized `scheme://host[:port]` form.
pub fn validate_osv_proxy_url(raw: &str) -> Result<String, &'static str> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("proxy URL is empty");
    }
    if value.len() > 512 {
        return Err("proxy URL exceeds 512 characters");
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("proxy URL contains control characters or whitespace");
    }
    let parsed = url::Url::parse(value).map_err(|_| "proxy URL is unparseable")?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err("proxy scheme must be http or https"),
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("proxy URL must not embed credentials");
    }
    let host = parsed.host_str().ok_or("proxy URL has no host")?;
    if host.is_empty() {
        return Err("proxy URL has no host");
    }
    if let Some(port) = parsed.port() {
        if port == 0 {
            return Err("proxy port is invalid");
        }
    }
    // A CONNECT proxy address has no path, query, or fragment. Their
    // presence signals a misconfigured or smuggled value; normalize-away
    // would hide the operator's mistake, so fail closed instead.
    if (parsed.path() != "/" && !parsed.path().is_empty())
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("proxy URL must be scheme://host[:port] with no path");
    }
    let port_part = parsed
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    Ok(format!("{}://{host}{port_part}", parsed.scheme()))
}

/// Resolve the mandatory OSV egress proxy. Fails closed: a missing or
/// malformed `OSV_EGRESS_PROXY` means the dependency scanner must not run
/// with unfettered bridge egress, so the caller reports unknown coverage
/// instead of scanning. This reads the same process environment the
/// `config` crate maps onto `Settings::osv_egress_proxy` (prefix-less
/// source), so there is one operator knob, not two.
pub fn resolve_osv_egress_proxy() -> Result<String, AppError> {
    let raw = std::env::var("OSV_EGRESS_PROXY").unwrap_or_default();
    if raw.trim().is_empty() {
        return Err(AppError::Internal(
            "OSV egress proxy is not configured (OSV_EGRESS_PROXY): refusing \
             unfettered bridge egress; dependency coverage is unknown until a \
             filtering proxy is provided"
                .into(),
        ));
    }
    validate_osv_proxy_url(&raw).map_err(|reason| {
        AppError::Internal(format!(
            "OSV egress proxy is misconfigured ({reason}): refusing to run the \
             dependency scanner without a valid filtering proxy"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approved_destinations_allowed() {
        assert_eq!(
            evaluate_egress_target("api.osv.dev", 443),
            EgressDecision::Allow
        );
        assert_eq!(
            evaluate_egress_target("osv.dev", 443),
            EgressDecision::Allow
        );
    }

    #[test]
    fn test_metadata_blocked() {
        assert_eq!(
            evaluate_egress_target("169.254.169.254", 443),
            EgressDecision::Block("cloud metadata and link-local blocked")
        );
    }

    #[test]
    fn test_loopback_blocked() {
        assert_eq!(
            evaluate_egress_target("127.0.0.1", 443),
            EgressDecision::Block("loopback blocked")
        );
        assert_eq!(
            evaluate_egress_target("localhost", 443),
            EgressDecision::Block("domain not in approved OSV allowlist")
        );
    }

    #[test]
    fn test_private_networks_blocked() {
        assert_eq!(
            evaluate_egress_target("10.0.0.1", 443),
            EgressDecision::Block("RFC1918 private network blocked")
        );
        assert_eq!(
            evaluate_egress_target("192.168.1.1", 443),
            EgressDecision::Block("RFC1918 private network blocked")
        );
        assert_eq!(
            evaluate_egress_target("172.16.0.5", 443),
            EgressDecision::Block("RFC1918 private network blocked")
        );
    }

    #[test]
    fn test_arbitrary_domains_blocked() {
        assert_eq!(
            evaluate_egress_target("google.com", 443),
            EgressDecision::Block("domain not in approved OSV allowlist")
        );
        assert_eq!(
            evaluate_egress_target("evil.attacker.com", 443),
            EgressDecision::Block("domain not in approved OSV allowlist")
        );
    }

    #[test]
    fn test_unauthorized_ports_blocked() {
        assert_eq!(
            evaluate_egress_target("api.osv.dev", 80),
            EgressDecision::Block("non-standard port blocked; only 443 and 53 permitted")
        );
        assert_eq!(
            evaluate_egress_target("api.osv.dev", 22),
            EgressDecision::Block("non-standard port blocked; only 443 and 53 permitted")
        );
    }
}
