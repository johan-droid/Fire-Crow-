//! OSV scanner egress policy and destination validation (Phase C / H2).
//!
//! OSV-Scanner is the sole scanner granted network access ([`NetworkMode::Bridge`]),
//! which it requires to query the live Open Source Vulnerabilities database.
//! This module defines the strict egress allowlist and validation logic to block
//! access to cloud metadata services, RFC 1918 private networks, loopback,
//! and arbitrary non-OSV external destinations.

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
            EgressDecision::Allow
        }
    }
}

/// Evaluates whether a destination host (hostname or IP string) and port are permitted.
pub fn evaluate_egress_target(host: &str, port: u16) -> EgressDecision {
    // Only HTTPS (443) and DNS (53) are valid ports for OSV database queries
    if port != 443 && port != 53 {
        return EgressDecision::Block("non-standard port blocked; only 443 and 53 permitted");
    }

    let host_trimmed = host.trim().to_lowercase();

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
