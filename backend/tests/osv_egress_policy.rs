//! Phase C (H2) test suite: OSV scanner network egress hardening.
//!
//! Asserts that:
//! 1. Approved OSV domains (`api.osv.dev`, `osv.dev`) on port 443 are allowed.
//! 2. Cloud instance metadata (`169.254.169.254`, link-local) is blocked.
//! 3. Loopback (`127.0.0.1`, `::1`, `localhost`) is blocked.
//! 4. Private networks (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are blocked.
//! 5. Arbitrary external destinations (`attacker.com`, etc.) are blocked.
//! 6. Non-standard ports (anything other than 443 and 53) are blocked.
//! 7. `Scanner::osv()` injects the egress proxy configuration when `OSV_EGRESS_PROXY` is set.

use firecrow_backend::agents::scanner::Scanner;
use firecrow_backend::services::egress_policy::{
    evaluate_egress_target, evaluate_ip, EgressDecision,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn approved_osv_destination_is_allowed() {
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
fn cloud_metadata_is_blocked() {
    let metadata_ip: IpAddr = "169.254.169.254".parse().unwrap();
    assert!(matches!(evaluate_ip(metadata_ip), EgressDecision::Block(_)));

    assert!(matches!(
        evaluate_egress_target("169.254.169.254", 443),
        EgressDecision::Block(_)
    ));
}

#[test]
fn localhost_and_loopback_are_blocked() {
    let loopback_v4: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let loopback_v6: IpAddr = Ipv6Addr::LOCALHOST.into();
    assert!(matches!(evaluate_ip(loopback_v4), EgressDecision::Block(_)));
    assert!(matches!(evaluate_ip(loopback_v6), EgressDecision::Block(_)));

    assert!(matches!(
        evaluate_egress_target("127.0.0.1", 443),
        EgressDecision::Block(_)
    ));
    assert!(matches!(
        evaluate_egress_target("localhost", 443),
        EgressDecision::Block(_)
    ));
}

#[test]
fn private_rfc1918_networks_are_blocked() {
    for ip_str in ["10.0.0.1", "172.16.0.1", "192.168.1.100"] {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            matches!(evaluate_ip(ip), EgressDecision::Block(_)),
            "IP {ip_str} should be blocked"
        );
        assert!(
            matches!(
                evaluate_egress_target(ip_str, 443),
                EgressDecision::Block(_)
            ),
            "Target {ip_str}:443 should be blocked"
        );
    }
}

#[test]
fn arbitrary_external_destinations_are_blocked() {
    for host in ["evil.attacker.com", "exfil.io", "google.com", "github.com"] {
        assert!(
            matches!(evaluate_egress_target(host, 443), EgressDecision::Block(_)),
            "Host {host} should be blocked"
        );
    }
}

#[test]
fn non_standard_ports_are_blocked() {
    assert!(matches!(
        evaluate_egress_target("api.osv.dev", 80),
        EgressDecision::Block(_)
    ));
    assert!(matches!(
        evaluate_egress_target("api.osv.dev", 8080),
        EgressDecision::Block(_)
    ));
    assert!(matches!(
        evaluate_egress_target("api.osv.dev", 22),
        EgressDecision::Block(_)
    ));
}

#[test]
fn osv_scanner_injects_egress_proxy_env() {
    std::env::set_var("OSV_EGRESS_PROXY", "http://egress-proxy:3128");
    let scanner = Scanner::osv();
    assert!(
        scanner
            .env
            .iter()
            .any(|(k, v)| k == "HTTPS_PROXY" && v == "http://egress-proxy:3128"),
        "Scanner::osv() must forward HTTPS_PROXY from OSV_EGRESS_PROXY"
    );
    assert!(
        scanner
            .env
            .iter()
            .any(|(k, v)| k == "HTTP_PROXY" && v == "http://egress-proxy:3128"),
        "Scanner::osv() must forward HTTP_PROXY from OSV_EGRESS_PROXY"
    );
    std::env::remove_var("OSV_EGRESS_PROXY");
}
